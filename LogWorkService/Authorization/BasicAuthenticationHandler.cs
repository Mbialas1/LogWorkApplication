using Dapper;
using LogWorkService.Authorization.Cache;
using LogWorkService.Controllers;
using LogWorkService.Exceptions;
using LogWorkService.Helpers;
using LogWorkService.Models.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using StackExchange.Redis;
using System.ComponentModel;
using System.Data;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace LogWorkService.Authorization
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IConfiguration _configuration;
        private readonly IDbConnection _dbConnection;
        private readonly ILogger<TaskController> _logger;
        private readonly RedisCacheAuthorizationService _cacheService;

        #region
        private long _idUser;
        private string _hashedPassword;
        private DateTime? _lockoutEnd;
        private int _failedLoginAttempts;
        #endregion

        public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder, ISystemClock clock,
            IConfiguration configuration, ILogger<TaskController> logger, RedisCacheAuthorizationService cacheService)
            : base(options, loggerFactory, encoder, clock)
        {
            _configuration = configuration;
            _dbConnection = new SqlConnection(_configuration.GetConnectionString(HelperConnections.TASK_DB_CONNECTION));
            _logger = logger;
            _cacheService = cacheService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Missing Authorization Header");

            UserAuthentication userAuthentication = null;
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
                var username = credentials[0];
                var password = credentials[1];

                userAuthentication = await Authenticate(username, password);
            }
            catch (TooManyRequestsException tooManyEx)
            {
                return AuthenticateResult.Fail(tooManyEx);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex + "Invalid Authorization Header");
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            if (userAuthentication == null)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var claims = new[] {
            new Claim(ClaimTypes.NameIdentifier, userAuthentication.UserName)};

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private async Task<UserAuthentication> Authenticate(string username, string password)
        {
            UserAuthentication user = null;
            var userFromCache = _cacheService.GetUserCacheItem(username);
            if (userFromCache != null && userFromCache.Value.PasswordHash == PasswordHasher.HashPassword(password, userFromCache.Value.Salt))
            {
                user = new UserAuthentication()
                {
                    PasswordHash = userFromCache.Value.PasswordHash,
                    LockoutEnd = userFromCache.Value.LockoutEnd,
                    FailedLoginAttempts = userFromCache.Value.FailedLoginAttempts,
                    Id = userFromCache.Value.Id,
                    UserName = username
                };
            }
            else
            {
                user = await _dbConnection.QuerySingleOrDefaultAsync<UserAuthentication>("SELECT * FROM UserAuthentication WHERE Username = @Username", new { Username = username });

                if (user == null)
                    return null;


                var hashedPassword = PasswordHasher.HashPassword(password, user.Salt);
                if (hashedPassword != user.PasswordHash)
                {
                    int failedLoginNumber = user.FailedLoginAttempts + 1;
                    await SetFailedLoginAttempt(user.Id, failedLoginNumber, user.LockoutEnd);
                    return null;
                }

                _cacheService.SetUserItem(user);
            }

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                _logger.LogError($"User is lockout. Number of logged {user.FailedLoginAttempts} to time: {user.LockoutEnd}");
                throw new TooManyRequestsException($"{user.FailedLoginAttempts} blocked to {user.LockoutEnd}");
            }

            if (user.FailedLoginAttempts > 0)
                await SetFailedLoginAttempt(user.Id);

            return user;
        }

        private async Task SetFailedLoginAttempt(UserAuthentication userAuth, int number = 0, DateTime? lockoutEnd = null)
        {
            lockoutEnd = number switch
            {
                5 => DateTime.UtcNow.AddMinutes(1),
                10 => DateTime.UtcNow.AddMinutes(15),
                15 => DateTime.UtcNow.AddHours(24),
                _ => (DateTime?)null
            };

            var parameters = new DynamicParameters();
            parameters.Add("FailedLoginAttempts", number);
            parameters.Add("Id", userAuth.Id);

            if (lockoutEnd.HasValue)
                parameters.Add("LockoutEnd", lockoutEnd.Value);
            else
                parameters.Add("LockoutEnd", dbType: DbType.DateTime, value: null, direction: ParameterDirection.Input);

            string updateSql = "UPDATE UserAuthentication SET FailedLoginAttempts = @FailedLoginAttempts, LockoutEnd = @LockoutEnd WHERE Id = @Id";
            await _dbConnection.ExecuteAsync(updateSql, parameters);

            userAuth.LockoutEnd = 
            _cacheService.SetUserItem(userAuth);
        }
    }
}
