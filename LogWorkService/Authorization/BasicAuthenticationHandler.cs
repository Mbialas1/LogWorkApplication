using Dapper;
using LogWorkService.Controllers;
using LogWorkService.Exceptions;
using LogWorkService.Helpers;
using LogWorkService.Models.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
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

        public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory loggerFactory, UrlEncoder encoder, ISystemClock clock, IConfiguration configuration, ILogger<TaskController> logger)
            : base(options, loggerFactory, encoder, clock)
        {
            _configuration = configuration;
            _dbConnection = new SqlConnection(_configuration.GetConnectionString(HelperConnections.TASK_DB_CONNECTION));
            _logger = logger;
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
            var user = await _dbConnection.QuerySingleOrDefaultAsync<UserAuthentication>("SELECT * FROM UserAuthentication WHERE Username = @Username", new { Username = username });

            if (user == null)
                return null;

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                _logger.LogError($"User is lockout. Number of logged {user.FailedLoginAttempts} to time: {user.LockoutEnd}");
                throw new TooManyRequestsException($"{username} blocked to {user.LockoutEnd}");
            }

            var hashedPassword = PasswordHasher.HashPassword(password, user.Salt);

            if (hashedPassword != user.PasswordHash)
            {
                int failedLoginNumber = user.FailedLoginAttempts + 1;
                await SetFailedLoginAttempt(user.Id, failedLoginNumber, user.LockoutEnd);
                return null;
            }

            if (user.FailedLoginAttempts > 0)
                await SetFailedLoginAttempt(user.Id);

            return user;
        }

        private async Task SetFailedLoginAttempt(long idUserAuth, int number = 0, DateTime? lockoutEnd = null)
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
            parameters.Add("Id", idUserAuth);

            if (lockoutEnd.HasValue)
                parameters.Add("LockoutEnd", lockoutEnd.Value);
            else
                parameters.Add("LockoutEnd", dbType: DbType.DateTime, value: null, direction: ParameterDirection.Input);

            string updateSql = "UPDATE UserAuthentication SET FailedLoginAttempts = @FailedLoginAttempts, LockoutEnd = @LockoutEnd WHERE Id = @Id";
            await _dbConnection.ExecuteAsync(updateSql, parameters);
        }
    }
}
