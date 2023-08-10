using LogWorkService.Models.Authorization;
using Newtonsoft.Json;
using StackExchange.Redis;
using System.Text.Json.Serialization;

namespace LogWorkService.Authorization.Cache
{
    public class RedisCacheAuthorizationService
    {
        private readonly IDatabase _database;
        private readonly string _instanceName;

        public RedisCacheAuthorizationService(IConnectionMultiplexer connectionMultiplexer, IConfiguration configuration)
        {
            _database = connectionMultiplexer.GetDatabase();
            _instanceName = configuration.GetSection("Redis:InstanceName").Value;
        }

        public void SetUserItem(UserAuthentication userAuthentication)
        {
            var expiry = TimeSpan.FromMinutes(5);

            UserCacheItem userCacheItem = new UserCacheItem()
            {
                Id = userAuthentication.Id,
                Username = userAuthentication.UserName,
                PasswordHash = userAuthentication.PasswordHash,
                FailedLoginAttempts = userAuthentication.FailedLoginAttempts,
                LockoutEnd = userAuthentication.LockoutEnd,
                Salt = userAuthentication.Salt
            };

            var serializedData = JsonConvert.SerializeObject(userCacheItem);

            _database.StringSet($"{_instanceName}:usercacheitem:{userCacheItem}", serializedData ,expiry);
        }

        public UserCacheItem? GetUserCacheItem(string username)
        {
            var serializedData = _database.StringGet($"{_instanceName}:userauthdata:{username}");
            if (!serializedData.HasValue)
                return null;

            return JsonConvert.DeserializeObject<UserCacheItem>(serializedData);
        }

        public void InvalidatePassword(string username)
        {
            _database.KeyDelete($"{_instanceName}:userauthdata:{username}");
        }

    }
}
