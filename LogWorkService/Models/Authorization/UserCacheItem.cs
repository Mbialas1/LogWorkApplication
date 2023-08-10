namespace LogWorkService.Models.Authorization
{
    public struct UserCacheItem
    {
        public long Id { get; set; }
        public string Username { get; set; }
        public string Salt { get; set; }
        public string PasswordHash { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockoutEnd { get; set; }
    }
}
