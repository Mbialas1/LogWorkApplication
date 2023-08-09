namespace LogWorkService.Models.Authorization
{
    public class UserAuthentication
    {
        public long Id { get; set; }    
        public string UserName { get; set; }
        public string PasswordHash { get; set; }
        public string Salt { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime LastLogin { get; set; }
        public DateTime? LockoutEnd { get; set; }
    }
}
