using System.Security.Cryptography;
using System.Text;

namespace LogWorkService.Helpers
{
    public class PasswordHasher
    {
        public static string HashPassword(string password, string salt)
        {
            using var sha256 = SHA256.Create();
            var saltedPassword = $"{salt}{password}";
            var byteValue = Encoding.UTF8.GetBytes(saltedPassword);
            var byteHash = sha256.ComputeHash(byteValue);

            return Convert.ToBase64String(byteHash);
        }
    }
}
