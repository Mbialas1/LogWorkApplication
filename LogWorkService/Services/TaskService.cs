using Dapper;
using LogWorkService.Helpers;
using Microsoft.Data.SqlClient;

namespace LogWorkService.Services
{
    public class TaskService
    {
        private readonly IConfiguration _configuration;

        public TaskService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<bool> TaskExist(string taskName)
        {
            using var connection = new SqlConnection(_configuration.GetConnectionString(HelperConnections.TASK_DB_CONNECTION));
            
            var sql = "SELECT 1 FROM Task WHERE Name = @name";
            var result = await connection.QuerySingleOrDefaultAsync<int?>(sql, new { Name = taskName });

            return result != null;
        }
    }
}
