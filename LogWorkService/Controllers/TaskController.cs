using Dapper;
using LogWorkService.Helpers;
using LogWorkService.Models;
using LogWorkService.Models.DTO;
using LogWorkService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Runtime.CompilerServices;

namespace LogWorkService.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class TaskController : Controller
    {
        private readonly ILogger<TaskController> _logger;
        private readonly IConfiguration _configuration;
        private readonly TaskService _taskService;
        public TaskController(ILogger<TaskController> logger, IConfiguration configuration, TaskService taskService)
        {
            _logger = logger;
            _configuration = configuration; 
            _taskService = taskService;
        }

        [HttpGet("{userId}")]
        public ActionResult<IEnumerable<TaskModelDTO>> GetTasksCurrentUser(long userId)
        {
            //Get task for current user
            return Ok(new List<TaskModelDTO>());
        }

        [HttpPost]
        public async Task<IActionResult> AddTask(TaskModelDTO taskDto)
        {
            try
            {
                _logger.LogInformation("Start add task to db");

                if(await _taskService.TaskExist(taskDto.Name))
                {
                    _logger.LogInformation($"Name = {taskDto.Name} already exists");
                    return Conflict($"Name = {taskDto.Name} already exists");
                }

                using var connection = new SqlConnection(_configuration.GetConnectionString(HelperConnections.TASK_DB_CONNECTION));
                await connection.OpenAsync();

                taskDto.CreatedDate= DateTime.Now;
                taskDto.UpdateDate = taskDto.CreatedDate;

                var sql = "INSERT INTO Task (UserID, Name, Description, CreatedDate, UpdateDate) VALUES (@UserId, @Name, @Description, @CreatedDate, @UpdateDate)";
                await connection.ExecuteAsync(sql, taskDto);

                _logger.LogInformation($"Task {taskDto.Id} was created");
                return Ok();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString(), "Error durring add new task to db.");
                return StatusCode(500, "Couldn't add new task");
            }
        }
        }
    }
