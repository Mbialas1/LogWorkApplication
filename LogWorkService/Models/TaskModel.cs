namespace LogWorkService.Models
{
    public class TaskModel
    {
        public long Id { get; set; }
        public long UserId { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime UpdatedDate { get; set;}
        public TaskModel BaseTask {get; set; }
        public List<TaskModel> SubTasks { get; set; }
        public TaskModel() { }
    }
}
