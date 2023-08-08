using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace LogWorkService.Models.DTO
{
    public class TaskModelDTO
    {
        public long Id { get; set; }
        [Required]
        public long UserId { get; set; }
        [Required]
        public string Name { get; set; }
        public string Description { get; set; } = string.Empty;
        //public string Status { get; set; }
        public DateTime CreatedDate { get; set; }   
        public DateTime UpdateDate { get; set;}
    }
}
