using System.ComponentModel.DataAnnotations;

namespace P328Pustok.Models
{
    public class Tag
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(20)]
        public string Name { get; set; }
    }
}
