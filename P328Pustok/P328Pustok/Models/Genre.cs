using System.ComponentModel.DataAnnotations;

namespace P328Pustok.Models
{
    public class Genre
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(20,ErrorMessage = "20-den uzun olmaz qaqa!")]
        public string Name { get; set; }

        public List<Book> Books { get; set; }
    }
}
