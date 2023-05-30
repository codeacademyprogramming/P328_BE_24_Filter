using P328Pustok.Attributes.ValidationAttributes;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace P328Pustok.Models
{
    public class Slider
    {
        public int Id { get; set; }
        public int Order { get; set; }
        [MaxLength(20)]
        public string Title1 { get; set; }
        [MaxLength(20)]
        public string Title2 { get; set; }
        [MaxLength(250)]
        public string Desc { get; set; }
        [MaxLength(50)]
        public string BtnText { get; set; }
        [MaxLength(250)]
        public string BtnUrl { get; set; }
        [MaxLength(100)]
        public string ImageName { get; set; }
        [MaxFileSize(2097152)]
        [AllowedFileTypes("image/jpeg","image/png")]
        [NotMapped]
        public IFormFile ImageFile { get; set; }
    }
}
