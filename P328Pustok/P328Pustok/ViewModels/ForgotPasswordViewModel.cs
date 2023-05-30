using System.ComponentModel.DataAnnotations;

namespace P328Pustok.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [MaxLength(100)]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}
