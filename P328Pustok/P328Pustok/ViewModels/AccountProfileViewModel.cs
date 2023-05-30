using P328Pustok.Models;

namespace P328Pustok.ViewModels
{
    public class AccountProfileViewModel
    {
        public ProfileEditViewModel Profile { get; set; }
        public List<Order> Orders { get; set; } 
    }
}
