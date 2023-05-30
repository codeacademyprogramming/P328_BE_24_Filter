using P328Pustok.Models;

namespace P328Pustok.ViewModels
{
    public class HomeViewModel
    {
        public List<Book> FeaturedBoooks { get; set; }
        public List<Book> NewBoooks { get; set; }
        public List<Book> DiscountedBoooks { get; set; }

    }
}
