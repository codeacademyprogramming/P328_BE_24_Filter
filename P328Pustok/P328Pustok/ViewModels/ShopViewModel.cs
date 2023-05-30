using P328Pustok.Models;

namespace P328Pustok.ViewModels
{
    public class ShopViewModel
    {
        public List<Genre> Genres { get; set; }
        public List<Author> Authors { get; set; }
        public List<Tag> Tags { get; set; }
        public List<Book> Books { get; set; }

    }
}
