using Microsoft.AspNetCore.Mvc;
using P328Pustok.DAL;

namespace P328Pustok.ViewComponents
{
    public class NavGenresViewComponent:ViewComponent
    {
        private readonly PustokContext _context;

        public NavGenresViewComponent(PustokContext context)
        {
            _context = context;
        }
        public IViewComponentResult Invoke()
        {
            var data = _context.Genres.ToList();

            return View(data);
        }
    }
}
