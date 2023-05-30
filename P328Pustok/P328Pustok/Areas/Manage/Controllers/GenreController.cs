using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using P328Pustok.DAL;
using P328Pustok.Models;
using P328Pustok.ViewModels;

namespace P328Pustok.Areas.Manage.Controllers
{
	[Authorize(Roles = "SuperAdmin,Admin")]
	[Area("manage")]
    public class GenreController : Controller
    {
        private readonly PustokContext _context;

        public GenreController(PustokContext context)
        {
            _context = context;
        }
        public IActionResult Index(int page=1)
        {
            var query = _context.Genres.Include(x => x.Books).AsQueryable();

            return View(PaginatedList<Genre>.Create(query,page,2));
        }

        public IActionResult Create()
        {
            return View();
        }

        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Genre genre)
        {
            if (!ModelState.IsValid)
                return View();

            if (_context.Genres.Any(x => x.Name == genre.Name))
            {
                ModelState.AddModelError("Name", "Name is already taken");
                return View();
            }


            _context.Genres.Add(genre);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Edit(int id)
        {
            Genre genre = _context.Genres.Find(id);

            if(genre == null) return View("Error");

            return View(genre);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Edit(Genre genre)
        {
            if (!ModelState.IsValid) return View();

            Genre existGenre = _context.Genres.Find(genre.Id);

            if (existGenre == null) return View("Error");

            if(genre.Name!=existGenre.Name && _context.Genres.Any(x=>x.Name == genre.Name))
            {
                ModelState.AddModelError("Name", "Name is already taken");
                return View();
            }

            existGenre.Name = genre.Name;

            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Delete(int id)
        {
            Genre genre = _context.Genres.Include(x=>x.Books).FirstOrDefault(x=>x.Id==id);

            if (genre == null) return View("Error");
            return View(genre);
        }

        [HttpPost]
        public IActionResult Delete(Genre genre)
        {
            Genre existGenre = _context.Genres.Find(genre.Id);

            if (existGenre == null) return View("Error");

            _context.Genres.Remove(existGenre);
            _context.SaveChanges();

            return RedirectToAction("index");   
        }


    }
}
