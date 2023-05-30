using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using P328Pustok.DAL;
using P328Pustok.Models;

namespace P328Pustok.Areas.Manage.Controllers
{
    [Authorize(Roles = "SuperAdmin,Admin")]
	[Area("manage")]
    public class AuthorController : Controller
    {
        private readonly PustokContext _context;

        public AuthorController(PustokContext context)
        {
            _context = context;
        }
        public IActionResult Index()
        {
            return View(_context.Authors.Include(x=>x.Books).ToList());
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Create(Author author)
        {
            if (!ModelState.IsValid) return View();

            if(_context.Authors.Any(x=>x.FullName == author.FullName))
            {
                ModelState.AddModelError("FullName", "FullName has already taken");
                return View();
            }

            _context.Authors.Add(author);
            _context.SaveChanges();

            return RedirectToAction("index");
        }

        public IActionResult Delete(int id)
        {
            Author author = _context.Authors.Find(id);

            if (author == null) return StatusCode(404);

            _context.Authors.Remove(author);
            _context.SaveChanges();

            return StatusCode(200);
        }


    }
}
