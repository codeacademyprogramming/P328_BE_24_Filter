using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using P328Pustok.DAL;
using P328Pustok.Models;
using P328Pustok.Services;
using P328Pustok.ViewModels;
using System.Diagnostics;

namespace P328Pustok.Controllers
{
    public class HomeController : Controller
    {
        private readonly PustokContext _context;

        public HomeController(PustokContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            ViewData["Title"] = "Esas Sehife";


            HomeViewModel vm = new HomeViewModel
            {
                FeaturedBoooks = _context.Books.Include(x=>x.Author).Include(x=>x.BookImages).Where(x => x.IsFeatured).Take(10).ToList(),
                NewBoooks = _context.Books.Include("Author").Include(x => x.BookImages).Where(x => x.IsNew).Take(10).ToList(),
                DiscountedBoooks = _context.Books.Include(x=>x.Author).Include(x => x.BookImages).Where(x => x.DiscountPercent>0).Take(10).ToList(),
            };

            return View(vm);
        }



        //var tag = _context.Tags.Find(2);
        //tag = _context.Tags.First(x => x.Name.StartsWith("a"));
        //tag = _context.Tags.FirstOrDefault(x => x.Id == 2);
        //tag = _context.Tags.Single(x => x.Id == 2);
        //tag = _context.Tags.SingleOrDefault(x => x.Id == 2);

        //var tags = _context.Tags.Where(x => x.Name.StartsWith("a"));
        //tags = tags.Where(x => x.Id > 2);
        //tags = tags.OrderBy(x => x.Id);

        //_context.Tags.Where(x=>x.Name.StartsWith("a")).Skip(4).Take(2).ToList();


        public IActionResult SetSession()
        {
            HttpContext.Session.SetString("bookCount", "5");
            return RedirectToAction("index");
        }

        public IActionResult GetSession()
        {
            var val = HttpContext.Session.GetString("bookCount");
            return Json(new { bookCount = val });
        }

        public IActionResult SetCookie()
        {
            Response.Cookies.Append("bookCount", "10");
            return RedirectToAction("index");

        }

        public IActionResult GetCookie()
        {
            var val = Request.Cookies["bookCount"];
            return Json(new { bookCount = val });
        }
    }
}