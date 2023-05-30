namespace P328Pustok.ViewModels
{
    public class BasketViewModel
    {
        public List<BasketItemViewModel> BasketItems { get; set; } = new List<BasketItemViewModel>();
        public decimal TotalPrice { get; set; }
    }
}
