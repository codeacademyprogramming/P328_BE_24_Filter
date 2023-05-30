using System.ComponentModel.DataAnnotations.Schema;

namespace P328Pustok.Models
{
	public class OrderItem
	{
		public int Id { get; set; }
		public int OrderId { get; set; }	
		public int BookId { get;set; }
		public int Count { get; set; }
		[Column(TypeName = "money")]
		public decimal UnitPrice { get; set; }
		[Column(TypeName = "money")]
		public decimal UnitCostPrice { get; set; }
		[Column(TypeName = "money")]
		public decimal DiscountPercent { get; set; }

		public Order Order { get; set; }
		public Book Book { get; set; }
	}
}
