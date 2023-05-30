using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace P328Pustok.Migrations
{
    public partial class SlidersTableCreated : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Sliders",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Order = table.Column<int>(type: "int", nullable: false),
                    Title1 = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                    Title2 = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                    Desc = table.Column<string>(type: "nvarchar(250)", maxLength: 250, nullable: true),
                    BtnText = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    BtnUrl = table.Column<string>(type: "nvarchar(250)", maxLength: 250, nullable: true),
                    ImageName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sliders", x => x.Id);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Sliders");
        }
    }
}
