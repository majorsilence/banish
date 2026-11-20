using System;
using Microsoft.EntityFrameworkCore.Migrations;
using MySql.EntityFrameworkCore.Metadata;

#nullable disable

namespace Majorsilence.Banish.Store.Ef.Migrations.MySql.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Agents",
                columns: table => new
                {
                    MachineName = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    Os = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    Version = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Firewall = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    AppliedBans = table.Column<int>(type: "int", nullable: false),
                    StartedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Agents", x => x.MachineName);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Allowlist",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    Address = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Note = table.Column<string>(type: "varchar(256)", maxLength: 256, nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    CreatedBy = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Allowlist", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "ApiKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    Name = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    Prefix = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    KeyHash = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Role = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastUsedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    RevokedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiKeys", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "BanEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("MySQL:ValueGenerationStrategy", MySQLValueGenerationStrategy.IdentityColumn),
                    BanId = table.Column<Guid>(type: "char(36)", nullable: false),
                    Address = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Kind = table.Column<string>(type: "varchar(32)", maxLength: 32, nullable: false),
                    Actor = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    MachineName = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    TimestampUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    Detail = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BanEvents", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Bans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    Address = table.Column<string>(type: "varchar(64)", maxLength: 64, nullable: false),
                    Reason = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: false),
                    Source = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    RuleId = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    CreatedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    UpdatedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    ExpiresUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    RemovedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    RemovedBy = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    MachineName = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    CreatedBy = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: true),
                    Hits = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Bans", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "char(36)", nullable: false),
                    UserName = table.Column<string>(type: "varchar(128)", maxLength: 128, nullable: false),
                    PasswordHash = table.Column<string>(type: "varchar(512)", maxLength: 512, nullable: false),
                    Role = table.Column<string>(type: "varchar(16)", maxLength: 16, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime(6)", nullable: false),
                    LastLoginUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true),
                    FailedLogins = table.Column<int>(type: "int", nullable: false),
                    LockoutUntilUtc = table.Column<DateTime>(type: "datetime(6)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                })
                .Annotation("MySQL:Charset", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_Allowlist_Address",
                table: "Allowlist",
                column: "Address",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiKeys_KeyHash",
                table: "ApiKeys",
                column: "KeyHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ApiKeys_Name",
                table: "ApiKeys",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_BanEvents_TimestampUtc",
                table: "BanEvents",
                column: "TimestampUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Bans_Address",
                table: "Bans",
                column: "Address");

            migrationBuilder.CreateIndex(
                name: "IX_Bans_CreatedUtc",
                table: "Bans",
                column: "CreatedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Bans_RemovedUtc",
                table: "Bans",
                column: "RemovedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_Users_UserName",
                table: "Users",
                column: "UserName",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Agents");

            migrationBuilder.DropTable(
                name: "Allowlist");

            migrationBuilder.DropTable(
                name: "ApiKeys");

            migrationBuilder.DropTable(
                name: "BanEvents");

            migrationBuilder.DropTable(
                name: "Bans");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
