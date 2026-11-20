using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Majorsilence.Banish.Store.Ef.Migrations.SqlServer;

/// <summary>Used only by <c>dotnet ef</c> to scaffold migrations; nothing connects to this address.</summary>
internal sealed class DesignTimeFactory : IDesignTimeDbContextFactory<BanishDbContext>
{
    public BanishDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<BanishDbContext>();
        builder.UseSqlServer("Server=localhost;Database=banish_design;Trusted_Connection=True;TrustServerCertificate=True", o => o.MigrationsAssembly(typeof(DesignTimeFactory).Assembly.GetName().Name));
        return new BanishDbContext(builder.Options);
    }
}
