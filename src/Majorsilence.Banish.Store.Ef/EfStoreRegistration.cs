using Majorsilence.Banish.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Majorsilence.Banish.Store.Ef;

public static class EfStoreRegistration
{
    /// <summary>Default location of the SQLite database for the current OS.</summary>
    public static string DefaultSqlitePath() => Path.Combine(DefaultDataDirectory(), "banish.db");

    public static string DefaultDataDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Banish");
        }

        if (OperatingSystem.IsMacOS())
        {
            return "/Library/Application Support/Banish";
        }

        return "/var/lib/banish";
    }

    public static bool IsEfProvider(string provider) =>
        provider.Equals(StoreProviders.Sqlite, StringComparison.OrdinalIgnoreCase)
        || provider.Equals(StoreProviders.PostgreSql, StringComparison.OrdinalIgnoreCase)
        || provider.Equals(StoreProviders.SqlServer, StringComparison.OrdinalIgnoreCase)
        || provider.Equals(StoreProviders.MySql, StringComparison.OrdinalIgnoreCase);

    public static void Configure(DbContextOptionsBuilder builder, StoreOptions store)
    {
        string provider = store.Provider;
        if (provider.Equals(StoreProviders.Sqlite, StringComparison.OrdinalIgnoreCase))
        {
            string connection = store.ConnectionString ?? $"Data Source={DefaultSqlitePath()}";
            builder.UseSqlite(connection);
        }
        else if (provider.Equals(StoreProviders.PostgreSql, StringComparison.OrdinalIgnoreCase))
        {
            builder.UseNpgsql(Require(store));
        }
        else if (provider.Equals(StoreProviders.SqlServer, StringComparison.OrdinalIgnoreCase))
        {
            builder.UseSqlServer(Require(store));
        }
        else
        {
            throw new ArgumentException($"'{provider}' is not an EF Core store provider.");
        }
    }

    public static IServiceCollection AddBanishEfStore(this IServiceCollection services, StoreOptions store, string machineName)
    {
        if (store.Provider.Equals(StoreProviders.Sqlite, StringComparison.OrdinalIgnoreCase) && store.ConnectionString is null)
        {
            Directory.CreateDirectory(DefaultDataDirectory());
        }

        services.AddDbContextFactory<BanishDbContext>(o => Configure(o, store));
        services.AddSingleton(sp => new EfBanStore(sp.GetRequiredService<IDbContextFactory<BanishDbContext>>(), machineName));
        services.AddSingleton<IBanStore>(sp => sp.GetRequiredService<EfBanStore>());
        return services;
    }

    private static string Require(StoreOptions store) =>
        !string.IsNullOrWhiteSpace(store.ConnectionString)
            ? store.ConnectionString
            : throw new InvalidOperationException($"Store:ConnectionString is required for provider {store.Provider}.");
}
