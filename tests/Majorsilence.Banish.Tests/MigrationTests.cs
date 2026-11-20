using Majorsilence.Banish.Core;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Store.Ef;
using Majorsilence.Banish.Tests.Support;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Majorsilence.Banish.Tests;

public class MigrationTests
{
    private static BanishDbContext ContextFor(string provider, string connection)
    {
        var builder = new DbContextOptionsBuilder<BanishDbContext>();
        EfStoreRegistration.Configure(builder, new StoreOptions { Provider = provider, ConnectionString = connection });
        return new BanishDbContext(builder.Options);
    }

    [TestCase(StoreProviders.Sqlite, "Data Source=x.db")]
    [TestCase(StoreProviders.PostgreSql, "Host=localhost;Database=x")]
    [TestCase(StoreProviders.SqlServer, "Server=localhost;Database=x")]
    [TestCase(StoreProviders.MySql, "Server=localhost;Database=x")]
    public void Migrations_match_the_model_for_every_provider(string provider, string connection)
    {
        // Fails when the model changed but "dotnet ef migrations add" was not run for this provider.
        using var db = ContextFor(provider, connection);
        Assert.That(db.Database.HasPendingModelChanges(), Is.False, $"{provider} migrations are out of date");
    }

    [Test]
    public async Task A_new_database_is_created_by_the_migrations()
    {
        await using var temp = new TempStore();
        await temp.Store.MigrateAsync(default);
        await temp.Store.MigrateAsync(default); // running it again changes nothing

        await using var db = await temp.Factory.CreateDbContextAsync();
        Assert.That((await db.Database.GetAppliedMigrationsAsync()).Count(), Is.EqualTo(1));
    }

    [Test]
    public async Task A_database_made_by_version_0_1_with_EnsureCreated_is_adopted_and_keeps_its_data()
    {
        await using var temp = new TempStore();
        await using (var legacy = await temp.Factory.CreateDbContextAsync())
        {
            await legacy.Database.EnsureCreatedAsync(); // what 0.1.x did
            legacy.Bans.Add(new Ban { Address = "203.0.113.9", Source = BanSources.Manual, CreatedUtc = DateTime.UtcNow });
            await legacy.SaveChangesAsync();
        }

        await temp.Store.MigrateAsync(default);

        await using var db = await temp.Factory.CreateDbContextAsync();
        Assert.That(await db.Bans.CountAsync(), Is.EqualTo(1));
        Assert.That((await db.Database.GetAppliedMigrationsAsync()).Count(), Is.EqualTo(1));
        Assert.That(await db.Database.GetPendingMigrationsAsync(), Is.Empty);
    }

    [Test]
    public void Api_urls_accept_a_string_a_list_or_wildcards_and_reject_garbage()
    {
        static IConfigurationSection Section(Dictionary<string, string?> values) =>
            new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("Api:Urls");

        Assert.That(BanishConfig.NormalizeUrls(Section(new() { ["Api:Urls"] = "http://localhost:5080" }), "http://x:1"), Is.EqualTo("http://localhost:5080"));
        Assert.That(BanishConfig.NormalizeUrls(Section(new() { ["Api:Urls:0"] = "http://localhost:5080", ["Api:Urls:1"] = "https://+:443" }), "http://x:1"),
            Is.EqualTo("http://localhost:5080;https://+:443"));
        Assert.That(BanishConfig.NormalizeUrls(Section(new()), "http://127.0.0.1:5380"), Is.EqualTo("http://127.0.0.1:5380"));
        Assert.Throws<InvalidOperationException>(() => BanishConfig.NormalizeUrls(Section(new() { ["Api:Urls"] = "localhost:5080" }), ""));
        Assert.Throws<InvalidOperationException>(() => BanishConfig.NormalizeUrls(Section(new() { ["Api:Urls"] = "ftp://host" }), ""));
    }
}
