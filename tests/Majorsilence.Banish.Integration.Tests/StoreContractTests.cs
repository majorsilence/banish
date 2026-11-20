using Majorsilence.Banish.Core;
using Majorsilence.Banish.Store.Ef;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.MsSql;
using Testcontainers.MySql;
using Testcontainers.PostgreSql;

namespace Majorsilence.Banish.Integration.Tests;

/// <summary>
/// The IBanStore contract, run against a real database server for each EF Core provider. Each
/// subclass starts its own container; the tests are skipped when Docker is unavailable.
/// </summary>
public abstract class StoreContractTests
{
    private ServiceProvider? _agentA;
    private ServiceProvider? _agentB;

    protected abstract string Provider { get; }

    protected abstract Task<string> StartAsync();

    protected abstract Task StopAsync();

    protected EfBanStore A => _agentA!.GetRequiredService<EfBanStore>();

    /// <summary>A second agent process sharing the same database.</summary>
    protected EfBanStore B => _agentB!.GetRequiredService<EfBanStore>();

    [OneTimeSetUp]
    public async Task StartDatabase()
    {
        string connection;
        try
        {
            connection = await StartAsync();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Assert.Ignore($"{Provider}: container unavailable ({ex.GetType().Name}: {ex.Message})");
            return;
        }

        var store = new StoreOptions { Provider = Provider, ConnectionString = connection };
        _agentA = new ServiceCollection().AddBanishEfStore(store, "agent-a").BuildServiceProvider();
        _agentB = new ServiceCollection().AddBanishEfStore(store, "agent-b").BuildServiceProvider();
        await A.MigrateAsync(default);
        await B.MigrateAsync(default); // a second agent starting against an existing schema is harmless
    }

    [OneTimeTearDown]
    public async Task StopDatabase()
    {
        _agentA?.Dispose();
        _agentB?.Dispose();
        await StopAsync();
    }

    [SetUp]
    public async Task Clean()
    {
        var factory = _agentA!.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<BanishDbContext>>();
        await using var db = await factory.CreateDbContextAsync();
        db.Bans.RemoveRange(db.Bans);
        db.BanEvents.RemoveRange(db.BanEvents);
        db.Allowlist.RemoveRange(db.Allowlist);
        db.Agents.RemoveRange(db.Agents);
        await db.SaveChangesAsync();
    }

    [Test]
    public async Task A_database_without_migration_history_is_adopted_not_recreated()
    {
        // What a 0.1.x database looks like: the tables exist but __EFMigrationsHistory does not.
        var factory = _agentA!.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<BanishDbContext>>();
        await using (var db = await factory.CreateDbContextAsync())
        {
            string table = Provider switch
            {
                StoreProviders.PostgreSql => "\"__EFMigrationsHistory\"",
                StoreProviders.MySql => "`__EFMigrationsHistory`",
                _ => "[__EFMigrationsHistory]",
            };
            string sql = "DROP TABLE " + table;
            await db.Database.ExecuteSqlRawAsync(sql);
        }

        await A.MigrateAsync(default);

        await using var check = await factory.CreateDbContextAsync();
        Assert.That((await check.Database.GetAppliedMigrationsAsync()).Count(), Is.EqualTo(1));
        Assert.That(await check.Database.GetPendingMigrationsAsync(), Is.Empty);
    }

    private static Ban NewBan(string address, DateTime? expires, string source = BanSources.Local, string rule = "sshd") => new()
    {
        Address = address,
        Reason = "contract test",
        Source = source,
        RuleId = rule,
        ExpiresUtc = expires,
        Hits = 3,
    };

    [Test]
    public async Task BanMadeByOneAgentIsVisibleToTheOther()
    {
        await A.AddAsync(NewBan("203.0.113.5", DateTime.UtcNow.AddHours(1)), default);

        var seenByB = await B.GetActiveAsync(default);

        Assert.That(seenByB, Has.Count.EqualTo(1));
        Assert.That(seenByB[0].Address, Is.EqualTo("203.0.113.5"));
        Assert.That(seenByB[0].MachineName, Is.EqualTo("agent-a"));
        Assert.That(seenByB[0].CreatedUtc.Kind, Is.EqualTo(DateTimeKind.Utc));
    }

    [Test]
    public async Task UnbanByOneAgentIsVisibleToTheOther()
    {
        await A.AddAsync(NewBan("203.0.113.5", null), default);
        Assert.That(await B.RemoveAsync("203.0.113.5", "admin", default), Is.EqualTo(1));
        Assert.That(await A.GetActiveAsync(default), Is.Empty);
    }

    [Test]
    public async Task ExpiredBansAreNotActive()
    {
        await A.AddAsync(NewBan("203.0.113.5", DateTime.UtcNow.AddMinutes(-1)), default);
        await A.AddAsync(NewBan("203.0.113.6", DateTime.UtcNow.AddMinutes(30)), default);

        Assert.That((await B.GetActiveAsync(default)).Select(b => b.Address), Is.EqualTo(new[] { "203.0.113.6" }));
        Assert.That(await B.CountPriorAsync("203.0.113.5", default), Is.EqualTo(1));
        Assert.That((await B.QueryAsync(new BanQuery { State = "expired" }, default)).Total, Is.EqualTo(1));
    }

    [Test]
    public async Task ReAddingExtendsAndKeepsPermanent()
    {
        await A.AddAsync(NewBan("203.0.113.5", DateTime.UtcNow.AddMinutes(10)), default);
        await B.AddAsync(NewBan("203.0.113.5", null), default);

        var active = await A.GetActiveAsync(default);
        Assert.That(active, Has.Count.EqualTo(1));
        Assert.That(active[0].ExpiresUtc, Is.Null);
        Assert.That(active[0].Hits, Is.EqualTo(6));
    }

    [Test]
    public async Task IpV6AndCidrRoundTrip()
    {
        await A.AddAsync(NewBan("2001:db8::/32", null), default);
        await A.AddAsync(NewBan("198.51.100.0/24", null), default);

        Assert.That((await B.GetActiveAsync(default)).Select(b => b.Address), Is.EquivalentTo(new[] { "2001:db8::/32", "198.51.100.0/24" }));
        Assert.That((await B.GetActiveByAddressAsync("2001:db8::/32", default)), Is.Not.Null);
    }

    [Test]
    public async Task QueryPagesFiltersAndSearches()
    {
        for (int i = 1; i <= 7; i++)
        {
            await A.AddAsync(NewBan($"203.0.113.{i}", null, i % 2 == 0 ? BanSources.Manual : BanSources.Local, i < 4 ? "nginx" : "sshd"), default);
        }

        var page = await B.QueryAsync(new BanQuery { Skip = 2, Take = 3 }, default);
        Assert.That(page.Total, Is.EqualTo(7));
        Assert.That(page.Items, Has.Count.EqualTo(3));
        Assert.That((await B.QueryAsync(new BanQuery { Source = BanSources.Manual }, default)).Total, Is.EqualTo(3));
        Assert.That((await B.QueryAsync(new BanQuery { RuleId = "nginx" }, default)).Total, Is.EqualTo(3));
        Assert.That((await B.QueryAsync(new BanQuery { Search = ".113.7" }, default)).Total, Is.EqualTo(1));
        Assert.That((await B.QueryAsync(new BanQuery { MachineName = "agent-a" }, default)).Total, Is.EqualTo(7));
    }

    [Test]
    public async Task BulkAddSkipsActiveAddressesAndIsVisibleToOtherAgents()
    {
        await A.AddAsync(NewBan("203.0.113.1", null), default);
        var bans = Enumerable.Range(1, 1200).Select(i => NewBan($"198.51.{i / 250}.{i % 250 + 1}", null, "blocklist:big")).ToList();
        bans.Add(NewBan("203.0.113.1", null, "blocklist:big"));

        Assert.That(await A.AddRangeAsync(bans, default), Is.EqualTo(1200));
        Assert.That((await B.GetActiveAsync(default)).Count, Is.EqualTo(1201));
        Assert.That(await B.AddRangeAsync(bans, default), Is.EqualTo(0), "idempotent");
    }

    [Test]
    public async Task BlocklistRefreshRemovesDroppedEntries()
    {
        await A.AddAsync(NewBan("203.0.113.1", null, "blocklist:x"), default);
        await A.AddAsync(NewBan("203.0.113.2", null, "blocklist:x"), default);

        Assert.That(await B.RemoveBySourceAsync("blocklist:x", ["203.0.113.2"], "sync", default), Is.EqualTo(1));
        Assert.That((await A.GetActiveAsync(default)).Select(b => b.Address), Is.EqualTo(new[] { "203.0.113.2" }));
    }

    [Test]
    public async Task StatsAndEventsAndAgents()
    {
        await A.AddAsync(NewBan("203.0.113.1", null), default);
        await B.AddAsync(NewBan("203.0.113.2", DateTime.UtcNow.AddHours(1), rule: "nginx"), default);
        await A.RemoveAsync("203.0.113.1", "admin", default);
        await A.HeartbeatAsync(new AgentInfo { MachineName = "agent-a", StartedUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow }, default);
        await B.HeartbeatAsync(new AgentInfo { MachineName = "agent-b", StartedUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow }, default);

        var stats = await A.GetStatsAsync(default);
        Assert.That(stats.ActiveBans, Is.EqualTo(1));
        Assert.That(stats.TotalBans, Is.EqualTo(2));
        Assert.That(stats.BansLast24Hours, Is.EqualTo(2));
        Assert.That(stats.Agents.Select(a => a.MachineName), Is.EqualTo(new[] { "agent-a", "agent-b" }));
        Assert.That(stats.BansPerDay.Sum(d => d.Count), Is.EqualTo(2));

        var events = await B.GetEventsAsync(10, default);
        Assert.That(events.Select(e => e.Kind), Is.EqualTo(new[] { BanEventKinds.Unbanned, BanEventKinds.Banned, BanEventKinds.Banned }));
    }

    [Test]
    public async Task AllowlistIsSharedAndUnique()
    {
        await A.AddAllowAsync(new AllowEntry { Address = "203.0.113.0/24", Note = "office" }, default);
        await B.AddAllowAsync(new AllowEntry { Address = "203.0.113.0/24", Note = "again" }, default);

        var list = await B.GetAllowlistAsync(default);
        Assert.That(list, Has.Count.EqualTo(1));
        Assert.That(await A.RemoveAllowAsync("203.0.113.0/24", default), Is.True);
        Assert.That(await B.GetAllowlistAsync(default), Is.Empty);
    }

    [Test]
    public async Task ConcurrentAgentsBanningTheSameAddressConverge()
    {
        var tasks = Enumerable.Range(0, 6).Select(i => (i % 2 == 0 ? A : B).AddAsync(NewBan("203.0.113.99", null), default));
        await Task.WhenAll(tasks);

        var active = await A.GetActiveAsync(default);
        // Without a portable unique partial index a race may briefly create duplicates; readers must cope.
        Assert.That(active.Select(b => b.Address).Distinct().Count(), Is.EqualTo(1));
    }
}

[TestFixture, Category("Container")]
public class PostgreSqlStoreTests : StoreContractTests
{
    private PostgreSqlContainer? _container;

    protected override string Provider => StoreProviders.PostgreSql;

    protected override async Task<string> StartAsync()
    {
        _container = new PostgreSqlBuilder("postgres:18").Build();
        await _container.StartAsync();
        return _container.GetConnectionString();
    }

    protected override async Task StopAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}

[TestFixture, Category("Container")]
public class SqlServerStoreTests : StoreContractTests
{
    private MsSqlContainer? _container;

    protected override string Provider => StoreProviders.SqlServer;

    protected override async Task<string> StartAsync()
    {
        _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest").Build();
        await _container.StartAsync();
        return _container.GetConnectionString();
    }

    protected override async Task StopAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}

[TestFixture, Category("Container")]
public class MySqlStoreTests : StoreContractTests
{
    private MySqlContainer? _container;

    protected override string Provider => StoreProviders.MySql;

    protected override async Task<string> StartAsync()
    {
        _container = new MySqlBuilder("mysql:8.4").Build();
        await _container.StartAsync();
        return _container.GetConnectionString();
    }

    protected override async Task StopAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}
