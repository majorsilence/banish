using Majorsilence.Banish.Core;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class EfBanStoreTests
{
    private static Ban NewBan(string address, DateTime? expires, string source = BanSources.Local, string rule = "sshd", string machine = "a") => new()
    {
        Address = address,
        Reason = "test",
        Source = source,
        RuleId = rule,
        CreatedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        ExpiresUtc = expires,
        MachineName = machine,
        Hits = 5,
    };

    [Test]
    public async Task AddedBanIsActiveUntilItExpires()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        await store.AddAsync(NewBan("203.0.113.5", clock.GetUtcNow().UtcDateTime.AddMinutes(10)), default);

        Assert.That(await store.GetActiveAsync(default), Has.Count.EqualTo(1));
        clock.Advance(TimeSpan.FromMinutes(11));
        Assert.That(await store.GetActiveAsync(default), Is.Empty);
        Assert.That(await store.CountPriorAsync("203.0.113.5", default), Is.EqualTo(1));
    }

    [Test]
    public async Task AddingAnActiveAddressExtendsInsteadOfDuplicating()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var now = clock.GetUtcNow().UtcDateTime;
        await store.AddAsync(NewBan("203.0.113.5", now.AddMinutes(10)), default);
        var merged = await store.AddAsync(NewBan("203.0.113.5", now.AddHours(1)), default);

        Assert.That(await store.GetActiveAsync(default), Has.Count.EqualTo(1));
        Assert.That(merged.ExpiresUtc, Is.EqualTo(now.AddHours(1)));
        Assert.That(merged.Hits, Is.EqualTo(10));

        await store.AddAsync(NewBan("203.0.113.5", null), default);
        Assert.That((await store.GetActiveByAddressAsync("203.0.113.5", default))!.ExpiresUtc, Is.Null, "permanent wins");
    }

    [Test]
    public async Task RemoveLiftsBanAndRecordsEvent()
    {
        await using var temp = new TempStore(new ManualTimeProvider());
        var store = await temp.CreateAsync();
        await store.AddAsync(NewBan("203.0.113.5", null), default);

        Assert.That(await store.RemoveAsync("203.0.113.5", "alice", default), Is.EqualTo(1));
        Assert.That(await store.RemoveAsync("203.0.113.5", "alice", default), Is.EqualTo(0));
        Assert.That(await store.GetActiveAsync(default), Is.Empty);

        var events = await store.GetEventsAsync(10, default);
        Assert.That(events.Select(e => e.Kind), Is.EqualTo(new[] { BanEventKinds.Unbanned, BanEventKinds.Banned }));
        Assert.That(events[0].Actor, Is.EqualTo("alice"));
    }

    [Test]
    public async Task RemoveBySourceKeepsListedAddresses()
    {
        await using var temp = new TempStore(new ManualTimeProvider());
        var store = await temp.CreateAsync();
        await store.AddAsync(NewBan("203.0.113.1", null, "blocklist:x"), default);
        await store.AddAsync(NewBan("203.0.113.2", null, "blocklist:x"), default);
        await store.AddAsync(NewBan("203.0.113.3", null, "blocklist:y"), default);

        int removed = await store.RemoveBySourceAsync("blocklist:x", ["203.0.113.1"], "sync", default);

        Assert.That(removed, Is.EqualTo(1));
        Assert.That((await store.GetActiveAsync(default)).Select(b => b.Address), Is.EquivalentTo(new[] { "203.0.113.1", "203.0.113.3" }));
    }

    [Test]
    public async Task QueryFiltersAndPages()
    {
        await using var temp = new TempStore(new ManualTimeProvider());
        var store = await temp.CreateAsync();
        for (int i = 1; i <= 5; i++)
        {
            await store.AddAsync(NewBan($"203.0.113.{i}", null, i % 2 == 0 ? BanSources.Manual : BanSources.Local), default);
        }

        await store.RemoveAsync("203.0.113.1", "x", default);

        var active = await store.QueryAsync(new BanQuery { Take = 2 }, default);
        Assert.That(active.Total, Is.EqualTo(4));
        Assert.That(active.Items, Has.Count.EqualTo(2));
        Assert.That((await store.QueryAsync(new BanQuery { State = "removed" }, default)).Total, Is.EqualTo(1));
        Assert.That((await store.QueryAsync(new BanQuery { State = "all" }, default)).Total, Is.EqualTo(5));
        Assert.That((await store.QueryAsync(new BanQuery { Source = BanSources.Manual }, default)).Total, Is.EqualTo(2));
        Assert.That((await store.QueryAsync(new BanQuery { Search = "113.3" }, default)).Total, Is.EqualTo(1));
    }

    [Test]
    public async Task StatsSummarizeBans()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var now = clock.GetUtcNow().UtcDateTime;
        await store.AddAsync(NewBan("203.0.113.1", null), default);
        await store.AddAsync(NewBan("203.0.113.2", now.AddHours(1), rule: "nginx", machine: "b"), default);
        await store.HeartbeatAsync(new AgentInfo { MachineName = "a", LastSeenUtc = now, StartedUtc = now }, default);

        var stats = await store.GetStatsAsync(default);

        Assert.That(stats.ActiveBans, Is.EqualTo(2));
        Assert.That(stats.PermanentBans, Is.EqualTo(1));
        Assert.That(stats.TotalBans, Is.EqualTo(2));
        Assert.That(stats.BansPerDay, Has.Count.EqualTo(7));
        Assert.That(stats.TopRules.Select(r => r.Key), Is.EquivalentTo(new[] { "sshd", "nginx" }));
        Assert.That(stats.ByMachine, Has.Count.EqualTo(2));
        Assert.That(stats.Agents, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task AllowlistAddIsIdempotentAndRemovable()
    {
        await using var temp = new TempStore(new ManualTimeProvider());
        var store = await temp.CreateAsync();
        await store.AddAllowAsync(new AllowEntry { Address = "203.0.113.0/24", Note = "office" }, default);
        await store.AddAllowAsync(new AllowEntry { Address = "203.0.113.0/24", Note = "office2" }, default);

        Assert.That(await store.GetAllowlistAsync(default), Has.Count.EqualTo(1));
        Assert.That(await store.RemoveAllowAsync("203.0.113.0/24", default), Is.True);
        Assert.That(await store.RemoveAllowAsync("203.0.113.0/24", default), Is.False);
    }

    [Test]
    public async Task HeartbeatUpdatesExistingAgent()
    {
        await using var temp = new TempStore(new ManualTimeProvider());
        var store = await temp.CreateAsync();
        var t = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        await store.HeartbeatAsync(new AgentInfo { MachineName = "a", AppliedBans = 1, LastSeenUtc = t, StartedUtc = t }, default);
        await store.HeartbeatAsync(new AgentInfo { MachineName = "a", AppliedBans = 7, LastSeenUtc = t.AddMinutes(1), StartedUtc = t }, default);

        var agents = (await store.GetStatsAsync(default)).Agents;
        Assert.That(agents, Has.Count.EqualTo(1));
        Assert.That(agents[0].AppliedBans, Is.EqualTo(7));
        Assert.That(agents[0].LastSeenUtc.Kind, Is.EqualTo(DateTimeKind.Utc));
    }
}
