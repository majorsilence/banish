using Majorsilence.Banish.Core;
using Majorsilence.Banish.Hosting;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class RetentionTests
{
    private static Ban NewBan(string address, DateTime now, DateTime? expires) => new()
    {
        Address = address,
        Source = BanSources.Local,
        Reason = "test",
        CreatedUtc = now,
        ExpiresUtc = expires,
        Hits = 1,
    };

    [Test]
    public async Task Prune_deletes_only_ended_bans_and_old_events()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var t0 = clock.GetUtcNow().UtcDateTime;

        await store.AddAsync(NewBan("203.0.113.1", t0, t0.AddMinutes(10)), default);   // expires, never lifted
        await store.AddAsync(NewBan("203.0.113.2", t0, null), default);                // lifted below
        await store.RemoveAsync("203.0.113.2", "admin", default);
        await store.AddAsync(NewBan("203.0.113.3", t0, null), default);                // permanent, still active

        clock.Advance(TimeSpan.FromDays(400));
        var now = clock.GetUtcNow().UtcDateTime;
        await store.AddAsync(NewBan("203.0.113.4", now, now.AddHours(1)), default);    // recent and active

        var (bans, events) = PruneService.Cutoffs(new RetentionOptions { BanHistoryDays = 365, EventDays = 90 }, now);

        var preview = await store.PruneAsync(bans, events, dryRun: true, default);
        Assert.That(preview.Bans, Is.EqualTo(2));
        Assert.That((await store.QueryAsync(new BanQuery { State = "all", Take = 50 }, default)).Total, Is.EqualTo(4), "dry run deletes nothing");

        var result = await store.PruneAsync(bans, events, dryRun: false, default);
        Assert.That(result.Bans, Is.EqualTo(2));
        Assert.That(result.Events, Is.GreaterThan(0));

        var left = await store.QueryAsync(new BanQuery { State = "all", Take = 50 }, default);
        Assert.That(left.Items.Select(b => b.Address), Is.EquivalentTo(new[] { "203.0.113.3", "203.0.113.4" }));
        Assert.That(await store.CountPriorAsync("203.0.113.1", default), Is.Zero, "the old history is forgotten");
    }

    [Test]
    public async Task A_null_cutoff_keeps_that_kind_forever()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var t0 = clock.GetUtcNow().UtcDateTime;
        await store.AddAsync(NewBan("203.0.113.1", t0, t0.AddMinutes(10)), default);
        clock.Advance(TimeSpan.FromDays(900));

        var (bans, events) = PruneService.Cutoffs(new RetentionOptions { BanHistoryDays = 0, EventDays = 0 }, clock.GetUtcNow().UtcDateTime);
        Assert.That(bans, Is.Null);
        Assert.That(events, Is.Null);
        var result = await store.PruneAsync(bans, events, dryRun: false, default);
        Assert.That(result, Is.EqualTo(new PruneResult(0, 0)));
    }
}
