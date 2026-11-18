using System.Net;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class BanEngineTests
{
    private static RuleOptions Rule(int maxRetry = 3, int findTime = 60, params long[] minutes) =>
        new() { Name = "r", MaxRetry = maxRetry, FindTimeSeconds = findTime, BanMinutes = [.. minutes] };

    private static FailureEvent Fail(string ip, string rule = "r") => new(IPAddress.Parse(ip), rule, DateTime.UtcNow);

    private static Allowlist NoAllow() => Allowlist.Create([], false, false);

    [Test]
    public async Task BansAfterMaxRetryFailures()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var engine = new BanEngine(store, [Rule(3, 60, 10)], NoAllow, "m", clock);

        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5"), default), Is.Null);
        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5"), default), Is.Null);
        var ban = await engine.ReportFailureAsync(Fail("203.0.113.5"), default);

        Assert.That(ban, Is.Not.Null);
        Assert.That(ban!.Address, Is.EqualTo("203.0.113.5"));
        Assert.That(ban.RuleId, Is.EqualTo("r"));
        Assert.That(ban.ExpiresUtc - ban.CreatedUtc, Is.EqualTo(TimeSpan.FromMinutes(10)));
        Assert.That((await store.GetActiveAsync(default)).Count, Is.EqualTo(1));
    }

    [Test]
    public async Task FailuresOutsideTheWindowDoNotCount()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var engine = new BanEngine(store, [Rule(3, 60)], NoAllow, "m", clock);

        await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5"), default), Is.Null);
    }

    [Test]
    public async Task CountsAreKeptPerAddress()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var engine = new BanEngine(store, [Rule(2)], NoAllow, "m", clock);

        await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.6"), default), Is.Null);
    }

    [Test]
    public async Task AllowListedAddressesAreNeverBanned()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var allow = Allowlist.Create(["203.0.113.0/24"], false, false);
        var engine = new BanEngine(store, [Rule(1)], () => allow, "m", clock);

        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5"), default), Is.Null);
        Assert.That(await store.GetActiveAsync(default), Is.Empty);
    }

    [Test]
    public async Task RepeatOffendersGetLongerBans()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var engine = new BanEngine(store, [Rule(1, 60, 10, 60, 0)], NoAllow, "m", clock);

        var first = await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        Assert.That(first!.ExpiresUtc - first.CreatedUtc, Is.EqualTo(TimeSpan.FromMinutes(10)));

        await store.RemoveAsync("203.0.113.5", "test", default);
        var second = await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        Assert.That(second!.ExpiresUtc - second.CreatedUtc, Is.EqualTo(TimeSpan.FromMinutes(60)));

        await store.RemoveAsync("203.0.113.5", "test", default);
        var third = await engine.ReportFailureAsync(Fail("203.0.113.5"), default);
        Assert.That(third!.ExpiresUtc, Is.Null, "0 minutes means permanent");
    }

    [Test]
    public async Task UnknownAndDisabledRulesAreIgnored()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var disabled = Rule(1);
        disabled.Enabled = false;
        var engine = new BanEngine(store, [disabled], NoAllow, "m", clock);

        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5"), default), Is.Null);
        Assert.That(await engine.ReportFailureAsync(Fail("203.0.113.5", "nope"), default), Is.Null);
    }

    [Test]
    public void EscalationLadderRepeatsTheLastEntry()
    {
        long[] ladder = [10, 60];
        Assert.That(Escalation.DurationFor(ladder, 0), Is.EqualTo(TimeSpan.FromMinutes(10)));
        Assert.That(Escalation.DurationFor(ladder, 1), Is.EqualTo(TimeSpan.FromMinutes(60)));
        Assert.That(Escalation.DurationFor(ladder, 9), Is.EqualTo(TimeSpan.FromMinutes(60)));
        Assert.That(Escalation.DurationFor([], 0), Is.EqualTo(TimeSpan.FromMinutes(10)));
    }
}
