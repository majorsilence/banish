using Majorsilence.Banish.Core;
using Majorsilence.Banish.Firewall;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class FirewallTests
{
    private sealed class RecordingRunner : IProcessRunner
    {
        public List<(string File, string Args, string? Stdin)> Calls { get; } = [];
        public Func<string, IReadOnlyList<string>, ProcessResult> Respond { get; set; } = (_, _) => new ProcessResult(0, "", "");

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? stdin, CancellationToken cancellationToken)
        {
            Calls.Add((fileName, string.Join(' ', arguments), stdin));
            return Task.FromResult(Respond(fileName, arguments));
        }
    }

    [Test]
    public void NftablesScriptSplitsFamiliesAndReplacesState()
    {
        string script = NftablesFirewall.BuildScript(["203.0.113.5", "198.51.100.0/24", "2001:db8::/32"]);

        Assert.That(script, Does.Contain("add table inet banish"));
        Assert.That(script, Does.Contain("add element inet banish banned4 { 203.0.113.5, 198.51.100.0/24 }"));
        Assert.That(script, Does.Contain("add element inet banish banned6 { 2001:db8::/32 }"));
        Assert.That(script.IndexOf("flush set inet banish banned4", StringComparison.Ordinal),
            Is.LessThan(script.IndexOf("add element", StringComparison.Ordinal)));
        Assert.That(script, Does.Contain("ip saddr @banned4 counter drop"));
    }

    [Test]
    public void NftablesScriptWithNoAddressesStillFlushes()
    {
        string script = NftablesFirewall.BuildScript([]);
        Assert.That(script, Does.Contain("flush set inet banish banned4"));
        Assert.That(script, Does.Not.Contain("add element"));
    }

    [Test]
    public async Task NftablesPipesScriptToNft()
    {
        var runner = new RecordingRunner();
        await new NftablesFirewall(runner).ApplyAsync(["203.0.113.5"], default);

        Assert.That(runner.Calls, Has.Count.EqualTo(1));
        Assert.That(runner.Calls[0].File, Is.EqualTo("nft"));
        Assert.That(runner.Calls[0].Args, Is.EqualTo("-f -"));
        Assert.That(runner.Calls[0].Stdin, Does.Contain("203.0.113.5"));
    }

    [Test]
    public async Task FailureSurfacesAsFirewallException()
    {
        var runner = new RecordingRunner { Respond = (_, _) => new ProcessResult(1, "", "Operation not permitted") };
        var ex = await Assert.ThrowsAsync<FirewallException>(() => new NftablesFirewall(runner).ApplyAsync(["203.0.113.5"], default));
        Assert.That(ex!.Message, Does.Contain("Operation not permitted"));
    }

    [Test]
    public async Task IptablesBuildsRestoreScriptAndInstallsRuleOnce()
    {
        var runner = new RecordingRunner
        {
            Respond = (file, args) => file != "ipset" && args[0] == "-C" ? new ProcessResult(1, "", "") : new ProcessResult(0, "", ""),
        };
        await new IptablesFirewall(runner).ApplyAsync(["203.0.113.5", "2001:db8::1"], default);

        var restore = runner.Calls.Where(c => c.File == "ipset").ToList();
        Assert.That(restore, Has.Count.EqualTo(2));
        Assert.That(restore[0].Stdin, Does.Contain("create banish hash:net family inet"));
        Assert.That(restore[0].Stdin, Does.Contain("add banish_tmp 203.0.113.5"));
        Assert.That(restore[0].Stdin, Does.Contain("swap banish_tmp banish"));
        Assert.That(restore[1].Stdin, Does.Contain("add banish6_tmp 2001:db8::1"));
        Assert.That(runner.Calls.Count(c => c.File == "iptables" && c.Args.StartsWith("-I INPUT 1", StringComparison.Ordinal)), Is.EqualTo(1));
        Assert.That(runner.Calls.Count(c => c.File == "ip6tables" && c.Args.StartsWith("-I INPUT 1", StringComparison.Ordinal)), Is.EqualTo(1));
    }

    [Test]
    public async Task IptablesDoesNotDuplicateAnExistingRule()
    {
        var runner = new RecordingRunner();
        await new IptablesFirewall(runner).ApplyAsync(["203.0.113.5"], default);
        Assert.That(runner.Calls.Any(c => c.Args.StartsWith("-I INPUT", StringComparison.Ordinal)), Is.False);
    }

    [Test]
    public void PfRulesDefineTableAndBlock()
    {
        string rules = PfFirewall.BuildRules(["203.0.113.5", "198.51.100.0/24"]);
        Assert.That(rules, Does.Contain("table <banished> persist {203.0.113.5, 198.51.100.0/24}"));
        Assert.That(rules, Does.Contain("block drop in quick from <banished> to any"));
    }

    [Test]
    public async Task PfLoadsAnchorAndEnablesOnce()
    {
        var runner = new RecordingRunner();
        var pf = new PfFirewall(runner);
        await pf.ApplyAsync(["203.0.113.5"], default);
        await pf.ApplyAsync(["203.0.113.6"], default);

        Assert.That(runner.Calls.Count(c => c.Args == "-E"), Is.EqualTo(1));
        Assert.That(runner.Calls.Count(c => c.Args == "-a banish -f -"), Is.EqualTo(2));
    }

    [Test]
    public void WindowsRulesAreChunkedAndNamedStably()
    {
        var addresses = Enumerable.Range(0, 2500).Select(i => $"10.{i / 250}.{i % 250}.1").ToList();
        var plan = WindowsFirewallRules.Plan(addresses);

        Assert.That(plan.Select(p => p.Name), Is.EqualTo(new[] { "Banish_Block_0", "Banish_Block_1", "Banish_Block_2" }));
        Assert.That(plan[0].RemoteAddresses.Split(',').Length, Is.EqualTo(WindowsFirewallRules.AddressesPerRule));
        Assert.That(WindowsFirewallRules.Plan([]), Is.Empty);
    }

    [Test]
    public async Task ReconcilerAppliesOnlyOnChangeAndSkipsAllowListed()
    {
        var clock = new ManualTimeProvider();
        await using var temp = new TempStore(clock);
        var store = await temp.CreateAsync();
        var firewall = new CapturingFirewall();
        var allow = Allowlist.Create(["203.0.113.9"], false, false);
        var reconciler = new FirewallReconciler(store, firewall, () => allow);

        await store.AddAsync(new Ban { Address = "203.0.113.5", Source = "manual", CreatedUtc = clock.GetUtcNow().UtcDateTime }, default);
        await store.AddAsync(new Ban { Address = "203.0.113.9", Source = "manual", CreatedUtc = clock.GetUtcNow().UtcDateTime }, default);

        Assert.That(await reconciler.ReconcileAsync(default), Is.True);
        Assert.That(firewall.Applied.Single(), Is.EqualTo(new[] { "203.0.113.5" }));
        Assert.That(await reconciler.ReconcileAsync(default), Is.False, "no change, no apply");

        await store.RemoveAsync("203.0.113.5", "t", default);
        Assert.That(await reconciler.ReconcileAsync(default), Is.True);
        Assert.That(firewall.Applied.Last(), Is.Empty);
    }

    private sealed class CapturingFirewall : IFirewall
    {
        public List<string[]> Applied { get; } = [];

        public string Name => "capture";

        public Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
        {
            Applied.Add([.. addresses]);
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
