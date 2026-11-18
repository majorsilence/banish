using System.Runtime.Versioning;
using System.Security.Principal;
using Majorsilence.Banish.Firewall;

namespace Majorsilence.Banish.Tests;

/// <summary>
/// Runs against the real Windows Firewall COM API. Rule creation needs an elevated process, so the tests
/// that edit rules are skipped otherwise. They use a unique rule-name prefix and documentation addresses
/// (RFC 5737 / RFC 3849), never the real <c>Banish_Block_*</c> rules.
/// </summary>
[Platform("Win")]
[SupportedOSPlatform("windows")]
public class WindowsFirewallTests
{
    private string _prefix = "";

    [SetUp]
    public void SetUp() => _prefix = "BanishTest_" + Guid.NewGuid().ToString("N")[..8] + "_";

    [TearDown]
    public async Task TearDown()
    {
        if (IsAdministrator())
        {
            await new WindowsFirewall(_prefix).ClearAsync(default);
        }
    }

    [Test]
    public void NormalizeMatchesWhatWindowsReadsBack()
    {
        string normalized = WindowsFirewall.Normalize("203.0.113.5,198.51.100.0/24,2001:db8::1,2001:db8::/32");

        Assert.That(normalized, Does.Contain("203.0.113.5/255.255.255.255"));
        Assert.That(normalized, Does.Contain("198.51.100.0/255.255.255.0"));
        Assert.That(normalized, Does.Contain("2001:db8::/32"));
        Assert.That(WindowsFirewall.Normalize(normalized), Is.EqualTo(normalized), "normalising twice must not change anything");
        Assert.That(WindowsFirewall.Normalize("2001:db8::/32,198.51.100.0/24,2001:db8::1,203.0.113.5"), Is.EqualTo(normalized), "order must not matter");
    }

    [Test]
    public async Task ApplyCreatesInboundBlockRulesAndIsIdempotent()
    {
        RequireAdministrator();
        var firewall = new WindowsFirewall(_prefix);
        string[] addresses = ["203.0.113.5", "198.51.100.0/24", "2001:db8::1", "2001:db8:1::/48"];

        await firewall.ApplyAsync(addresses, default);

        var rule = FindRule(_prefix + "0");
        Assert.That(rule, Is.Not.Null);
        Assert.That((int)rule!.Action, Is.EqualTo(0), "block");
        Assert.That((int)rule.Direction, Is.EqualTo(1), "inbound");
        Assert.That((bool)rule.Enabled, Is.True);
        Assert.That((int)rule.Profiles, Is.EqualTo(0x7FFFFFFF), "all profiles");
        string before = rule.RemoteAddresses;
        Assert.That(before, Is.EqualTo(WindowsFirewall.Normalize(string.Join(",", addresses.OrderBy(a => a, StringComparer.Ordinal)))));

        await firewall.ApplyAsync(addresses, default);
        Assert.That(CountRules(_prefix), Is.EqualTo(1));
        Assert.That((string)FindRule(_prefix + "0")!.RemoteAddresses, Is.EqualTo(before));

        await firewall.ApplyAsync(["203.0.113.6"], default);
        Assert.That(CountRules(_prefix), Is.EqualTo(1));
        Assert.That((string)FindRule(_prefix + "0")!.RemoteAddresses, Is.EqualTo(WindowsFirewall.Normalize("203.0.113.6")));
    }

    [Test]
    public async Task ManyAddressesSpillIntoSeveralRulesAndClearRemovesThem()
    {
        RequireAdministrator();
        var firewall = new WindowsFirewall(_prefix);
        var addresses = Enumerable.Range(0, 2500).Select(i => $"198.51.{100 + i / 250}.{i % 250 + 1}").ToList();

        await firewall.ApplyAsync(addresses, default);
        Assert.That(CountRules(_prefix), Is.EqualTo(3));

        await firewall.ApplyAsync(addresses.Take(1200).ToList(), default);
        Assert.That(CountRules(_prefix), Is.EqualTo(2), "surplus rules are removed");

        await firewall.ClearAsync(default);
        Assert.That(CountRules(_prefix), Is.EqualTo(0));
    }

    [Test]
    public async Task ApplyRepairsADisabledRule()
    {
        RequireAdministrator();
        var firewall = new WindowsFirewall(_prefix);
        await firewall.ApplyAsync(["203.0.113.5"], default);
        FindRule(_prefix + "0")!.Enabled = false;

        await firewall.ApplyAsync(["203.0.113.5"], default);

        Assert.That((bool)FindRule(_prefix + "0")!.Enabled, Is.True);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void RequireAdministrator()
    {
        if (!IsAdministrator())
        {
            Assert.Ignore("Editing Windows Firewall rules needs an elevated (Administrator) process.");
        }
    }

    private static dynamic? FindRule(string name)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
        foreach (dynamic rule in policy.Rules)
        {
            if (string.Equals((string)rule.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return rule;
            }
        }

        return null;
    }

    private static int CountRules(string prefix)
    {
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
        int count = 0;
        foreach (dynamic rule in policy.Rules)
        {
            if (((string)rule.Name).StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                count++;
            }
        }

        return count;
    }
}
