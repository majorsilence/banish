using System.Runtime.Versioning;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Firewall;

/// <summary>
/// Windows Firewall provider using the <c>HNetCfg.FwPolicy2</c> COM API. Blocked addresses are
/// packed into inbound block rules named <c>Banish_Block_0</c>, <c>Banish_Block_1</c>, ... holding
/// up to <see cref="WindowsFirewallRules.AddressesPerRule"/> addresses each; rules are created, updated or removed to
/// match the desired set.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsFirewall : IFirewall
{
    private const int ActionBlock = 0;
    private const int DirectionIn = 1;
    private const int ProfilesAll = 0x7FFFFFFF;

    private readonly string _prefix;

    public WindowsFirewall()
        : this(WindowsFirewallRules.RulePrefix)
    {
    }

    /// <summary>Uses a different rule-name prefix; tests use this so they never touch real Banish rules.</summary>
    public WindowsFirewall(string rulePrefix)
    {
        _prefix = rulePrefix;
    }

    public string Name => "windows-firewall";

    public Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
    {
        var chunks = WindowsFirewallRules.Plan(addresses, _prefix);
        dynamic policy = CreatePolicy();
        dynamic rules = policy.Rules;
        var existing = new Dictionary<string, dynamic>(StringComparer.OrdinalIgnoreCase);
        foreach (dynamic rule in rules)
        {
            string name = rule.Name;
            if (name.StartsWith(_prefix, StringComparison.OrdinalIgnoreCase))
            {
                existing[name] = rule;
            }
        }

        foreach (var (name, remote) in chunks)
        {
            if (existing.Remove(name, out dynamic? current))
            {
                // Windows rewrites RemoteAddresses on read (sorted, netmasks, IPv6 hosts as ranges), so the
                // desired list is run through a scratch rule before comparing; otherwise every apply would rewrite.
                if (!string.Equals((string)current.RemoteAddresses, Normalize(remote), StringComparison.OrdinalIgnoreCase)
                    || !(bool)current.Enabled
                    || (int)current.Action != ActionBlock
                    || (int)current.Direction != DirectionIn)
                {
                    current.Action = ActionBlock;
                    current.Direction = DirectionIn;
                    current.Enabled = true;
                    current.RemoteAddresses = remote;
                }
            }
            else
            {
                dynamic rule = NewRule();
                rule.Name = name;
                rule.Description = "Blocked by Banish";
                rule.Action = ActionBlock;
                rule.Direction = DirectionIn;
                rule.Enabled = true;
                rule.Profiles = ProfilesAll;
                rule.RemoteAddresses = remote;
                rules.Add(rule);
            }
        }

        foreach (string stale in existing.Keys.ToList())
        {
            rules.Remove(stale);
        }

        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken cancellationToken) => ApplyAsync([], cancellationToken);

    /// <summary>The address list as Windows stores and returns it (used for comparisons).</summary>
    public static string Normalize(string remoteAddresses)
    {
        dynamic scratch = NewRule();
        scratch.RemoteAddresses = remoteAddresses;
        return (string)scratch.RemoteAddresses;
    }

    private static dynamic NewRule() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;

    private static dynamic CreatePolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
}

/// <summary>Platform-independent planning of Windows Firewall rules.</summary>
public static class WindowsFirewallRules
{
    public const string RulePrefix = "Banish_Block_";
    public const int AddressesPerRule = 1000;

    /// <summary>Splits addresses into rule names and comma-separated remote-address lists.</summary>
    public static List<(string Name, string RemoteAddresses)> Plan(IReadOnlyCollection<string> addresses) =>
        Plan(addresses, RulePrefix);

    public static List<(string Name, string RemoteAddresses)> Plan(IReadOnlyCollection<string> addresses, string prefix)
    {
        var result = new List<(string, string)>();
        int index = 0;
        foreach (var chunk in addresses.OrderBy(a => a, StringComparer.Ordinal).Chunk(AddressesPerRule))
        {
            result.Add((prefix + index++, string.Join(",", chunk)));
        }

        return result;
    }
}
