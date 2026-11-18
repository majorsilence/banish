using System.Net.Sockets;
using System.Text;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Firewall;

/// <summary>
/// Linux iptables + ipset provider for hosts without nftables. Two ipsets (<c>banish</c> and
/// <c>banish6</c>) are rebuilt in a temporary set and swapped in atomically; one DROP rule per
/// family references each set.
/// </summary>
public sealed class IptablesFirewall : IFirewall
{
    private readonly IProcessRunner _runner;

    public IptablesFirewall(IProcessRunner runner) => _runner = runner;

    public string Name => "iptables+ipset";

    public async Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
    {
        var (v4, v6) = Split(addresses);
        await ApplyFamilyAsync("banish", "inet", "iptables", v4, cancellationToken).ConfigureAwait(false);
        await ApplyFamilyAsync("banish6", "inet6", "ip6tables", v6, cancellationToken).ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        foreach (var (set, tool) in new[] { ("banish", "iptables"), ("banish6", "ip6tables") })
        {
            while ((await _runner.RunAsync(tool, ["-D", "INPUT", "-m", "set", "--match-set", set, "src", "-j", "DROP"], null, cancellationToken).ConfigureAwait(false)).Success)
            {
            }

            await _runner.RunAsync("ipset", ["destroy", set], null, cancellationToken).ConfigureAwait(false);
        }
    }

    public static (List<string> V4, List<string> V6) Split(IReadOnlyCollection<string> addresses)
    {
        var v4 = new List<string>();
        var v6 = new List<string>();
        foreach (string address in addresses)
        {
            if (IpAddressUtil.TryParseNetwork(address, out var network))
            {
                (network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? v4 : v6).Add(IpAddressUtil.Format(network));
            }
        }

        return (v4, v6);
    }

    public static string BuildRestoreScript(string set, string family, IEnumerable<string> addresses)
    {
        string tmp = set + "_tmp";
        var sb = new StringBuilder();
        sb.AppendLine($"create {set} hash:net family {family} -exist");
        sb.AppendLine($"create {tmp} hash:net family {family} -exist");
        sb.AppendLine($"flush {tmp}");
        foreach (string address in addresses)
        {
            sb.AppendLine($"add {tmp} {address} -exist");
        }

        sb.AppendLine($"swap {tmp} {set}");
        sb.AppendLine($"destroy {tmp}");
        return sb.ToString();
    }

    private async Task ApplyFamilyAsync(string set, string family, string tool, List<string> addresses, CancellationToken ct)
    {
        (await _runner.RunAsync("ipset", ["restore"], BuildRestoreScript(set, family, addresses), ct).ConfigureAwait(false)).ThrowIfFailed("ipset restore");
        string[] rule = ["-m", "set", "--match-set", set, "src", "-j", "DROP"];
        var check = await _runner.RunAsync(tool, ["-C", "INPUT", .. rule], null, ct).ConfigureAwait(false);
        if (!check.Success)
        {
            (await _runner.RunAsync(tool, ["-I", "INPUT", "1", .. rule], null, ct).ConfigureAwait(false)).ThrowIfFailed(tool);
        }
    }
}
