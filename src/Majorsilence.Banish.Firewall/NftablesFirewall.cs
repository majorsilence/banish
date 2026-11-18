using System.Net.Sockets;
using System.Text;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Firewall;

/// <summary>
/// Linux nftables provider. Owns one table (<c>inet banish</c>) with an input chain at a priority
/// ahead of the usual filter chains and two interval sets. The whole state is replaced in a single
/// atomic <c>nft -f</c> transaction. Works alongside firewalld, ufw and plain iptables-nft.
/// </summary>
public sealed class NftablesFirewall : IFirewall
{
    public const string TableName = "banish";
    private readonly IProcessRunner _runner;

    public NftablesFirewall(IProcessRunner runner) => _runner = runner;

    public string Name => "nftables";

    public async Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync("nft", ["-f", "-"], BuildScript(addresses), cancellationToken).ConfigureAwait(false);
        result.ThrowIfFailed("nft");
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync("nft", ["delete", "table", "inet", TableName], null, cancellationToken).ConfigureAwait(false);
        // A missing table is fine.
        if (!result.Success && !result.StdErr.Contains("No such file", StringComparison.OrdinalIgnoreCase))
        {
            result.ThrowIfFailed("nft delete table");
        }
    }

    public static string BuildScript(IReadOnlyCollection<string> addresses)
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

        var sb = new StringBuilder();
        sb.AppendLine($"add table inet {TableName}");
        sb.AppendLine($"add set inet {TableName} banned4 {{ type ipv4_addr; flags interval; auto-merge; }}");
        sb.AppendLine($"add set inet {TableName} banned6 {{ type ipv6_addr; flags interval; auto-merge; }}");
        sb.AppendLine($"add chain inet {TableName} input {{ type filter hook input priority -10; policy accept; }}");
        sb.AppendLine($"flush chain inet {TableName} input");
        sb.AppendLine($"add rule inet {TableName} input ip saddr @banned4 counter drop");
        sb.AppendLine($"add rule inet {TableName} input ip6 saddr @banned6 counter drop");
        sb.AppendLine($"flush set inet {TableName} banned4");
        sb.AppendLine($"flush set inet {TableName} banned6");
        AppendElements(sb, "banned4", v4);
        AppendElements(sb, "banned6", v6);
        return sb.ToString();
    }

    private static void AppendElements(StringBuilder sb, string set, List<string> elements)
    {
        // Chunked so one line never becomes enormous.
        foreach (var chunk in elements.Chunk(1000))
        {
            sb.AppendLine($"add element inet {TableName} {set} {{ {string.Join(", ", chunk)} }}");
        }
    }
}
