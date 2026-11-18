using System.Text;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Firewall;

/// <summary>
/// macOS (and BSD) pf provider. Loads a table and a blocking rule into the <c>banish</c> anchor.
/// The main ruleset must reference the anchor (<c>anchor "banish"</c> in /etc/pf.conf);
/// <see cref="IsAnchorReferencedAsync"/> reports whether it does.
/// </summary>
public sealed class PfFirewall : IFirewall
{
    public const string AnchorName = "banish";
    private readonly IProcessRunner _runner;
    private bool _enabled;

    public PfFirewall(IProcessRunner runner) => _runner = runner;

    public string Name => "pf";

    public async Task ApplyAsync(IReadOnlyCollection<string> addresses, CancellationToken cancellationToken)
    {
        if (!_enabled)
        {
            (await _runner.RunAsync("pfctl", ["-E"], null, cancellationToken).ConfigureAwait(false)).ThrowIfFailedUnlessEnabled();
            _enabled = true;
        }

        (await _runner.RunAsync("pfctl", ["-a", AnchorName, "-f", "-"], BuildRules(addresses), cancellationToken).ConfigureAwait(false)).ThrowIfFailed("pfctl");
    }

    public async Task ClearAsync(CancellationToken cancellationToken) =>
        await _runner.RunAsync("pfctl", ["-a", AnchorName, "-F", "all"], null, cancellationToken).ConfigureAwait(false);

    public async Task<bool> IsAnchorReferencedAsync(CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync("pfctl", ["-s", "rules"], null, cancellationToken).ConfigureAwait(false);
        return result.Success && result.StdOut.Contains($"anchor \"{AnchorName}\"", StringComparison.Ordinal);
    }

    public static string BuildRules(IReadOnlyCollection<string> addresses)
    {
        var sb = new StringBuilder();
        sb.Append("table <banished> persist {");
        sb.Append(string.Join(", ", addresses));
        sb.AppendLine("}");
        sb.AppendLine("block drop in quick from <banished> to any");
        return sb.ToString();
    }
}

internal static class PfResultExtensions
{
    // `pfctl -E` exits non-zero noise when pf is already enabled on some macOS versions; treat as success.
    public static void ThrowIfFailedUnlessEnabled(this ProcessResult result)
    {
        if (!result.Success && !result.StdErr.Contains("already", StringComparison.OrdinalIgnoreCase)
            && !result.StdErr.Contains("pf enabled", StringComparison.OrdinalIgnoreCase))
        {
            result.ThrowIfFailed("pfctl -E");
        }
    }
}
