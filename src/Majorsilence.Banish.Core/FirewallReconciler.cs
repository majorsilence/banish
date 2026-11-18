using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Core;

/// <summary>
/// Makes the host firewall match the store: every active, non-allow-listed ban is blocked and
/// everything else is not. The store is the source of truth.
/// </summary>
public sealed class FirewallReconciler
{
    private readonly IBanStore _store;
    private readonly IFirewall _firewall;
    private readonly Func<Allowlist> _allowlist;
    private readonly ILogger _logger;
    private string? _lastFingerprint;

    public FirewallReconciler(IBanStore store, IFirewall firewall, Func<Allowlist> allowlist, ILogger? logger = null)
    {
        _store = store;
        _firewall = firewall;
        _allowlist = allowlist;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    public int AppliedCount { get; private set; }

    /// <summary>Returns true when the firewall was changed.</summary>
    public async Task<bool> ReconcileAsync(CancellationToken cancellationToken)
    {
        var allow = _allowlist();
        var active = await _store.GetActiveAsync(cancellationToken).ConfigureAwait(false);
        var desired = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var ban in active)
        {
            if (!IpAddressUtil.TryParseNetwork(ban.Address, out var network) || allow.Overlaps(network))
            {
                continue;
            }

            desired.Add(IpAddressUtil.Format(network));
        }

        string fingerprint = string.Join('\n', desired);
        if (fingerprint == _lastFingerprint)
        {
            return false;
        }

        await _firewall.ApplyAsync(desired, cancellationToken).ConfigureAwait(false);
        _lastFingerprint = fingerprint;
        AppliedCount = desired.Count;
        _logger.LogInformation("Firewall {Firewall} now blocks {Count} addresses", _firewall.Name, desired.Count);
        return true;
    }
}
