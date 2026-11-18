using Majorsilence.Banish.Core;
using Microsoft.AspNetCore.Components.Authorization;

namespace Majorsilence.Banish.Dashboard;

/// <summary>
/// Everything the dashboard shows or changes. Reads are masked for anyone who is not an admin when
/// <c>Dashboard:MaskIps</c> is on; every write re-checks, on the server, that the caller is an admin.
/// </summary>
public sealed class DashboardService
{
    private readonly IBanStore _store;
    private readonly AuthenticationStateProvider _auth;
    private readonly BanishOptions _options;
    private readonly AllowlistProvider _allowlist;

    private readonly IBlocklistSync? _sync;

    public DashboardService(IBanStore store, AuthenticationStateProvider auth, BanishOptions options, AllowlistProvider allowlist, IBlocklistSync? sync = null)
    {
        _sync = sync;
        _store = store;
        _auth = auth;
        _options = options;
        _allowlist = allowlist;
    }

    public async Task<bool> IsAdminAsync()
    {
        var state = await _auth.GetAuthenticationStateAsync().ConfigureAwait(false);
        return state.User.IsInRole(ApiRoles.Admin);
    }

    private async Task<bool> ShouldMaskAsync() => _options.Dashboard.MaskIps && !await IsAdminAsync().ConfigureAwait(false);

    private async Task RequireAdminAsync()
    {
        if (!await IsAdminAsync().ConfigureAwait(false))
        {
            throw new UnauthorizedAccessException("Administrator rights are required.");
        }
    }

    private async Task<string> UserNameAsync() =>
        (await _auth.GetAuthenticationStateAsync().ConfigureAwait(false)).User.Identity?.Name ?? "unknown";

    public async Task<BanStats> GetStatsAsync(CancellationToken ct = default)
    {
        var stats = await _store.GetStatsAsync(ct).ConfigureAwait(false);
        return await ShouldMaskAsync().ConfigureAwait(false) ? IpMasker.Mask(stats) : stats;
    }

    public async Task<PagedResult<Ban>> QueryAsync(BanQuery query, CancellationToken ct = default)
    {
        var page = await _store.QueryAsync(query, ct).ConfigureAwait(false);
        return await ShouldMaskAsync().ConfigureAwait(false)
            ? page with { Items = page.Items.Select(IpMasker.Mask).ToList() }
            : page;
    }

    public async Task<IReadOnlyList<BanEvent>> GetEventsAsync(int take, CancellationToken ct = default)
    {
        var events = await _store.GetEventsAsync(take, ct).ConfigureAwait(false);
        return await ShouldMaskAsync().ConfigureAwait(false) ? events.Select(IpMasker.Mask).ToList() : events;
    }

    public async Task<IReadOnlyList<AllowEntry>> GetAllowlistAsync(CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        return await _store.GetAllowlistAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Bans an address by hand. Returns an error message, or null on success.</summary>
    public async Task<string?> BanAsync(string address, string? reason, TimeSpan? duration, bool force, CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        if (!IpAddressUtil.TryParseNetwork(address, out var network))
        {
            return "That is not an IP address or CIDR range.";
        }

        if (!IpAddressUtil.IsBannable(network))
        {
            return $"That address cannot be banned (reserved, or a range wider than /{IpAddressUtil.MinIPv4Prefix} IPv4 or /{IpAddressUtil.MinIPv6Prefix} IPv6).";
        }

        await _allowlist.RefreshAsync(_store, ct).ConfigureAwait(false);
        if (_allowlist.Current.Overlaps(network) && !force)
        {
            return "That address is, or contains, an allow-listed or local address. Tick “ban anyway” to override.";
        }

        var now = DateTime.UtcNow;
        await _store.AddAsync(new Ban
        {
            Address = IpAddressUtil.Format(network),
            Reason = string.IsNullOrWhiteSpace(reason) ? "manual ban" : reason.Trim(),
            Source = BanSources.Manual,
            CreatedUtc = now,
            ExpiresUtc = duration is null ? null : now + duration,
            MachineName = _options.MachineName,
            CreatedBy = await UserNameAsync().ConfigureAwait(false),
        }, ct).ConfigureAwait(false);
        return null;
    }

    /// <summary>Lifts a ban. Takes the unmasked address, which only admins ever see.</summary>
    public async Task<int> UnbanAsync(string address, CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        return await _store.RemoveAsync(address, await UserNameAsync().ConfigureAwait(false), ct).ConfigureAwait(false);
    }

    public async Task<string?> AddAllowAsync(string address, string? note, CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        if (!IpAddressUtil.TryNormalize(address, out string normalized))
        {
            return "That is not an IP address or CIDR range.";
        }

        await _store.AddAllowAsync(new AllowEntry { Address = normalized, Note = note, CreatedBy = await UserNameAsync().ConfigureAwait(false) }, ct).ConfigureAwait(false);
        return null;
    }

    public async Task RemoveAllowAsync(string address, CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        await _store.RemoveAllowAsync(address, ct).ConfigureAwait(false);
    }

    public async Task<(IReadOnlyList<BlocklistSourceOptions> Sources, IReadOnlyList<SyncResult> Results)> GetSyncStatusAsync()
    {
        await RequireAdminAsync().ConfigureAwait(false);
        return _sync is null ? ([], []) : (_sync.Sources, _sync.LastResults);
    }

    public async Task<IReadOnlyList<SyncResult>> SyncNowAsync(bool dryRun, CancellationToken ct = default)
    {
        await RequireAdminAsync().ConfigureAwait(false);
        return _sync is null ? [] : await _sync.RunAllAsync(dryRun, ct).ConfigureAwait(false);
    }
}
