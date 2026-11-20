using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Dashboard;

public sealed record GeoBubble(string Code, string Name, int Count, double Lat, double Lon);

public sealed record GeoSummary(
    bool Enabled,
    IReadOnlyList<CountItem> Countries,
    IReadOnlyList<CountItem> Networks,
    IReadOnlyList<GeoBubble> Bubbles,
    int Unlocated)
{
    public static readonly GeoSummary Off = new(false, [], [], [], 0);
}

/// <summary>
/// Counts active bans by country and network using the local GeoIP files. Only totals leave this class, never
/// addresses, so the result is safe to show read-only viewers. The answer is cached briefly because a large
/// blocklist makes the underlying list long.
/// </summary>
public sealed class GeoSummaryService
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);

    private readonly IBanStore _store;
    private readonly IGeoLookup _geo;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private GeoSummary? _cached;
    private DateTimeOffset _cachedAt;

    public GeoSummaryService(IBanStore store, IGeoLookup geo, TimeProvider? time = null)
    {
        _store = store;
        _geo = geo;
        _time = time ?? TimeProvider.System;
    }

    public bool Enabled => _geo.IsEnabled;

    public async Task<GeoSummary> GetAsync(CancellationToken ct = default)
    {
        if (!_geo.IsEnabled)
        {
            return GeoSummary.Off;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = _time.GetUtcNow();
            if (_cached is null || now - _cachedAt > Lifetime)
            {
                _cached = Compute(await _store.GetActiveAsync(ct).ConfigureAwait(false));
                _cachedAt = now;
            }

            return _cached;
        }
        finally
        {
            _gate.Release();
        }
    }

    public GeoSummary Compute(IReadOnlyList<Ban> active)
    {
        var countries = new Dictionary<string, (string Name, int Count)>(StringComparer.OrdinalIgnoreCase);
        var networks = new Dictionary<string, int>(StringComparer.Ordinal);
        int unlocated = 0;
        foreach (var ban in active)
        {
            if (!IpAddressUtil.TryParseNetwork(ban.Address, out var network))
            {
                unlocated++;
                continue;
            }

            // A range is placed by its first address.
            var info = _geo.Lookup(network.BaseAddress);
            if (info?.CountryCode is { Length: 2 } code)
            {
                countries.TryGetValue(code, out var existing);
                countries[code] = (info.CountryName ?? code, existing.Count + 1);
            }
            else
            {
                unlocated++;
            }

            if (info?.Asn is { } asn)
            {
                string key = info.AsnOrganization is { Length: > 0 } org ? $"AS{asn} {org}" : $"AS{asn}";
                networks[key] = networks.GetValueOrDefault(key) + 1;
            }
        }

        var countryItems = countries
            .OrderByDescending(c => c.Value.Count).ThenBy(c => c.Value.Name, StringComparer.Ordinal)
            .Take(10).Select(c => new CountItem($"{c.Value.Name} ({c.Key.ToUpperInvariant()})", c.Value.Count)).ToList();
        var networkItems = networks.OrderByDescending(n => n.Value).ThenBy(n => n.Key, StringComparer.Ordinal)
            .Take(10).Select(n => new CountItem(n.Key, n.Value)).ToList();
        var bubbles = new List<GeoBubble>();
        foreach (var (code, (name, count)) in countries)
        {
            if (CountryCentroids.TryGet(code, out var centre))
            {
                bubbles.Add(new GeoBubble(code.ToUpperInvariant(), name, count, centre.Lat, centre.Lon));
            }
            else
            {
                unlocated += count;
            }
        }

        return new GeoSummary(true, countryItems, networkItems, bubbles.OrderByDescending(b => b.Count).ToList(), unlocated);
    }
}
