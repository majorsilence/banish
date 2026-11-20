using System.Net;

namespace Majorsilence.Banish.Core;

/// <summary>What a local GeoIP database knows about an address. Any part may be missing.</summary>
public sealed record GeoInfo(string? CountryCode, string? CountryName, long? Asn, string? AsnOrganization);

/// <summary>
/// Country and network lookup for the dashboard. Display only: nothing in detection, banning or the
/// firewall ever calls it. Lookups read a local file; there are no network calls.
/// </summary>
public interface IGeoLookup
{
    /// <summary>False when GeoIP is switched off or no database could be opened.</summary>
    bool IsEnabled { get; }

    GeoInfo? Lookup(IPAddress address);
}

public sealed class NullGeoLookup : IGeoLookup
{
    public bool IsEnabled => false;

    public GeoInfo? Lookup(IPAddress address) => null;
}
