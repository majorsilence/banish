using System.Net;
using MaxMind.GeoIP2;
using Majorsilence.Banish.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.GeoIp;

/// <summary>Reads MaxMind GeoLite2 / GeoIP2 (or compatible, such as DB-IP) .mmdb files you supply.</summary>
public sealed class MaxMindGeoLookup : IGeoLookup, IDisposable
{
    private readonly DatabaseReader? _country;
    private readonly DatabaseReader? _asn;

    public MaxMindGeoLookup(string? countryPath, string? asnPath)
    {
        _country = string.IsNullOrWhiteSpace(countryPath) ? null : new DatabaseReader(countryPath);
        _asn = string.IsNullOrWhiteSpace(asnPath) ? null : new DatabaseReader(asnPath);
    }

    public bool IsEnabled => _country is not null || _asn is not null;

    public GeoInfo? Lookup(IPAddress address)
    {
        string? code = null, name = null, org = null;
        long? asn = null;
        if (_country is not null && _country.TryCountry(address, out var country) && country is not null)
        {
            code = country.Country.IsoCode;
            name = country.Country.Name;
        }

        if (_asn is not null && _asn.TryAsn(address, out var network) && network is not null)
        {
            asn = network.AutonomousSystemNumber;
            org = network.AutonomousSystemOrganization;
        }

        return code is null && asn is null ? null : new GeoInfo(code, name, asn, org);
    }

    public void Dispose()
    {
        _country?.Dispose();
        _asn?.Dispose();
    }
}

public static class GeoIpRegistration
{
    /// <summary>
    /// Registers the lookup. With <c>GeoIp:Enabled</c> false (the default) nothing is opened. If it is enabled but a
    /// file cannot be read, a warning is logged and the dashboard simply shows no geographic data.
    /// </summary>
    public static IServiceCollection AddBanishGeoIp(this IServiceCollection services, GeoIpOptions options)
    {
        services.AddSingleton<IGeoLookup>(sp =>
        {
            if (!options.Enabled)
            {
                return new NullGeoLookup();
            }

            var log = sp.GetRequiredService<ILoggerFactory>().CreateLogger("GeoIp");
            try
            {
                var lookup = new MaxMindGeoLookup(Existing(options.CountryDatabasePath, log), Existing(options.AsnDatabasePath, log));
                if (!lookup.IsEnabled)
                {
                    log.LogWarning("GeoIp:Enabled is true but no database file was found; set GeoIp:CountryDatabasePath");
                }

                return lookup;
            }
            catch (Exception ex) when (ex is IOException or MaxMind.Db.InvalidDatabaseException or UnauthorizedAccessException)
            {
                log.LogWarning(ex, "Could not open the GeoIP database; the dashboard will show no geographic data");
                return new NullGeoLookup();
            }
        });
        return services;
    }

    private static string? Existing(string? path, ILogger log)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        if (File.Exists(path))
        {
            return path;
        }

        log.LogWarning("GeoIP database {Path} does not exist", path);
        return null;
    }
}
