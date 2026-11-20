using System.Net;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Dashboard;
using Majorsilence.Banish.GeoIp;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Majorsilence.Banish.Tests;

public class GeoIpTests
{
    private sealed class FakeGeo : IGeoLookup
    {
        public bool IsEnabled => true;

        public GeoInfo? Lookup(IPAddress address) => address.ToString() switch
        {
            "203.0.113.1" or "203.0.113.2" => new GeoInfo("AU", "Australia", 64500, "Example Net"),
            "198.51.100.1" => new GeoInfo("DE", "Germany", null, null),
            "192.0.2.1" => new GeoInfo("ZZ", "Nowhere", null, null), // a code we have no centre for
            _ => null,
        };
    }

    private static Ban B(string address) => new() { Address = address, Source = BanSources.Local, CreatedUtc = DateTime.UtcNow };

    [Test]
    public void Active_bans_are_counted_by_country_and_network_and_unplaceable_ones_are_reported()
    {
        var service = new GeoSummaryService(null!, new FakeGeo());
        var summary = service.Compute([B("203.0.113.1"), B("203.0.113.2"), B("198.51.100.1"), B("192.0.2.1"), B("100.64.1.1"), B("203.0.113.0/24")]);

        Assert.That(summary.Countries[0], Is.EqualTo(new CountItem("Australia (AU)", 2)));
        Assert.That(summary.Networks.Single(), Is.EqualTo(new CountItem("AS64500 Example Net", 2)));
        Assert.That(summary.Bubbles.Select(b => b.Code), Is.EquivalentTo(new[] { "AU", "DE" }));
        Assert.That(summary.Unlocated, Is.EqualTo(3), "ZZ has no centre, 100.64.1.1 and 203.0.113.0/24 are not in the database");
    }

    [Test]
    public async Task Nothing_is_looked_up_when_GeoIp_is_off()
    {
        var service = new GeoSummaryService(null!, new NullGeoLookup());
        Assert.That(service.Enabled, Is.False);
        Assert.That(await service.GetAsync(), Is.SameAs(GeoSummary.Off));
    }

    [Test]
    public void Disabled_or_missing_database_files_never_stop_the_host()
    {
        var logs = LoggerFactory.Create(b => { });
        foreach (var options in new[]
        {
            new GeoIpOptions { Enabled = false, CountryDatabasePath = "/does/not/exist.mmdb" },
            new GeoIpOptions { Enabled = true, CountryDatabasePath = "/does/not/exist.mmdb" },
            new GeoIpOptions { Enabled = true },
        })
        {
            using var provider = new ServiceCollection().AddSingleton(logs).AddBanishGeoIp(options).BuildServiceProvider();
            Assert.That(provider.GetRequiredService<IGeoLookup>().IsEnabled, Is.False);
        }
    }

    [Test]
    public void A_file_that_is_not_a_database_is_reported_and_ignored()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "not a maxmind database");
            using var provider = new ServiceCollection().AddSingleton(LoggerFactory.Create(b => { }))
                .AddBanishGeoIp(new GeoIpOptions { Enabled = true, CountryDatabasePath = path }).BuildServiceProvider();
            Assert.That(provider.GetRequiredService<IGeoLookup>().IsEnabled, Is.False);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Test]
    public void Country_centres_are_valid_coordinates()
    {
        foreach (string code in new[] { "US", "AU", "DE", "BR", "CN", "NZ", "ZA", "RU", "JP", "GB" })
        {
            Assert.That(CountryCentroids.TryGet(code, out var c), Is.True, code);
            Assert.That(c.Lat, Is.InRange(-90, 90));
            Assert.That(c.Lon, Is.InRange(-180, 180));
        }

        Assert.That(CountryCentroids.TryGet("us", out _), Is.True, "case-insensitive");
        Assert.That(CountryCentroids.TryGet("ZZ", out _), Is.False);
        Assert.That(CountryCentroids.TryGet(null, out _), Is.False);
    }
}
