using System.Net;
using System.Net.NetworkInformation;

namespace Majorsilence.Banish.Core;

/// <summary>Addresses that must never be banned.</summary>
public sealed class Allowlist
{
    private static readonly string[] PrivateRanges =
    [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "::1", "fc00::/7", "fe80::/10",
    ];

    private readonly IPNetwork[] _networks;

    public Allowlist(IEnumerable<IPNetwork> networks) => _networks = networks.ToArray();

    public int Count => _networks.Length;

    public bool Contains(IPAddress address) => _networks.Any(n => n.Contains(address));

    /// <summary>True when the ban target is, or contains, an allow-listed address.</summary>
    public bool Overlaps(IPNetwork target) => _networks.Any(n => IpAddressUtil.Overlaps(n, target));

    public static Allowlist Create(
        IEnumerable<string>? entries,
        bool includePrivateRanges = true,
        bool includeLocalInterfaces = true)
    {
        var list = new List<IPNetwork>();
        foreach (string entry in (entries ?? []).Concat(includePrivateRanges ? PrivateRanges : []))
        {
            if (IpAddressUtil.TryParseNetwork(entry, out var network))
            {
                list.Add(network);
            }
        }

        // The loopback range is always protected.
        list.Add(new IPNetwork(IPAddress.Loopback, 8));
        list.Add(new IPNetwork(IPAddress.IPv6Loopback, 128));

        if (includeLocalInterfaces)
        {
            foreach (var address in LocalAddresses())
            {
                list.Add(new IPNetwork(address, IpAddressUtil.MaxPrefix(address)));
            }
        }

        return new Allowlist(list);
    }

    /// <summary>Returns a new allow-list with extra entries (for example from the shared store).</summary>
    public Allowlist With(IEnumerable<string> extra)
    {
        var list = _networks.ToList();
        foreach (string entry in extra)
        {
            if (IpAddressUtil.TryParseNetwork(entry, out var network))
            {
                list.Add(network);
            }
        }

        return new Allowlist(list);
    }

    private static IEnumerable<IPAddress> LocalAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(i => i.GetIPProperties().UnicastAddresses)
                .Select(a => a.Address)
                .ToList();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}
