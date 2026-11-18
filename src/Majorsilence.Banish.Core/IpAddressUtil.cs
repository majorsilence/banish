using System.Net;
using System.Net.Sockets;

namespace Majorsilence.Banish.Core;

/// <summary>Parsing and normalization of IP addresses and CIDR ranges.</summary>
public static class IpAddressUtil
{
    /// <summary>Smallest IPv4 prefix length accepted for a ban, so a typo cannot block the internet.</summary>
    public const int MinIPv4Prefix = 8;

    /// <summary>Smallest IPv6 prefix length accepted for a ban.</summary>
    public const int MinIPv6Prefix = 16;

    /// <summary>Parses an address as found in logs: strips brackets and zone ids, unmaps IPv4-in-IPv6.</summary>
    public static bool TryParseAddress(string? text, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        text = text.Trim().Trim('[', ']');
        int zone = text.IndexOf('%');
        if (zone >= 0)
        {
            text = text[..zone];
        }

        // IPAddress.TryParse also accepts legacy forms ("1.2.3", "16909060") that must never be
        // mistaken for an address scraped from a log line, so IPv4 is checked strictly.
        if (!text.Contains(':') && !StrictIPv4(text))
        {
            return false;
        }

        if (!IPAddress.TryParse(text, out var parsed) || text.Contains(' '))
        {
            return false;
        }

        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    /// <summary>
    /// Normalizes a single address or a CIDR range to its canonical text form. A CIDR covering one
    /// address collapses to the plain address; host bits are cleared.
    /// </summary>
    public static bool TryNormalize(string? text, out string normalized)
    {
        normalized = "";
        if (!TryParseNetwork(text, out var network))
        {
            return false;
        }

        normalized = Format(network);
        return true;
    }

    public static bool TryParseNetwork(string? text, out IPNetwork network)
    {
        network = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        text = text.Trim();
        int slash = text.IndexOf('/');
        if (slash < 0)
        {
            if (!TryParseAddress(text, out var single))
            {
                return false;
            }

            network = new IPNetwork(single, MaxPrefix(single));
            return true;
        }

        if (!TryParseAddress(text[..slash], out var baseAddress)
            || !int.TryParse(text[(slash + 1)..], out int prefix)
            || prefix < 0
            || prefix > MaxPrefix(baseAddress))
        {
            return false;
        }

        network = new IPNetwork(Mask(baseAddress, prefix), prefix);
        return true;
    }

    /// <summary>True when the address may be banned: not unspecified, multicast or broadcast.</summary>
    public static bool IsBannable(IPAddress address)
    {
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.None))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return address.GetAddressBytes()[0] < 224;
        }

        return !address.IsIPv6Multicast;
    }

    /// <summary>True when the ban target is acceptable: bannable address and a not-too-broad prefix.</summary>
    public static bool IsBannable(IPNetwork network)
    {
        int min = network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? MinIPv4Prefix : MinIPv6Prefix;
        return network.PrefixLength >= min && IsBannable(network.BaseAddress);
    }

    public static string Format(IPNetwork network) =>
        network.PrefixLength == MaxPrefix(network.BaseAddress)
            ? network.BaseAddress.ToString()
            : network.BaseAddress + "/" + network.PrefixLength;

    public static bool Overlaps(IPNetwork a, IPNetwork b) =>
        a.Contains(b.BaseAddress) || b.Contains(a.BaseAddress);

    public static int MaxPrefix(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

    private static bool StrictIPv4(string text)
    {
        string[] parts = text.Split('.');
        return parts.Length == 4
            && parts.All(p => p.Length is >= 1 and <= 3 && p.All(char.IsAsciiDigit) && int.Parse(p, System.Globalization.CultureInfo.InvariantCulture) <= 255);
    }

    private static IPAddress Mask(IPAddress address, int prefix)
    {
        var bytes = address.GetAddressBytes();
        for (int bit = prefix; bit < bytes.Length * 8; bit++)
        {
            bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        }

        return new IPAddress(bytes);
    }
}
