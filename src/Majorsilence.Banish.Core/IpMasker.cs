using System.Net;
using System.Net.Sockets;

namespace Majorsilence.Banish.Core;

/// <summary>Hides the host part of an address for viewers who are not admins.</summary>
public static class IpMasker
{
    /// <summary><c>203.0.113.5</c> becomes <c>203.0.113.x</c>; <c>2001:db8:1:2::9</c> becomes <c>2001:db8:1:x</c>. A CIDR keeps its prefix length.</summary>
    public static string Mask(string address)
    {
        if (string.IsNullOrEmpty(address))
        {
            return address;
        }

        string suffix = "";
        int slash = address.IndexOf('/');
        string host = address;
        if (slash >= 0)
        {
            suffix = address[slash..];
            host = address[..slash];
        }

        if (!IPAddress.TryParse(host, out var ip))
        {
            return "x";
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return $"{b[0]}.{b[1]}.{b[2]}.x{suffix}";
        }

        string[] groups = ip.ToString().Split(':');
        return string.Join(':', groups.Take(3).Where(g => g.Length > 0)) + ":x" + suffix;
    }

    public static Ban Mask(Ban ban) => new()
    {
        Id = ban.Id,
        Address = Mask(ban.Address),
        Reason = ban.Reason,
        Source = ban.Source,
        RuleId = ban.RuleId,
        CreatedUtc = ban.CreatedUtc,
        UpdatedUtc = ban.UpdatedUtc,
        ExpiresUtc = ban.ExpiresUtc,
        RemovedUtc = ban.RemovedUtc,
        RemovedBy = ban.RemovedBy,
        MachineName = ban.MachineName,
        CreatedBy = ban.CreatedBy,
        Hits = ban.Hits,
    };

    public static BanEvent Mask(BanEvent e) => new()
    {
        Id = e.Id,
        BanId = e.BanId,
        Address = Mask(e.Address),
        Kind = e.Kind,
        Actor = e.Actor,
        MachineName = e.MachineName,
        TimestampUtc = e.TimestampUtc,
        Detail = e.Detail,
    };

    public static BanStats Mask(BanStats s) =>
        s with { TopAddresses = s.TopAddresses.Select(a => a with { Key = Mask(a.Key) }).ToList() };
}

/// <summary>Authorization policy names shared by the Web API and the dashboard.</summary>
public static class Policies
{
    /// <summary>An agent or admin API key (or an admin user).</summary>
    public const string Agent = "Agent";

    /// <summary>An admin API key or admin user.</summary>
    public const string Admin = "Admin";

    /// <summary>A signed-in viewer, agent or admin, or anyone when the dashboard is public read-only.</summary>
    public const string Viewer = "Viewer";
}

/// <summary>Authentication scheme names shared by the API host and the dashboard.</summary>
public static class AuthSchemes
{
    public const string Cookie = "Cookies";
    public const string Oidc = "oidc";
    public const string ApiKey = "ApiKey";
    public const string Smart = "Smart";
}
