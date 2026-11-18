using System.Globalization;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Dashboard;

public static class Format
{
    /// <summary>1,284 / 12.9K / 4.2M.</summary>
    public static string Compact(long n) => n switch
    {
        >= 1_000_000 => (n / 1_000_000d).ToString("0.#", CultureInfo.InvariantCulture) + "M",
        >= 10_000 => (n / 1_000d).ToString("0.#", CultureInfo.InvariantCulture) + "K",
        _ => n.ToString("N0", CultureInfo.InvariantCulture),
    };

    public static string Inv(double d) => d.ToString("0.##", CultureInfo.InvariantCulture);

    public static string When(DateTime utc) => utc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";

    public static string Expiry(Ban ban, DateTime nowUtc)
    {
        if (ban.RemovedUtc is not null)
        {
            return "lifted " + When(ban.RemovedUtc.Value);
        }

        if (ban.ExpiresUtc is null)
        {
            return "permanent";
        }

        return ban.ExpiresUtc <= nowUtc ? "expired" : "until " + When(ban.ExpiresUtc.Value);
    }

    public static string Ago(DateTime utc, DateTime nowUtc)
    {
        var span = nowUtc - utc;
        if (span < TimeSpan.Zero)
        {
            span = TimeSpan.Zero;
        }

        return span.TotalSeconds < 90 ? $"{(int)span.TotalSeconds}s ago"
            : span.TotalMinutes < 90 ? $"{(int)span.TotalMinutes}m ago"
            : span.TotalHours < 48 ? $"{(int)span.TotalHours}h ago"
            : $"{(int)span.TotalDays}d ago";
    }
}
