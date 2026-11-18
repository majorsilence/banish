using System.Globalization;

namespace Majorsilence.Banish.Cli;

public static class Duration
{
    /// <summary>Parses 30s, 10m, 2h, 7d, w (weeks), or "permanent"/"forever" (returned as null).</summary>
    public static bool TryParse(string text, out TimeSpan? duration)
    {
        duration = null;
        text = text.Trim().ToLowerInvariant();
        if (text is "permanent" or "forever" or "0")
        {
            return true;
        }

        if (text.Length < 2 || !double.TryParse(text[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out double value) || value <= 0)
        {
            return false;
        }

        duration = text[^1] switch
        {
            's' => TimeSpan.FromSeconds(value),
            'm' => TimeSpan.FromMinutes(value),
            'h' => TimeSpan.FromHours(value),
            'd' => TimeSpan.FromDays(value),
            'w' => TimeSpan.FromDays(7 * value),
            _ => null,
        };
        return duration is not null;
    }
}
