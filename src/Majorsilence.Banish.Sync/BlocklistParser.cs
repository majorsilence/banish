using System.Text.Json;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Sync;

public sealed record ParseResult(IReadOnlyList<string> Addresses, int Invalid, bool Truncated);

/// <summary>Turns the text of a downloaded blocklist into normalized, bannable addresses.</summary>
public static class BlocklistParser
{
    private static readonly string[] ObjectKeys = ["cidr", "ip", "address", "ip_address", "ipv4", "ipv6"];

    public static ParseResult Parse(string text, string format, int maxEntries)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var addresses = new List<string>();
        int invalid = 0;
        bool truncated = false;

        void Take(string? candidate)
        {
            if (truncated || string.IsNullOrWhiteSpace(candidate))
            {
                return;
            }

            if (!IpAddressUtil.TryParseNetwork(candidate, out var network) || !IpAddressUtil.IsBannable(network))
            {
                invalid++;
                return;
            }

            if (addresses.Count >= maxEntries)
            {
                truncated = true;
                return;
            }

            string normalized = IpAddressUtil.Format(network);
            if (seen.Add(normalized))
            {
                addresses.Add(normalized);
            }
        }

        switch (format.ToLowerInvariant())
        {
            case "plain":
                foreach (string line in Lines(text))
                {
                    Take(FirstToken(line));
                }

                break;
            case "csv":
                bool header = true;
                foreach (string line in Lines(text))
                {
                    string first = line.Split(',')[0].Trim().Trim('"');
                    // A leading non-address row is a header, not an error.
                    if (header && !IpAddressUtil.TryParseNetwork(first, out _))
                    {
                        header = false;
                        continue;
                    }

                    header = false;
                    Take(FirstToken(first));
                }

                break;
            case "json":
                foreach (string value in JsonValues(text))
                {
                    Take(value);
                }

                break;
            default:
                throw new ArgumentException($"Unknown blocklist format '{format}'. Use plain, csv or json.");
        }

        return new ParseResult(addresses, invalid, truncated);
    }

    private static IEnumerable<string> Lines(string text)
    {
        using var reader = new StringReader(text);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            line = line.Trim();
            if (line.Length > 0 && line[0] is not ('#' or ';' or '/'))
            {
                yield return line;
            }
        }
    }

    // "1.10.16.0/20 ; SBL256894" and "1.2.3.4 # note" both mean the first token.
    private static string FirstToken(string line)
    {
        int end = line.IndexOfAny([' ', '\t', ';', '#', ',']);
        return end < 0 ? line : line[..end];
    }

    private static IEnumerable<string> JsonValues(string text)
    {
        text = text.Trim();
        if (text.Length == 0)
        {
            yield break;
        }

        if (text[0] == '[')
        {
            using var doc = JsonDocument.Parse(text);
            foreach (var element in doc.RootElement.EnumerateArray())
            {
                if (Extract(element) is { } value)
                {
                    yield return value;
                }
            }

            yield break;
        }

        // Newline-delimited JSON, one value per line.
        foreach (string line in Lines(text))
        {
            string? value = null;
            try
            {
                using var doc = JsonDocument.Parse(line);
                value = Extract(doc.RootElement);
            }
            catch (JsonException)
            {
            }

            yield return value ?? line;
        }
    }

    private static string? Extract(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            return element.GetString();
        }

        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (string key in ObjectKeys)
            {
                if (element.TryGetProperty(key, out var prop) && prop.ValueKind == JsonValueKind.String)
                {
                    return prop.GetString();
                }
            }
        }

        return null;
    }
}
