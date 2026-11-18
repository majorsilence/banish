using System.Net;
using System.Text.RegularExpressions;

namespace Majorsilence.Banish.Core;

/// <summary>Applies a rule's patterns to a line of text and extracts the offending address.</summary>
public sealed class RuleMatcher
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private readonly Regex[] _patterns;
    private readonly Regex[] _ignore;

    public RuleMatcher(RuleOptions rule)
    {
        Rule = rule;
        _patterns = rule.Patterns.Select(Compile).ToArray();
        _ignore = rule.IgnorePatterns.Select(Compile).ToArray();
    }

    public RuleOptions Rule { get; }

    public bool TryMatch(string line, out IPAddress address)
    {
        address = IPAddress.None;
        try
        {
            if (_ignore.Any(r => r.IsMatch(line)))
            {
                return false;
            }

            foreach (var regex in _patterns)
            {
                var match = regex.Match(line);
                if (match.Success
                    && match.Groups["ip"].Success
                    && IpAddressUtil.TryParseAddress(match.Groups["ip"].Value, out address)
                    && IpAddressUtil.IsBannable(address))
                {
                    return true;
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // A pathological line must not stall detection.
        }

        return false;
    }

    private static Regex Compile(string pattern) =>
        new(pattern, RegexOptions.CultureInvariant | RegexOptions.Compiled, RegexTimeout);
}
