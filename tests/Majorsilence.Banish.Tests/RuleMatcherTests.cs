using Majorsilence.Banish.Core;
using Majorsilence.Banish.Detectors;

namespace Majorsilence.Banish.Tests;

public class RuleMatcherTests
{
    private static RuleMatcher Sshd() =>
        new(new RuleOptions { Name = "sshd", Patterns = [.. DefaultRules.SshdPatterns] });

    [TestCase("Nov 17 10:00:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 52000 ssh2", "203.0.113.5")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: Failed password for invalid user admin from 203.0.113.6 port 52000 ssh2", "203.0.113.6")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: Failed publickey for bob from 2001:db8::9 port 5000 ssh2", "2001:db8::9")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: Connection closed by authenticating user root 203.0.113.7 port 4000 [preauth]", "203.0.113.7")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: Did not receive identification string from 203.0.113.8", "203.0.113.8")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: error: maximum authentication attempts exceeded for root from 203.0.113.9 port 22 ssh2 [preauth]", "203.0.113.9")]
    public void SshdFailuresAreMatched(string line, string expected)
    {
        Assert.That(Sshd().TryMatch(line, out var ip), Is.True);
        Assert.That(ip.ToString(), Is.EqualTo(expected));
    }

    [TestCase("Nov 17 10:00:01 host sshd[1234]: Accepted password for root from 203.0.113.5 port 52000 ssh2")]
    [TestCase("Nov 17 10:00:01 host sshd[1234]: Server listening on 0.0.0.0 port 22.")]
    [TestCase("Nov 17 10:00:01 host cron[1]: Failed password for x from 203.0.113.5 port 1")]
    public void OtherLinesAreIgnored(string line) =>
        Assert.That(Sshd().TryMatch(line, out _), Is.False);

    [Test]
    public void IgnorePatternsWin()
    {
        var matcher = new RuleMatcher(new RuleOptions
        {
            Name = "x",
            Patterns = [@"fail from (?<ip>\S+)"],
            IgnorePatterns = ["monitoring"],
        });
        Assert.That(matcher.TryMatch("fail from 203.0.113.5", out _), Is.True);
        Assert.That(matcher.TryMatch("monitoring fail from 203.0.113.5", out _), Is.False);
    }

    [Test]
    public void NonIpCaptureAndUnspecifiedAddressesAreRejected()
    {
        var matcher = new RuleMatcher(new RuleOptions { Name = "x", Patterns = [@"from (?<ip>\S+)"] });
        Assert.That(matcher.TryMatch("from localhost", out _), Is.False);
        Assert.That(matcher.TryMatch("from -", out _), Is.False);
        Assert.That(matcher.TryMatch("from 0.0.0.0", out _), Is.False);
    }

    [Test]
    public void WindowsLogonEventXmlIsMatched()
    {
        var matcher = new RuleMatcher(new RuleOptions { Name = "w", Patterns = [DefaultRules.WindowsFailedLogonPattern] });
        Assert.That(matcher.TryMatch("<Event><EventData><Data Name='IpAddress'>198.51.100.4</Data></EventData></Event>", out var ip), Is.True);
        Assert.That(ip.ToString(), Is.EqualTo("198.51.100.4"));
        Assert.That(matcher.TryMatch("<Data Name='IpAddress'>-</Data>", out _), Is.False);
    }
}
