using System.Net;
using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Tests;

public class IpAddressUtilTests
{
    [TestCase("1.2.3.4", "1.2.3.4")]
    [TestCase(" 1.2.3.4 ", "1.2.3.4")]
    [TestCase("::ffff:1.2.3.4", "1.2.3.4")]
    [TestCase("[2001:db8::1]", "2001:db8::1")]
    [TestCase("fe80::1%eth0", "fe80::1")]
    [TestCase("10.1.2.3/8", "10.0.0.0/8")]
    [TestCase("203.0.113.9/32", "203.0.113.9")]
    [TestCase("2001:db8::/32", "2001:db8::/32")]
    public void Normalizes(string input, string expected)
    {
        Assert.That(IpAddressUtil.TryNormalize(input, out string result), Is.True);
        Assert.That(result, Is.EqualTo(expected));
    }

    [TestCase("")]
    [TestCase("not an ip")]
    [TestCase("1.2.3.4/33")]
    [TestCase("1.2.3.4/-1")]
    [TestCase("1.2.3")]
    [TestCase("16909060")]
    [TestCase("1.2.3.256")]
    [TestCase("01234.1.1.1")]
    [TestCase("1.2.3.4 5.6.7.8")]
    public void RejectsGarbage(string input) =>
        Assert.That(IpAddressUtil.TryNormalize(input, out _), Is.False);

    [Test]
    public void RefusesDangerousTargets()
    {
        Assert.That(IpAddressUtil.IsBannable(IPAddress.Any), Is.False);
        Assert.That(IpAddressUtil.IsBannable(IPAddress.Parse("224.0.0.1")), Is.False);
        Assert.That(IpAddressUtil.IsBannable(IPAddress.Parse("ff02::1")), Is.False);
        IpAddressUtil.TryParseNetwork("0.0.0.0/0", out var all);
        Assert.That(IpAddressUtil.IsBannable(all), Is.False);
        IpAddressUtil.TryParseNetwork("203.0.113.0/24", out var ok);
        Assert.That(IpAddressUtil.IsBannable(ok), Is.True);
    }
}

public class AllowlistTests
{
    [Test]
    public void PrivateAndLoopbackAreProtectedByDefault()
    {
        var allow = Allowlist.Create([], includePrivateRanges: true, includeLocalInterfaces: false);
        Assert.That(allow.Contains(IPAddress.Parse("192.168.1.5")), Is.True);
        Assert.That(allow.Contains(IPAddress.Parse("127.0.0.1")), Is.True);
        Assert.That(allow.Contains(IPAddress.Parse("::1")), Is.True);
        Assert.That(allow.Contains(IPAddress.Parse("8.8.8.8")), Is.False);
    }

    [Test]
    public void PrivateRangesCanBeDisabledButLoopbackStays()
    {
        var allow = Allowlist.Create([], includePrivateRanges: false, includeLocalInterfaces: false);
        Assert.That(allow.Contains(IPAddress.Parse("192.168.1.5")), Is.False);
        Assert.That(allow.Contains(IPAddress.Loopback), Is.True);
    }

    [Test]
    public void CidrBanOverlappingAnAllowedAddressIsDetected()
    {
        var allow = Allowlist.Create(["203.0.113.7"], includePrivateRanges: false, includeLocalInterfaces: false);
        IpAddressUtil.TryParseNetwork("203.0.113.0/24", out var range);
        IpAddressUtil.TryParseNetwork("198.51.100.0/24", out var other);
        Assert.That(allow.Overlaps(range), Is.True);
        Assert.That(allow.Overlaps(other), Is.False);
    }
}
