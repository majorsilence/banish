using System.Runtime.Versioning;
using System.Security.Principal;
using Majorsilence.Banish.Core;
using Majorsilence.Banish.Detectors;
using Microsoft.Extensions.Logging.Abstractions;

namespace Majorsilence.Banish.Tests;

[Platform("Win")]
[SupportedOSPlatform("windows")]
public class WindowsEventLogDetectorTests
{
    [Test]
    public void DefaultRuleTargetsFailedLogonsInTheSecurityLog()
    {
        var rule = DefaultRules.ForCurrentOs().Single();

        Assert.That(rule.Detector, Is.EqualTo("WindowsEventLog"));
        Assert.That(rule.EventLog, Is.EqualTo("Security"));
        Assert.That(rule.EventQuery, Does.Contain("4625"));
    }

    [Test]
    public async Task ReadingTheSecurityLogWithoutPermissionIsReportedNotSilent()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Assert.Ignore("Only meaningful when the test process cannot read the Security log.");
        }

        var rule = DefaultRules.ForCurrentOs().Single();
        var detector = new WindowsEventLogDetector(rule, NullLogger.Instance);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            detector.RunAsync(_ => ValueTask.CompletedTask, cts.Token));

        Assert.That(ex!.Message, Does.Contain("Event Log Readers"));
    }
}
