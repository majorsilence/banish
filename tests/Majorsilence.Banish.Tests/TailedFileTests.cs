using Majorsilence.Banish.Core;
using Majorsilence.Banish.Detectors;
using Microsoft.Extensions.Logging.Abstractions;

namespace Majorsilence.Banish.Tests;

public class TailedFileTests
{
    private string _dir = "";

    [SetUp]
    public void SetUp()
    {
        _dir = Path.Combine(Path.GetTempPath(), "banish-tail-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    [TearDown]
    public void TearDown() => Directory.Delete(_dir, true);

    [Test]
    public void OnlyNewCompleteLinesAreReturned()
    {
        string path = Path.Combine(_dir, "a.log");
        File.WriteAllText(path, "old line\n");
        using var tail = new TailedFile(path, fromStart: false);

        Assert.That(tail.ReadNewLines(), Is.Empty, "existing content is skipped");
        File.AppendAllText(path, "one\ntwo\npart");
        Assert.That(tail.ReadNewLines(), Is.EqualTo(new[] { "one", "two" }));
        File.AppendAllText(path, "ial\r\n");
        Assert.That(tail.ReadNewLines(), Is.EqualTo(new[] { "partial" }));
    }

    [Test]
    public void FromStartReadsExistingContent()
    {
        string path = Path.Combine(_dir, "a.log");
        File.WriteAllText(path, "a\nb\n");
        using var tail = new TailedFile(path, fromStart: true);
        Assert.That(tail.ReadNewLines(), Is.EqualTo(new[] { "a", "b" }));
    }

    [Test]
    public void TruncationRestartsFromTheBeginning()
    {
        string path = Path.Combine(_dir, "a.log");
        File.WriteAllText(path, "aaaaaaaaaa\nbbbbbbbbbb\n");
        using var tail = new TailedFile(path, fromStart: true);
        tail.ReadNewLines();

        File.WriteAllText(path, "new\n");
        Assert.That(tail.ReadNewLines(), Is.EqualTo(new[] { "new" }));
    }

    [Test]
    public void MissingFileIsToleratedAndPickedUpLater()
    {
        string path = Path.Combine(_dir, "later.log");
        using var tail = new TailedFile(path, fromStart: true);
        Assert.That(tail.ReadNewLines(), Is.Empty);

        File.WriteAllText(path, "hello\n");
        Assert.That(tail.ReadNewLines(), Is.EqualTo(new[] { "hello" }));
    }

    [Test]
    public async Task DetectorReportsMatchesFromAppendedLines()
    {
        string path = Path.Combine(_dir, "auth.log");
        File.WriteAllText(path, "");
        var rule = new RuleOptions { Name = "t", Paths = [path], Patterns = [@"bad from (?<ip>\S+)"] };
        var detector = new LogFileDetector(rule, NullLogger.Instance, TimeSpan.FromMilliseconds(20));
        var seen = new List<FailureEvent>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var run = detector.RunAsync(f => { lock (seen) { seen.Add(f); } return ValueTask.CompletedTask; }, cts.Token);

        await Task.Delay(100);
        File.AppendAllText(path, "ok\nbad from 203.0.113.5\nbad from 203.0.113.6\n");
        for (int i = 0; i < 200; i++)
        {
            lock (seen)
            {
                if (seen.Count >= 2)
                {
                    break;
                }
            }

            await Task.Delay(25);
        }

        cts.Cancel();
        await run;
        Assert.That(seen.Select(s => s.Address.ToString()), Is.EqualTo(new[] { "203.0.113.5", "203.0.113.6" }));
    }
}
