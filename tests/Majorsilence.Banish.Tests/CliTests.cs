using Majorsilence.Banish.Cli;
using Majorsilence.Banish.Tests.Support;

namespace Majorsilence.Banish.Tests;

public class CliTests
{
    private string _dir = "";
    private string _config = "";

    [SetUp]
    public void SetUp()
    {
        _dir = Path.Combine(Path.GetTempPath(), "banish-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _config = Path.Combine(_dir, "banish.json");
        string db = Path.Combine(_dir, "b.db").Replace("\\", "/");
        File.WriteAllText(_config, $$"""{ "MachineName": "cli-test", "Store": { "Provider": "Sqlite", "ConnectionString": "Data Source={{db}}" }, "Rules": [] }""");
    }

    [TearDown]
    public void TearDown()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, true);
    }

    [TestCase("secret-password", "secret-password")]
    [TestCase("﻿secret-password\r", "secret-password", Description = "Windows PowerShell 5.1 pipes a BOM and CRLF")]
    [TestCase("﻿secret-password", "secret-password")]
    [TestCase(null, "")]
    public void PipedPasswordsLoseShellArtifacts(string? line, string expected) =>
        Assert.That(CliApp.CleanPasswordLine(line), Is.EqualTo(expected));

    private async Task<(int Code, string Out, string Err)> Run(params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        int code = await CliApp.RunAsync(["--config", _config, .. args], o, e, default);
        return (code, o.ToString(), e.ToString());
    }

    [Test]
    public async Task BanListUnbanRoundTrip()
    {
        var ban = await Run("ban", "203.0.113.5", "--reason", "scanner", "--for", "2h");
        Assert.That(ban.Code, Is.EqualTo(0), ban.Err);

        var list = await Run("list");
        Assert.That(list.Out, Does.Contain("203.0.113.5").And.Contain("scanner").And.Contain("manual"));

        var unban = await Run("unban", "203.0.113.5");
        Assert.That(unban.Code, Is.EqualTo(0), unban.Err);
        Assert.That((await Run("list")).Out, Does.Not.Contain("203.0.113.5"));
        Assert.That((await Run("unban", "203.0.113.5")).Code, Is.EqualTo(1));
    }

    [Test]
    public async Task RefusesToBanAllowListedOrPrivateWithoutForce()
    {
        var priv = await Run("ban", "192.168.1.10");
        Assert.That(priv.Code, Is.EqualTo(1));
        Assert.That(priv.Err, Does.Contain("--force"));
        Assert.That((await Run("ban", "192.168.1.10", "--force")).Code, Is.EqualTo(0));
    }

    [Test]
    public async Task RefusesNonsenseTargets()
    {
        Assert.That((await Run("ban", "banana")).Code, Is.EqualTo(2));
        Assert.That((await Run("ban", "0.0.0.0/0")).Code, Is.EqualTo(1));
        Assert.That((await Run("ban", "203.0.113.5", "--for", "soon")).Code, Is.EqualTo(2));
    }

    [Test]
    public async Task AllowListCommands()
    {
        Assert.That((await Run("allow", "add", "203.0.113.0/24", "--note", "office")).Code, Is.EqualTo(0));
        Assert.That((await Run("allow", "list")).Out, Does.Contain("203.0.113.0/24").And.Contain("office"));
        var blocked = await Run("ban", "203.0.113.50");
        Assert.That(blocked.Code, Is.EqualTo(1), "store allow-list is honoured");
        Assert.That((await Run("allow", "remove", "203.0.113.0/24")).Code, Is.EqualTo(0));
    }

    [Test]
    public async Task StatusReportsCounts()
    {
        await Run("ban", "203.0.113.5");
        var status = await Run("status");
        Assert.That(status.Out, Does.Contain("Active bans:  1"));
    }

    [Test]
    public async Task TestRuleShowsMatchesAndThreshold()
    {
        string cfg = Path.Combine(_dir, "rules.json");
        File.WriteAllText(cfg, """{ "Rules": [ { "Name": "demo", "MaxRetry": 2, "Patterns": ["bad from (?<ip>\\S+)"] } ] }""");
        string log = Path.Combine(_dir, "x.log");
        File.WriteAllLines(log, ["bad from 203.0.113.5", "ok", "bad from 203.0.113.5", "bad from 203.0.113.6"]);

        var o = new StringWriter();
        int code = await CliApp.RunAsync(["--config", cfg, "test-rule", "demo", log], o, new StringWriter(), default);

        Assert.That(code, Is.EqualTo(0));
        Assert.That(o.ToString(), Does.Contain("4 lines, 3 matched, 2 addresses"));
        Assert.That(o.ToString(), Does.Contain("203.0.113.5").And.Contain("would reach threshold"));
    }

    [TestCase("30m", 30 * 60)]
    [TestCase("2h", 2 * 3600)]
    [TestCase("7d", 7 * 86400)]
    [TestCase("1w", 7 * 86400)]
    public void DurationParses(string text, int seconds)
    {
        Assert.That(Duration.TryParse(text, out var d), Is.True);
        Assert.That(d!.Value.TotalSeconds, Is.EqualTo(seconds));
    }

    [Test]
    public void DurationPermanentAndInvalid()
    {
        Assert.That(Duration.TryParse("permanent", out var d), Is.True);
        Assert.That(d, Is.Null);
        Assert.That(Duration.TryParse("abc", out _), Is.False);
        Assert.That(Duration.TryParse("-5m", out _), Is.False);
    }
}
