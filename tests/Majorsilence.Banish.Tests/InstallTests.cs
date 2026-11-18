using Majorsilence.Banish.Cli;
using Majorsilence.Banish.Firewall;
using Majorsilence.Banish.Hosting;

namespace Majorsilence.Banish.Tests;

public class InstallTests
{
    private sealed class RecordingRunner : IProcessRunner
    {
        public List<string> Calls { get; } = [];
        public Func<string, IReadOnlyList<string>, ProcessResult> Respond { get; set; } = (_, _) => new ProcessResult(0, "", "");

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? stdin, CancellationToken cancellationToken)
        {
            Calls.Add(fileName + " " + string.Join(' ', arguments));
            return Task.FromResult(Respond(fileName, arguments));
        }
    }

    [Test]
    public void AgentUnitRunsAsRootWithAStateDirectoryAndRestarts()
    {
        string unit = ServiceInstaller.BuildSystemdUnit(ServiceKind.Agent, "/opt/banish/banish-agent", "/etc/banish/banish.json");

        Assert.That(unit, Does.Contain("ExecStart=/opt/banish/banish-agent --config /etc/banish/banish.json"));
        Assert.That(unit, Does.Contain("Type=notify").And.Contain("Restart=on-failure").And.Contain("WantedBy=multi-user.target"));
        Assert.That(unit, Does.Contain("StateDirectory=banish").And.Contain("NoNewPrivileges=true"));
        Assert.That(unit, Does.Not.Contain("DynamicUser"), "the agent edits the firewall, so it is not a dynamic user");
    }

    [Test]
    public void ApiUnitDropsAllPrivileges()
    {
        string unit = ServiceInstaller.BuildSystemdUnit(ServiceKind.Api, "/opt/banish/banish-api", "/etc/banish/banish.json");

        Assert.That(unit, Does.Contain("DynamicUser=yes").And.Contain("CapabilityBoundingSet=").And.Contain("ProtectSystem=strict"));
        Assert.That(unit, Does.Contain("StateDirectory=banish").And.Contain("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"));
    }

    [Test]
    public void PathsWithSpacesAreQuoted()
    {
        string unit = ServiceInstaller.BuildSystemdUnit(ServiceKind.Agent, "/opt/my banish/banish-agent", "/etc/my banish/banish.json");
        Assert.That(unit, Does.Contain("ExecStart=\"/opt/my banish/banish-agent\" --config \"/etc/my banish/banish.json\""));
    }

    [Test]
    public void LaunchdPlistIsWellFormedAndEscaped()
    {
        string plist = ServiceInstaller.BuildLaunchdPlist(ServiceKind.Agent, "/usr/local/banish/banish-agent", "/Library/Application Support/Banish/a&b.json");

        var doc = System.Xml.Linq.XDocument.Parse(plist);
        Assert.That(plist, Does.Contain("<key>Label</key><string>com.majorsilence.banish-agent</string>"));
        Assert.That(plist, Does.Contain("a&amp;b.json"));
        Assert.That(doc.Descendants("true").Count(), Is.EqualTo(2), "RunAtLoad and KeepAlive");
    }

    [Test]
    public void WindowsServiceArguments()
    {
        string[] args = ServiceInstaller.BuildWindowsCreateArguments(ServiceKind.Agent, @"C:\Program Files\Banish\banish-agent.exe", @"C:\ProgramData\Banish\banish.json");

        Assert.That(args[..2], Is.EqualTo(new[] { "create", "Banish" }));
        Assert.That(args[3], Is.EqualTo("\"C:\\Program Files\\Banish\\banish-agent.exe\" --config \"C:\\ProgramData\\Banish\\banish.json\""));
        Assert.That(ServiceInstaller.ServiceName(ServiceKind.Api), Is.EqualTo("BanishApi"), "matches the name the API host registers with the service manager");
    }

    [Test]
    [Platform(Include = "Linux")]
    public async Task InstallWritesTheUnitAndEnablesIt()
    {
        string dir = Path.Combine(Path.GetTempPath(), "banish-inst-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string exe = Path.Combine(dir, "banish-agent");
            File.WriteAllText(exe, "#!/bin/sh");
            var runner = new RecordingRunner();
            var installer = new ServiceInstaller(runner, new ServicePaths(dir, dir));

            var result = await installer.InstallAsync(ServiceKind.Agent, exe, "/etc/banish/banish.json", start: true, default);

            Assert.That(result.Success, Is.True, result.Message);
            Assert.That(File.ReadAllText(Path.Combine(dir, "banish-agent.service")), Does.Contain(exe));
            Assert.That(runner.Calls, Is.EqualTo(new[] { "systemctl daemon-reload", "systemctl enable --now banish-agent" }));

            var removed = await installer.UninstallAsync(ServiceKind.Agent, default);
            Assert.That(removed.Success, Is.True);
            Assert.That(File.Exists(Path.Combine(dir, "banish-agent.service")), Is.False);
            Assert.That(runner.Calls, Does.Contain("systemctl disable --now banish-agent"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    [Platform(Include = "Linux")]
    public async Task InstallReportsMissingExecutableAndSystemctlFailures()
    {
        var installer = new ServiceInstaller(new RecordingRunner(), new ServicePaths(Path.GetTempPath(), Path.GetTempPath()));
        var missing = await installer.InstallAsync(ServiceKind.Agent, "/nonexistent/banish-agent", "/x", true, default);
        Assert.That(missing.Success, Is.False);
        Assert.That(missing.Message, Does.Contain("Cannot find"));

        string dir = Path.Combine(Path.GetTempPath(), "banish-inst-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string exe = Path.Combine(dir, "banish-agent");
            File.WriteAllText(exe, "x");
            var failing = new RecordingRunner { Respond = (_, _) => new ProcessResult(1, "", "Failed to connect to bus") };
            var result = await new ServiceInstaller(failing, new ServicePaths(dir, dir)).InstallAsync(ServiceKind.Agent, exe, "/x", true, default);
            Assert.That(result.Success, Is.False);
            Assert.That(result.Message, Does.Contain("Failed to connect to bus"));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Test]
    public async Task ConfigInitWritesASampleThatLoadsAsDefaults()
    {
        string dir = Path.Combine(Path.GetTempPath(), "banish-init-" + Guid.NewGuid().ToString("N"));
        try
        {
            string path = Path.Combine(dir, "sub", "banish.json");
            var o1 = new StringWriter();
            Assert.That(await CliApp.RunAsync(["--config", path, "config", "init"], o1, new StringWriter(), default), Is.EqualTo(0));
            Assert.That(File.Exists(path), Is.True);

            var again = new StringWriter();
            Assert.That(await CliApp.RunAsync(["--config", path, "config", "init"], again, new StringWriter(), default), Is.EqualTo(1));
            Assert.That(again.ToString(), Does.Contain("already exists"));
            Assert.That(await CliApp.RunAsync(["--config", path, "config", "init", "--force"], new StringWriter(), new StringWriter(), default), Is.EqualTo(0));

            var options = BanishConfig.Load(path);
            Assert.That(options.Store.Provider, Is.EqualTo("Sqlite"));
            Assert.That(options.Firewall.Provider, Is.EqualTo("Auto"));
            Assert.That(options.Reconcile.IntervalSeconds, Is.EqualTo(15));
            Assert.That(options.Dashboard.MaskIps, Is.True);
            Assert.That(options.Rules, Is.Not.Empty, "no Rules in the sample, so the OS defaults apply");
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, true);
            }
        }
    }
}
