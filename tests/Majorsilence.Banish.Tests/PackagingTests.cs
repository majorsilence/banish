using Majorsilence.Banish.Cli;

namespace Majorsilence.Banish.Tests;

/// <summary>
/// The files under packaging/ that mirror what <c>banish install</c> generates must not drift from the code.
/// Run with UPDATE_PACKAGING=1 to rewrite them.
/// </summary>
public class PackagingTests
{
    private static string Root()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "Majorsilence.Banish.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        return dir ?? throw new InvalidOperationException("repository root not found");
    }

    private static void Check(string relative, string expected)
    {
        string path = Path.Combine(Root(), relative);
        expected = expected.Replace("\r\n", "\n");
        if (Environment.GetEnvironmentVariable("UPDATE_PACKAGING") == "1")
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, expected);
        }

        Assert.That(File.Exists(path), Is.True, $"{relative} is missing (run the tests with UPDATE_PACKAGING=1)");
        Assert.That(File.ReadAllText(path).Replace("\r\n", "\n"), Is.EqualTo(expected), $"{relative} is out of date (run the tests with UPDATE_PACKAGING=1)");
    }

    [Test]
    public void The_packaged_agent_unit_matches_the_one_the_installer_writes() =>
        Check("packaging/linux/banish-agent.service", ServiceInstaller.BuildSystemdUnit(ServiceKind.Agent, "/usr/bin/banish-agent", "/etc/banish/banish.json"));

    [Test]
    public void The_packaged_api_unit_matches_the_one_the_installer_writes() =>
        Check("packaging/linux/banish-api.service", ServiceInstaller.BuildSystemdUnit(ServiceKind.Api, "/usr/bin/banish-api", "/etc/banish/banish.json"));

    [Test]
    public void The_packaged_default_config_is_the_sample_config() =>
        Check("packaging/linux/banish.json", SampleConfig.Text + "\n");

    [Test]
    public void The_windows_default_config_is_the_sample_config() =>
        Check("packaging/windows/banish.json", SampleConfig.Text + "\n");
}
