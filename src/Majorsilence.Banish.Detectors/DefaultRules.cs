using Majorsilence.Banish.Core;

namespace Majorsilence.Banish.Detectors;

/// <summary>Rules used when <c>Rules</c> is absent from the configuration.</summary>
public static class DefaultRules
{
    /// <summary>
    /// Patterns for the messages OpenSSH's sshd writes on failed authentication. Each failed attempt
    /// produces exactly one matching line, so MaxRetry counts attempts.
    /// </summary>
    public static readonly string[] SshdPatterns =
    [
        @"sshd(?:\[\d+\])?: Failed \S+ for (?:invalid user )?.*? from (?<ip>\S+) port \d+",
        @"sshd(?:\[\d+\])?: Connection closed by (?:invalid|authenticating) user \S+ (?<ip>\S+) port \d+ \[preauth\]",
        @"sshd(?:\[\d+\])?: Did not receive identification string from (?<ip>\S+)",
        @"sshd(?:\[\d+\])?: error: maximum authentication attempts exceeded for .*? from (?<ip>\S+) port \d+",
    ];

    public const string WindowsFailedLogonPattern = @"<Data Name='IpAddress'>(?<ip>[^<]+)</Data>";

    public static List<RuleOptions> ForCurrentOs()
    {
        if (OperatingSystem.IsWindows())
        {
            return
            [
                new RuleOptions
                {
                    Name = "windows-logon",
                    Detector = "WindowsEventLog",
                    EventLog = "Security",
                    EventQuery = "*[System[(EventID=4625)]]",
                    Patterns = [WindowsFailedLogonPattern],
                    MaxRetry = 5,
                },
            ];
        }

        if (OperatingSystem.IsMacOS())
        {
            return
            [
                new RuleOptions
                {
                    Name = "sshd",
                    Detector = "Command",
                    Command = ["/usr/bin/log", "stream", "--style", "syslog", "--predicate", "process == \"sshd\""],
                    Patterns = [.. SshdPatterns],
                },
            ];
        }

        string? authLog = new[] { "/var/log/auth.log", "/var/log/secure" }.FirstOrDefault(File.Exists);
        if (authLog is not null)
        {
            return [new RuleOptions { Name = "sshd", Detector = "LogFile", Paths = [authLog], Patterns = [.. SshdPatterns] }];
        }

        return
        [
            new RuleOptions
            {
                Name = "sshd",
                Detector = "Command",
                Command = ["journalctl", "-f", "-n", "0", "-o", "short", "-t", "sshd"],
                Patterns = [.. SshdPatterns],
            },
        ];
    }
}
