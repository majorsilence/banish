# Banish

Banish is a cross-platform (Windows, Linux, macOS) intrusion-prevention agent for .NET, in the
spirit of fail2ban and IPBan. It watches logs and event sources for failed logins and abusive
behaviour, blocks the offending IP addresses in the host firewall, and records every ban in a
**central, shareable ban store**.

- **Per-machine by default**: a local SQLite database, zero configuration.
- **Shared when you want it**: point many agents at one PostgreSQL / SQL Server / MySQL database
  (any EF Core provider), or at the Banish Web API. A ban made on one machine is applied by all.
- **Dashboard**: a read-only statistics view and an admin view where bans can be added or lifted.
- **Blocklist sync**: periodically import public IP blocklists.

See [PLAN.md](PLAN.md) for the design, [CHANGELOG.md](CHANGELOG.md) for progress, and
[BACKLOG.md](BACKLOG.md) for accepted-but-unscheduled work.

## Quick start (Linux)

```sh
dotnet publish src/Majorsilence.Banish.Agent -c Release -o /opt/banish
dotnet publish src/Majorsilence.Banish.Cli   -c Release -o /opt/banish
sudo /opt/banish/banish-agent          # needs root to edit the firewall
banish status
banish ban 203.0.113.5 --for 2h --reason "port scan"
banish unban 203.0.113.5
banish test-rule sshd /var/log/auth.log
```

Configuration lives in `/etc/banish/banish.json` (Linux), `/Library/Application Support/Banish/banish.json`
(macOS) or `%ProgramData%\Banish\banish.json` (Windows); override with `--config` or `BANISH_CONFIG`.
Any setting can also be set with `BANISH__Section__Key` environment variables. Example:

```json
{
  "Store": { "Provider": "Sqlite" },
  "Firewall": { "Provider": "Auto" },
  "Allowlist": { "Entries": [ "203.0.113.0/24" ] },
  "Rules": [
    {
      "Name": "sshd",
      "Detector": "LogFile",
      "Paths": [ "/var/log/auth.log" ],
      "Patterns": [ "sshd(?:\\[\\d+\\])?: Failed \\S+ for (?:invalid user )?.*? from (?<ip>\\S+) port \\d+" ],
      "MaxRetry": 5,
      "FindTimeSeconds": 600,
      "BanMinutes": [ 10, 60, 1440, 10080 ]
    }
  ]
}
```

Without `Rules`, sensible defaults for the current OS are used (sshd on Linux/macOS, failed
logons - event 4625 - on Windows).

## License

Tri-licensed under your choice of MIT, Apache 2.0, or BSD 3-Clause.
See [LICENSE](LICENSE) for the full text of all three licenses.
