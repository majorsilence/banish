# Banish

Banish is a cross-platform (Windows, Linux, macOS) intrusion-prevention agent for .NET, in the
spirit of fail2ban and IPBan. It watches logs and event sources for failed logins and abusive
behaviour, blocks the offending IP addresses in the host firewall, and records every ban in a
**central, shareable ban store**.

- **Per-machine by default**: a local SQLite database, zero configuration.
- **Shared when you want it**: point many agents at one PostgreSQL / SQL Server / MySQL database
  (any EF Core provider), or at the Banish Web API. A ban made on one machine is applied by all.
- **Dashboard**: a read-only statistics view (optionally public, with addresses partly masked) and an admin view where bans can be added or lifted. Local accounts by default, OpenID Connect optionally.
- **Blocklist sync**: periodically import public IP blocklists.

See [PLAN.md](PLAN.md) for the design, [CHANGELOG.md](CHANGELOG.md) for progress, and
[BACKLOG.md](BACKLOG.md) for accepted-but-unscheduled work.

## Install

Download the archive for your platform from the GitHub releases page and see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (topologies, services, firewall tools, dashboard sign-in, HTTPS).
Short version: `banish config init && sudo banish install`.

## Quick start from source (Linux)

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

## Blocklist sync

Banish can import public IP blocklists on a schedule. Add sources under `Sync:Sources`; they run
in the agent, or in `banish-api` for a shared store (configure them on **one** node only). Try one
with `banish sync --dry-run`.

```json
{
  "Sync": {
    "Sources": [
      { "Name": "spamhaus-drop", "Url": "https://www.spamhaus.org/drop/drop.txt", "Format": "plain", "IntervalMinutes": 720 },
      { "Name": "feodo", "Url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "Format": "plain" },
      { "Name": "firehol-level1", "Url": "https://iplists.firehol.org/files/firehol_level1.netset", "Format": "plain" }
    ]
  }
}
```

Formats: `plain` (first token per line, `#`/`;` comments), `csv` (first column) and `json` (an array, or
one JSON value per line, as strings or objects with a `cidr`/`ip`/`address` field).
Those URLs were reachable when this was written; check each list's current location and terms of use
before relying on it.

Safety: HTTPS only (unless `AllowInsecureHttp`), allow-listed and private addresses are never
imported, a download that is empty or would lift more than `MaxRemovalPercent` (50) of the source's
entries changes nothing, downloads are capped at 32 MB and `MaxEntries`, and unchanged lists are
not re-processed (ETag / If-Modified-Since). Entries are bans with source `blocklist:<name>` that
are lifted when they leave the list; admins can run a refresh from the dashboard's Blocklists page.

## License

Tri-licensed under your choice of MIT, Apache 2.0, or BSD 3-Clause.
See [LICENSE](LICENSE) for the full text of all three licenses.
