# Changelog

## Unreleased

- **M1 + M2 – local MVP and platform coverage** (macOS pf, Windows Event Log, journald, rule tester and escalation were built together with the core)
  - Core engine: sliding-window failure counting per rule and address, escalating ban durations,
    allow-list (private ranges, loopback and local interface addresses protected by default).
  - Detectors: log-file tail (rotation/truncation safe, wildcards), command output
    (journalctl, macOS `log stream`), Windows Event Log.
  - Firewall providers: nftables, iptables + ipset, Windows Firewall (COM API), macOS pf, dry-run.
    The store is the source of truth; the firewall is reconciled to it.
  - EF Core store with SQLite as the default; ban/unban/audit events, allow-list, agent heartbeats, stats.
  - `banish` CLI (`status`, `list`, `ban`, `unban`, `allow`, `test-rule`, `config`) and `banish-agent` service host.
