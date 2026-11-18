# Changelog

## Unreleased

- **M3 – shared database**
  - MySQL joins SQLite, PostgreSQL and SQL Server as an EF Core store (`Store:Provider` = `MySql`,
    using Oracle's `MySql.EntityFrameworkCore`; Pomelo has no stable EF Core 10 release).
  - Agents sharing one database converge through the reconcile loop: a ban or unban made by one
    is applied by the others within `Reconcile:IntervalSeconds`.
  - Integration tests (Testcontainers) run one `IBanStore` contract against all three server databases.
  - The schema is created with `EnsureCreated` (safe if several agents start at once); versioned migrations are future work.
- **M1 + M2 – local MVP and platform coverage** (macOS pf, Windows Event Log, journald, rule tester and escalation were built together with the core)
  - Core engine: sliding-window failure counting per rule and address, escalating ban durations,
    allow-list (private ranges, loopback and local interface addresses protected by default).
  - Detectors: log-file tail (rotation/truncation safe, wildcards), command output
    (journalctl, macOS `log stream`), Windows Event Log.
  - Firewall providers: nftables, iptables + ipset, Windows Firewall (COM API), macOS pf, dry-run.
    The store is the source of truth; the firewall is reconciled to it.
  - EF Core store with SQLite as the default; ban/unban/audit events, allow-list, agent heartbeats, stats.
  - `banish` CLI (`status`, `list`, `ban`, `unban`, `allow`, `test-rule`, `config`) and `banish-agent` service host.
