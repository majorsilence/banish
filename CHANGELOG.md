# Changelog

## Unreleased

- **M4 – Web API**
  - `banish-api`: ASP.NET Core minimal API (`/api/v1`) in front of the central store, with
    hashed per-agent API keys (`banish apikey create|list|revoke`), `agent`/`admin` roles, rate limiting
    and a warning when listening on non-loopback HTTP.
  - Agents are least-privilege: an agent key can read active bans, report bans as itself (source forced
    to `local`, never against an allow-listed address) and send heartbeats; it cannot unban,
    edit the allow-list or claim manual bans.
  - `Store:Provider = Api` (`HttpBanStore`) lets an agent use the API as its store.
  - `POST /api/v1/failures` feeds the central engine for rules with `"Detector": "Http"` (apps/WAFs).
  - `GET /api/v1/blocklist.txt` exports the active bans.
  - Schema now also holds `ApiKeys` and `Users` (local dashboard accounts, used from M5).
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
