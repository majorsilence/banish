# Banish – Implementation Plan

> **Status: all seven milestones are implemented.** See [Status and deviations](#status-and-deviations) at the end for what was built differently from this plan and what is not done.

Banish is a cross-platform (Windows, Linux, macOS) intrusion-prevention agent in C#/.NET, in the spirit of fail2ban and IPBan. It watches logs and event sources for failed logins and abusive behaviour, bans offending IPs at the host firewall, and shares bans through a central store.

## 1. What fail2ban and IPBan do (from public docs only)

| Concept | fail2ban | IPBan | Banish equivalent |
|---|---|---|---|
| Detection | Regex **filters** over log files | Windows Event Log + log files, SSH logs on Linux | **Detectors** (log-file regex, Windows Event Log, journald, macOS unified log, HTTP "report" endpoint) |
| Policy | **jail**: `maxretry`, `findtime`, `bantime` | Failed-login threshold, ban duration in `ipban.config` | **Rule/Jail** config with the same three knobs, plus escalating bans |
| Enforcement | **actions** (iptables/nftables, notify) | Firewall rules (Windows Firewall, firewalld/nftables/iptables) | **Firewall providers** |
| Repeat offenders | `recidive` jail | Longer bans | Ban-duration escalation ladder |
| Tooling | `fail2ban-client`, `fail2ban-regex` | Config hot reload, service install | `banish` CLI incl. `test-rule`, allow-list, hot reload |
| Sharing bans | none built in | Only in the commercial IPBan Pro | **Core feature**: shared store |

Sources: [fail2ban overview (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-fail2ban-works-to-protect-services-on-a-linux-server), [fail2ban jail guide](https://oneuptime.com/blog/post/2026-03-02-how-to-configure-fail2ban-jails-for-ssh-apache-and-nginx-on-ubuntu/view), [IPBan FAQ](https://ipban.com/?p=967), [IPBan summary (LinuxLinks)](https://www.linuxlinks.com/ipban-detects-repeated-failed-logins/). No source code from either project was consulted.

## 2. Solution layout (`Majorsilence.Banish.slnx`)

```
src/
  Majorsilence.Banish.Core            domain: Ban, Failure, Rule, Whitelist; engine; interfaces (no I/O deps)
  Majorsilence.Banish.Detectors       LogFile, WindowsEventLog, Journald, MacUnifiedLog, HttpReport
  Majorsilence.Banish.Firewall        IFirewall + Windows (netsh/WFP), nftables, iptables, firewalld, macOS pf
  Majorsilence.Banish.Store           IBanStore abstraction
  Majorsilence.Banish.Store.Ef        EF Core store: SQLite (default), PostgreSQL, SQL Server, MySQL
  Majorsilence.Banish.Store.Api       HttpBanStore client for the Web API
  Majorsilence.Banish.Sync            blocklist importers (URL lists, CSV, CIDR) and scheduler
  Majorsilence.Banish.Agent           Worker Service host (Windows Service / systemd / launchd)
  Majorsilence.Banish.Api             ASP.NET Core Web API (central ban registry + dashboard host)
  Majorsilence.Banish.Dashboard       Blazor (Server) UI: read-only and admin modes
  Majorsilence.Banish.Cli             `banish` command (status, ban, unban, list, test-rule, sync)
tests/
  Majorsilence.Banish.Core.Tests, .Store.Tests (Testcontainers), .Detectors.Tests, .Api.Tests
```

Target `net10.0` (decided). Root namespace `Majorsilence.Banish` (decided). Central package management (`Directory.Packages.props`), `.editorconfig`, nullable enabled, warnings as errors. Mirrors conventions of Majorsilence.Sql2Postgre.

## 3. Core engine

1. **Detector** emits `FailureEvent(ip, source, ruleId, timestamp, rawLine?)`.
2. **Engine** keeps a sliding window per (ip, rule). When `count >= maxRetry` within `findTime`, it creates a `Ban`.
3. Checks before banning: allow-list (IPs/CIDRs, always includes loopback/private ranges by default, and the agent's own admin sessions), IPv4/IPv6 parsing, already-banned.
4. `Ban`: `Id, Ip/Cidr, Reason, Source (local|manual|blocklist:<name>|remote), RuleId, CreatedUtc, ExpiresUtc?, MachineName, Hits, CreatedBy`.
5. Ban duration escalates for repeat offenders (e.g. 10 min, 1 h, 1 day, 7 days, permanent), configurable.
6. Engine writes to `IBanStore`, then notifies firewall providers. A reconciliation loop (every N seconds) pulls active bans from the store and makes the firewall match (adds missing, removes expired/unbanned). This is what makes the shared store work: the store is the source of truth; firewalls are a projection of it.

## 4. Ban store (`IBanStore`)

Interface: `AddAsync, RemoveAsync, GetActiveAsync(since token), GetByIpAsync, QueryAsync(filter/paging), StatsAsync, AddFailureAsync (optional audit)`.

| Mode | Implementation | Notes |
|---|---|---|
| **Default: local SQLite** | EF Core SQLite, file in `%ProgramData%\Banish` / `/var/lib/banish` / `/Library/Application Support/Banish` | Zero config, per machine |
| **Shared DB** | EF Core with any provider (Npgsql, SqlServer, Pomelo/MySql) selected by `Store:Provider` + `Store:ConnectionString` | Several agents point at one DB; reconciliation loop picks up bans from other hosts. Separate migration sets per provider |
| **Web API** | `HttpBanStore` talking to `Majorsilence.Banish.Api` | For hosts that must not hold DB credentials; API key per agent; the API itself uses one of the EF stores |

Change feed: a monotonically increasing `Version`/`UpdatedUtc` column so agents poll "changes since X" cheaply. Optional later: LISTEN/NOTIFY (Postgres) or SignalR (API) for push.

Schema: `Bans`, `BanEvents` (audit: banned/unbanned/expired/who), `Failures` (optional, retention-limited, for stats), `Agents` (heartbeat), `Allowlist`, `BlocklistSources`.

## 5. Firewall providers (`IFirewall`)

- **Windows**: Windows Firewall inbound block rules via the `HNetCfg.FwPolicy2` COM API (or `netsh advfirewall` fallback); IPs batched into a few rules (up to ~1000 addresses per rule) like IPBan's approach in concept.
- **Linux**: nftables set (preferred), iptables+ipset, firewalld rich rules/ipset. Auto-detect, overridable.
- **macOS**: `pf` anchor with a table (`pfctl -a banish -t banished -T add/delete`).
- Dry-run mode (log only), IPv4+IPv6, CIDR support, idempotent apply, rules removed cleanly on uninstall.
- Requires elevated privileges; agent runs as service/root. API and dashboard run unprivileged.

## 6. Detectors

- **LogFile**: tail with rotation handling, regex with named `ip` group, rule files in YAML/JSON, shipped defaults for sshd, nginx/apache auth, RDP.
- **Windows Event Log**: Security 4625 (logon failure), RDP/NLA, SQL Server, etc., via `EventLogWatcher`.
- **Linux journald**: `journalctl -f -o json` process or sd-journal.
- **macOS**: `log stream` predicate for sshd/auth.
- **HTTP report endpoint** on the API: lets apps/WAFs push `POST /api/v1/failures`.
- `banish test-rule <rule> <logfile>` (like `fail2ban-regex`).

## 7. Blocklist sync

`Sync:Sources[]` in config: `{ Name, Url, Format (plain|cidr|csv|json), IntervalMinutes, Enabled, ExpireAfter, Headers/ApiKeyRef, MaxEntries }`.

- Scheduler downloads (ETag/If-Modified-Since), parses, validates (rejects private/reserved ranges and the allow-list), diffs against previous import, and bulk upserts with `Source = blocklist:<name>`; entries that disappear from the list are removed.
- Presets documented: Spamhaus DROP, Emerging Threats, Blocklist.de, FireHOL, abuse.ch, etc. (users opt in; check each list's terms of use).
- Safety: max-entries cap, dry-run diff preview, HTTPS only by default, never ban allow-listed IPs.
- Also export: `GET /api/v1/blocklist.txt` so other tools can consume Banish's list.

## 8. Web API (`Majorsilence.Banish.Api`)

Versioned `/api/v1`:
- Agent (API-key auth, per-agent keys): `GET bans?since=`, `POST bans`, `DELETE bans/{id}`, `POST heartbeat`, `POST failures`.
- Dashboard/admin (local accounts by default, OIDC by config; roles `Viewer`, `Admin`): `GET stats`, `GET bans` (paging/filter), `POST bans` (manual), `DELETE bans/{id}` (unban), allow-list and blocklist-source CRUD, agent keys management.
- OpenAPI doc, rate limiting, audit log, TLS required outside localhost.

## 9. Dashboard (`Majorsilence.Banish.Dashboard`, Blazor Server hosted by the API)

- **Viewer mode** (anonymous or Viewer role, config `Dashboard:PublicReadOnly`): totals, active bans, bans over time, top countries/ASNs (optional offline GeoLite2 DB), top rules, top offending IPs, per-agent health, recent events. No full IPs when `Dashboard:MaskIps=true` (e.g. `203.0.113.x`).
- **Admin mode** (login required, Admin role): ban an IP/CIDR manually with reason and expiry, unban, edit allow-list, manage blocklist sources and trigger sync, view audit log, manage agent API keys.
- CSRF protection, all mutating actions audited, server-side authorization on the API (UI hiding is not the security boundary).
- The dashboard can also run against any EF store directly (single-node setups) without the API.

## 10. Configuration

`banish.json` (+ env vars `BANISH__*`, hot reload), layered: defaults → file → env. Sections: `Store`, `Rules`, `Allowlist`, `Firewall`, `Sync`, `Api`, `Dashboard`, `Logging`. Secrets via env/secret store, never in the default file.

## 11. Packaging and install

- `dotnet publish` self-contained single-file for win-x64/arm64, linux-x64/arm64, osx-x64/arm64.
- `banish install|uninstall` registers Windows Service / systemd unit / launchd plist.
- Installers: MSI (WiX) or winget, `.deb`/`.rpm`, Homebrew formula, Docker image (API + dashboard only).
- GitHub Actions: build/test matrix on all three OSes, release artifacts, NuGet for `Banish.Core`/store packages, SBOM and signing.

## 12. Security considerations

- Never ban allow-listed/own/gateway addresses; lockout-prevention test on startup (current SSH/RDP session IP is auto-allowed).
- Validate all IP input; cap blocklist sizes; guard against log-injection spoofing (regex anchored, ignore attacker-controlled fields, forwarded-for only from trusted proxies).
- Shared store is a trust boundary: a compromised agent could ban arbitrary IPs. Mitigate with per-agent API keys/scopes, an optional "remote bans need approval/expire quickly" policy, and audit trail.
- Least privilege: only the agent needs admin rights.

## 13. Milestones

1. **M1 – Local MVP**: Core engine, SQLite store, log-file detector (sshd), nftables + Windows Firewall, CLI, allow-list. Linux + Windows.
2. **M2 – macOS and more detectors**: pf, Windows Event Log, journald, rule tester, escalation.
3. **M3 – Shared DB**: EF provider switching + migrations (PostgreSQL, SQL Server, MySQL), reconciliation loop, Testcontainers tests.
4. **M4 – Web API**: HttpBanStore, agent keys, heartbeat, failure reporting.
5. **M5 – Dashboard**: viewer mode, stats, then admin mode (ban/unban, allow-list, audit).
6. **M6 – Blocklist sync**: importers, scheduler, presets, export endpoint.
7. **M7 – Packaging/release**: installers, service registration, docs, CI.

## 14. Decisions

- Root namespace and project prefix: `Majorsilence.Banish`.
- Target framework: .NET 10.
- Dashboard: Blazor Server.
- Admin auth: **local accounts by default** (ASP.NET Core Identity or a lightweight user table, hashed passwords, first-run admin setup, lockout and rate limiting). Setting `Auth:Mode = "Oidc"` switches to an external OpenID Connect provider (`Authority`, `ClientId`, `ClientSecret`, role/group claim mapping to `Admin`/`Viewer`). Only one mode is active at a time.

## 15. Backlog

- GeoIP maps: optional, off by default, not scheduled. See [BACKLOG.md](BACKLOG.md).

## Status and deviations

All milestones M1–M7 are implemented and pushed; the test suite is 154 unit/HTTP tests plus 33 container tests
(real PostgreSQL 18, SQL Server 2022 and MySQL 8.4). Where the build differs from the plan above:

| Plan | What was built |
|---|---|
| Projects `Banish.*` / separate `Store` project | `Majorsilence.Banish.*`; the `IBanStore` interface lives in `Core`. Added `Hosting` (composition), `Sync` and `Dashboard` (Razor class library). |
| Per-provider EF migrations | `EnsureCreated` for every provider (safe when agents start together). Real migrations are on the backlog. |
| firewalld provider | Not needed: the nftables provider coexists with firewalld/ufw. |
| `Failures` table, `HttpReport` detector | No failures table. Apps report failures to `POST /api/v1/failures`; the API's engine counts them for rules with `"Detector": "Http"`. |
| Blocklist sources CRUD in the admin UI, `ExpireAfter` | Sources are configuration only (the dashboard shows status and runs "sync now"); imported entries are permanent while listed and lifted when they leave the list. |
| Auto-allow the current admin session's IP | Replaced by: never ban private ranges, loopback or the machine's own addresses; `banish ban` and the dashboard refuse allow-listed targets unless forced. |
| Admin keys / user accounts | API keys are hashed (`agent`/`admin`); dashboard users are local (default) or OIDC. |
| Packaging: MSI, `.deb`/`.rpm`, Homebrew, winget, NuGet, SBOM/signing | Not done. Delivered: self-contained single-file binaries per OS/arch in GitHub releases, `banish install` for systemd / launchd / Windows services, a Dockerfile and compose example for the API. See BACKLOG.md. |
| GeoIP | Backlog, as agreed. |

Not yet run on real hardware: the Windows Firewall, Windows Event Log, macOS `pf`/launchd code and the OIDC
sign-in redirect (they are implemented and their generated commands/config are tested).
