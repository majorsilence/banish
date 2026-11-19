# Backlog

Items here are accepted but not scheduled. See [PLAN.md](PLAN.md) for the active plan.

## GeoIP maps (optional, off by default)

Enrich bans with country/ASN using a local MaxMind GeoLite2 database file and show maps and "top countries/networks" on the dashboard.

- Disabled by default; enabled via configuration (`GeoIp:Enabled`, `GeoIp:DatabasePath`).
- User supplies the database file (and MaxMind license key if auto-update is added); nothing is bundled.
- Lookups are local; no per-IP network calls.
- Must not affect detection or banning, only dashboard display and stats.
- Do not start until the dashboard milestone (M5) is complete.

## Retention / pruning of old data

Expired and lifted bans and old `BanEvents` are never deleted, so the tables grow. Add a configurable retention
(for example keep ban history for 365 days, which also bounds how long repeat-offender escalation remembers an address)
and a `banish prune` command / background pass.

## Versioned schema migrations

The schema is created with `EnsureCreated`, which cannot alter an existing database. Add EF Core migrations
per provider before the first schema change after release.

## Native installers and distribution

MSI/winget (Windows), `.deb`/`.rpm` (Linux), Homebrew formula (macOS), NuGet packages for `Majorsilence.Banish.Core`
and the store libraries, release signing and an SBOM.

## Verification on real platforms

Run and fix, if needed, the macOS `pf`/launchd paths and the OIDC redirect flow against a real identity provider;
on Windows, exercise a remote RDP failed logon (NLA and non-NLA, IPv6) end to end and SQL Server from the
single-file build. Add CI jobs that exercise these where runners allow (the elevated Windows firewall tests
run on `windows-latest`, whose runner is an administrator).

## Dashboard extras

Theme toggle, IP/ban search across history, per-rule drill-downs, push updates instead of a 15-second refresh.
