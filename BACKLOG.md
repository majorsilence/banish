# Backlog

Items here are accepted but not scheduled. See [PLAN.md](PLAN.md) for the active plan.

## GeoIP maps (optional, off by default)

Enrich bans with country/ASN using a local MaxMind GeoLite2 database file and show maps and "top countries/networks" on the dashboard.

- Disabled by default; enabled via configuration (`GeoIp:Enabled`, `GeoIp:DatabasePath`).
- User supplies the database file (and MaxMind license key if auto-update is added); nothing is bundled.
- Lookups are local; no per-IP network calls.
- Must not affect detection or banning, only dashboard display and stats.
- Do not start until the dashboard milestone (M5) is complete.
