# Changelog

## Unreleased

- **M6 – blocklist sync**
  - `Sync:Sources` downloads public lists (plain, CSV or JSON) on a schedule, from the agent or the API host;
    `banish sync [--dry-run]` runs them once; admins can sync or preview from the dashboard's Blocklists page
    (`GET /api/v1/sync`, `POST /api/v1/sync/run`).
  - New entries are added in bulk (`IBanStore.AddRangeAsync`, `POST /api/v1/bans/bulk`); entries that left
    the list are lifted. Tried live against Spamhaus DROP, FireHOL level 1 and abuse.ch Feodo.
  - Guard rails: HTTPS only, allow-listed/private ranges skipped, empty or mass-removal refreshes refused,
    32 MB / `MaxEntries` caps, conditional requests.
- **M5 – dashboard** (Blazor Server, served by `banish-api` at `/`)
  - **Viewer mode**: tiles (active, last 24 h, permanent, all-time), new bans per day, bans by rule /
    source / machine, most active offenders, agent health (online/slow/offline with icon and label),
    ban list with filters and paging, audit events. Charts follow the data-viz palette (light and dark),
    each with a table view. `Dashboard:PublicReadOnly` shows it without signing in.
  - **Admin mode**: ban an address or CIDR, unban (with confirmation), manage the shared allow-list.
    Every write is re-checked on the server (`DashboardService`), not just hidden in the UI.
  - `Dashboard:MaskIps` (default on) hides the host part of addresses (`203.0.113.x`) for everyone who
    is not an admin, in the dashboard and in the API.
  - **Sign-in**: local accounts by default (PBKDF2 hashes, 12-character minimum, lockout after 5
    failures, antiforgery, per-IP rate limit, same-site return URLs only), created with
    `banish user create`. `Auth:Mode = "Oidc"` switches to an OpenID Connect provider
    (`Authority`, `ClientId`, `ClientSecret`, `RoleClaim`, `AdminRoles`, `ViewerRoles`); a user with
    no matching role gets no access. The OIDC redirect flow itself has not been exercised against a live provider.
  - `/api/blocklist.txt` now needs an agent or admin key so the unmasked list cannot leak through public mode.
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
