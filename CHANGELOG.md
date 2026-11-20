# Changelog

## 0.2.0 - 2026-11-20

- **Native packages.** `.deb` and `.rpm` (systemd units, sample config in `/etc/banish`), a Windows `.msi`
  (PATH, sample config, optional service registration with `INSTALLAGENT=1` / `INSTALLAPI=1`), a Homebrew formula and
  winget manifests generated for each release, and NuGet packages for the libraries. Releases also carry
  `SHA256SUMS`, an SPDX SBOM and signed build-provenance attestations. The release workflow can be run by hand as a
  dry run that builds the installers and installs them on the runners without publishing.
- **GeoIP maps** (`GeoIp:*`, off by default): country and network lookups from a local MaxMind-format file; the
  dashboard overview gets a bubble map, top countries and top networks (totals only).
- **Dashboard.** Pages update as soon as bans change on the API host instead of every 15 seconds (a one-minute
  poll remains for changes made by other processes); overview lists link to a filtered ban list (rule, source,
  machine); the ban list takes `rule`, `source`, `machine`, `state` and `search` in the address and has a Rule
  filter; light / dark / system theme switch.
- **Retention.** `Retention:*` and `banish prune`: old lifted/expired bans and events are deleted (defaults 365 and
  90 days, daily).
- **Schema migrations.** EF Core migrations per provider replace `EnsureCreated`; 0.1.x databases are adopted
  without changes. Verified on SQLite, PostgreSQL, SQL Server and MySQL.
- `Api:Urls` accepts a JSON array as well as a `;`-separated string and refuses values that are not http(s) URLs
  (a malformed value used to be ignored and the API listened on the default port).
- Release workflow: the release job downloads only the `banish-*` artifacts (v0.1.0 has a tag but no release
  because of this; v0.1.1 is the first release).

- **OIDC verified against a live provider** (Keycloak 26 in Docker): code flow with PKCE, role mapping from a
  `roles` claim, no access for a user without a role, and sign-out. Example realm in `docs/examples/`.
- Release workflow: the release job now downloads only the `banish-*` binary artifacts; the image job's build
  record made the download of "all artifacts" fail, so v0.1.0 has no GitHub release. Use v0.1.1.

- **Windows verification** (first run on real Windows 11 Pro 10.0.26300; fixes found by it)
  - Windows Firewall provider: verified creating, updating and removing the inbound block rules `Banish_Block_N`
    (IPv4, IPv6 and CIDR entries, 1,000 addresses per rule, all profiles). Windows rewrites `RemoteAddresses`
    on read (sorted, netmasks added, single IPv6 hosts as ranges), so every apply used to rewrite the rules;
    the desired list is now compared in Windows' own form, and a disabled or altered rule is repaired.
  - Verified end to end: a ban reaches the firewall within `Reconcile:IntervalSeconds` and a second machine
    (WSL2) can no longer connect until the ban is lifted. Windows-only tests (`[Platform("Win")]`) cover the
    provider; the ones that edit rules run only in an elevated process.
  - Event Log detector: a failed subscription (no right to read the Security log) used to be swallowed, so the
    agent logged "subscribed" and never saw anything; it now stops with a message naming Administrator and
    "Event Log Readers". Event 4625 was checked against real events (`IpAddress` is a plain address, `::1`,
    `127.0.0.1` or `-` for local logons); the default pattern also accepts double-quoted attributes.
  - `banish user create|passwd --password-stdin`: Windows PowerShell 5.1 prefixes piped text with a UTF-8 byte
    order mark, which became part of the password and made sign-in impossible. It is now stripped.
  - `banish-api` serves its static files (including `/_framework/blazor.web.js`) from the folder holding the
    executable; started from another working directory it returned an empty script and the dashboard did not load.
  - Services: `banish config init`, `install`, `install --api` and `uninstall [--api]` verified from a path with a
    space (`C:\Program Files\...`): correct quoting, auto-start, LocalSystem, restart-on-failure actions (a killed
    agent came back within 12 s), start/stop, and the database and key ring written to `%ProgramData%\Banish`.
    The API service served `/api/v1/health`, `/_framework/blazor.web.js` and `/login`. No changes were needed.
  - The single-file win-x64 build (about 49 MB for `banish` and `banish-agent`, 60 MB for `banish-api`) runs.
- **M7 – packaging and release**
  - `banish install [--api]` / `uninstall` register a systemd unit (the API unit runs as a dynamic user with no
    capabilities), a launchd daemon or a Windows service; `banish config init` writes an annotated sample.
  - `banish-api` runs as a Windows service or under systemd; `--healthcheck` for containers.
  - Release workflow: self-contained, compressed single-file binaries for linux/win/osx x64+arm64 with checksums,
    a GitHub release, and a GHCR image for the API. `Dockerfile` and `docker-compose.example.yml` (API + PostgreSQL).
  - The API persists its sign-in key ring in the data directory (`Api:KeyDirectory`), so restarts keep sessions.
  - Verified: self-contained single-file `banish`, `banish-agent` and `banish-api` (linux-x64) run; the Docker image builds and serves the dashboard, health check and bundled CLI.
  - [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and a status/deviations section in PLAN.md.
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
