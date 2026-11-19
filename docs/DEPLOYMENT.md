# Deploying Banish

Banish has three programs, all in each release archive:

| Program | What it is | Needs admin rights? |
|---|---|---|
| `banish-agent` | Watches logs / the Windows event log, bans abusive addresses, edits the host firewall | **Yes** (root / Administrator) |
| `banish-api` | The central ban registry, Web API and dashboard | No |
| `banish` | Command line: `status`, `list`, `ban`, `unban`, `allow`, `sync`, `user`, `apikey`, `install`... | Only for `install` and for reading some logs |

## Choosing a topology

**1. One machine (default).** Run only `banish-agent`. Bans live in a local SQLite file
(`/var/lib/banish/banish.db`, `/Library/Application Support/Banish/banish.db`, or
`%ProgramData%\Banish\banish.db`). Nothing to configure.

**2. Several machines, shared database.** Create a database on PostgreSQL, SQL Server or MySQL and
point every agent at it:

```json
{ "Store": { "Provider": "PostgreSql", "ConnectionString": "Host=db;Database=banish;Username=banish;Password=..." } }
```

Each agent applies every active ban in the database to its own firewall within
`Reconcile:IntervalSeconds` (15 by default), so a ban made on one machine blocks the address on all of
them. The schema is created automatically on first start (`EnsureCreated`; versioned migrations are on the backlog).

**3. Several machines, central API.** Run `banish-api` next to the database, give each agent an API key
and no database credentials:

```sh
banish apikey create web-01 --role agent      # prints the key once
```
```json
{ "Store": { "Provider": "Api", "ApiUrl": "https://banish.example.com", "ApiKey": "bnk_..." } }
```

An agent key can read active bans, report bans as itself and send heartbeats. It cannot unban, edit the
allow-list, claim manual bans or ban allow-listed addresses. Use `--role admin` keys only for scripts you trust.

The API itself uses one of the database providers from topology 2 (`Store:Provider` must not be `Api`).

## Installing

Unpack the archive for your platform (for example `banish-0.1.0-linux-x64.tar.gz`) somewhere permanent
such as `/opt/banish` or `C:\Program Files\Banish`, then, as root / Administrator:

```sh
banish config init                 # writes a commented banish.json to the default location
banish install                     # registers and starts the agent service
banish install --api               # (on the central host) registers the API and dashboard
banish uninstall [--api]
```

`install` creates a systemd unit (Linux), a launchd daemon (macOS) or a Windows service, using the
`banish-agent` / `banish-api` executable next to `banish`. The API unit runs as a throw-away user with no
capabilities; the agent stays root because it edits the firewall.

### Firewall tools

| OS | Used (`Firewall:Provider = Auto`) | Notes |
|---|---|---|
| Linux | `nft` if present, else `ipset` + `iptables` | Banish owns the table `inet banish` (nftables) or the ipsets `banish`/`banish6`. Works beside firewalld and ufw. |
| macOS | `pf` anchor `banish` | `/etc/pf.conf` must contain `anchor "banish"`; the agent warns if it does not. |
| Windows | Windows Firewall rules `Banish_Block_0...` | Up to 1,000 addresses per rule. |

Use `"Firewall": { "Provider": "DryRun" }` first to see what would be blocked without touching anything.

> **Platform status.** The Linux paths (nftables script generation, iptables/ipset, log and journald
> detection, the systemd unit) are covered by tests and were run on Linux. The Windows paths were run on
> Windows 11 Pro (10.0.26300): Windows Firewall rules (create, update, remove, IPv4/IPv6/CIDR, blocking a
> second machine), the Event Log detector on real failed-logon events, `banish install|uninstall [--api]`
> as services under LocalSystem (auto-start, restart on failure, `%ProgramData%\Banish` writable), and the
> single-file win-x64 binaries. Not exercised on Windows: a remote failed logon over RDP (NLA or not) feeding
> a ban, and SQL Server from the single-file build. The macOS `pf` and launchd code is implemented and
> unit-tested for the text it generates, but has **not been run on macOS yet**. Try any new platform in
> DryRun mode and with an allow-listed address you can reach from elsewhere before relying on it.

### Windows notes

* Reading the **Security** event log needs Administrator; the service runs as LocalSystem, which can. To run
  the agent under another account, add it to the *Event Log Readers* group. Without the right the agent stops
  with a message naming both options instead of running blind.
* Failed logons from the machine itself log `::1`, `127.0.0.1` or `-` as the address; those are never banned.
  Event 4625 is only written when failure auditing for the *Logon* subcategory is on
  (`auditpol /get /subcategory:"Logon"`).
* Editing Windows Firewall rules also needs Administrator. Rules appear as `Banish_Block_0`, `Banish_Block_1`, ...
  (inbound, block, all profiles) and are removed by `banish unban` / when the bans expire.
* `banish user create --password-stdin` strips the byte order mark that Windows PowerShell 5.1 adds to piped text.

## The dashboard

`banish-api` serves the dashboard at `/`. Create the first administrator on the API host:

```sh
banish user create admin --role admin      # prompts for the password (12+ characters)
banish user create auditor --role viewer
```

* `Dashboard:PublicReadOnly: true` lets anyone view statistics without signing in. Admin pages always need a sign-in.
* `Dashboard:MaskIps` (default true) shows `203.0.113.x` instead of full addresses to everyone but admins.
* To use your identity provider instead of local accounts:

```json
{ "Auth": { "Mode": "Oidc",
    "Oidc": { "Authority": "https://login.example.com/realms/ops", "ClientId": "banish", "ClientSecret": "...",
              "RoleClaim": "groups", "AdminRoles": [ "banish-admins" ], "ViewerRoles": [ "banish-viewers" ] } } }
```

The redirect URI to register is `https://<host>/signin-oidc`. Users with no matching role get no access.
Verified against Keycloak 26 (authorization code + PKCE, roles from a flat `roles` claim): sign-in, role
mapping (admin, viewer, and a user with no role who gets no access) and sign-out all work. Keycloak needs a
mapper that puts the realm roles in a top-level claim; [examples/keycloak-realm.json](examples/keycloak-realm.json)
is a realm with the client, mapper and three test users that you can import into a development Keycloak
(`start-dev --import-realm`). Register `https://<host>/signout-callback-oidc` as a post-logout redirect URI.
Other providers have not been tried.

**Use HTTPS.** `banish-api` listens on `Api:Urls` (default `http://127.0.0.1:5380`). Put a reverse
proxy with TLS in front of it before exposing it; the API logs a warning when it listens on a non-loopback
`http://` address, because API keys and passwords would cross the network in clear text. Behind a proxy,
forward the original client address (the per-IP login rate limit uses the connection address).

## Blocklists

See the README. Configure `Sync:Sources` on **one** node when several share a store, and check each
list's terms of use.

## Operating notes

* **Back up** the database (or the SQLite file). Ban history drives escalation of repeat offenders.
* **Locked out?** Add your address to the allow-list from another machine (`banish allow add <ip>`) or stop the
  agent (`systemctl stop banish-agent`); on Linux `nft delete table inet banish` removes every block at once.
  Private ranges, loopback and the machine's own addresses are never banned by default.
* **Expired bans are not deleted** yet; the tables grow slowly (see BACKLOG.md).
* **Trust.** Whoever can write to the shared store can ban any non-allow-listed address on every machine.
  Protect database credentials and admin API keys accordingly; prefer topology 3 with per-agent keys.
* **Time.** Expiry uses UTC timestamps written by each agent; keep clocks in sync (NTP).
