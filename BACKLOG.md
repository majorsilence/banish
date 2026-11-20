# Backlog

Items here are accepted but not scheduled. See [PLAN.md](PLAN.md) for the active plan.

## Verification on real platforms

* macOS: run and fix, if needed, the `pf` and launchd paths (no Mac has run them yet).
* OIDC: verified against Keycloak only; try Entra ID, Google and Auth0 (their role/group claims differ).
* Windows: a remote RDP failed logon (NLA and non-NLA, IPv6) feeding a ban end to end, and SQL Server from the
  single-file build.

## Distribution

* Authenticode-sign the MSI and executables, and notarize the macOS binaries (needs certificates).
* Publish the Homebrew formula to a tap and the winget manifests to `microsoft/winget-pkgs` automatically.
* Signed apt/yum repositories (today the `.deb`/`.rpm` are downloaded from the release page).

## GeoIP

* Land outlines on the bubble map (it shows a graticule and bubbles only; no map geometry is bundled).
* Optional automatic update of the GeoLite2 files with a MaxMind license key.
* City-level points when a city database is configured.

## Dashboard

* Per-address history page (all bans and events for one address).
* Push updates for changes made by other processes (agents that write to the database directly); today those
  show up on the one-minute poll.
