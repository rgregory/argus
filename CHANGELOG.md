# Changelog

## 1.3.0 (unreleased)

### Added

- **Flagged domains traced to programs.** Each domain flagged by a feed, CrowdSec or OSINT is joined to Little Snitch's hostnames, so the finding names the program on this Mac that connected to it (last 7 days).
- **Container image scanning.** If `grype` or `trivy` is installed, the user job scans the images your running containers use once a day. Results, with CISA KEV cross-referencing and fixable counts, are on the Vulnerabilities tab.
- **Time Machine.** Posture shows the last backup's age (warning after 2 days, failing after 7), a missing backup destination, and automatic backups switched off.
- **Wi-Fi, DNS and VPN.** Every 5 minutes the root job records the Wi-Fi network (`wdutil`), DNS resolvers and VPN state (Mullvad, connected VPN services or a tunnel default route). Findings for open Wi-Fi, new networks and, if you set `ARGUS_EXPECTED_DNS` / `ARGUS_EXPECT_VPN=1`, DNS going elsewhere and the VPN dropping. Current state appears in Posture.
- **Acknowledge findings.** Open a finding, add an optional note and acknowledge it. It drops out of the counts and lists until something new appears in its evidence (timestamps and repeat counters are ignored), then comes back marked "changed since acknowledged". A switch on the Findings tab shows acknowledged ones.
- **What changed.** The Overview shows findings that are new, changed or resolved compared with the hourly snapshot closest to 24 hours ago.
- **Daily digest.** A self-contained HTML page with new, changed and resolved findings, open high and medium findings with evidence, and posture problems. Written each morning (`ARGUS_DIGEST_HOUR`, default 7) to `$ARGUS_HOME/data/reports/digest-YYYYMMDD.html` and `digest-latest.html`, kept 30 days, and linked from the Overview.
- **Sigma rules.** SigmaHQ's macOS process-creation rules (about 65) are fetched weekly and run against every process launch from Endpoint Security. Matches appear as a finding naming the rule and the command line. `ARGUS_SIGMA=0` turns this off and `ARGUS_SIGMA_DISABLE` drops individual rules. Adds the `yaml` package (no dependencies) to read the rules.
- **USB and Bluetooth devices.** Hourly `system_profiler` snapshots; new USB devices (storage rated higher) and new Bluetooth devices are reported for 7 days.

## 1.2.0 (2026-10-21)

### Added

- **Endpoint tab.** A new dashboard tab for what the Mac is doing, not just what it logs:
  - **Endpoint Security events** from `eslogger`: process launches, background items being registered, authentication, XProtect detections and removals, sudo and su, configuration profiles, TCC changes, SSH and Screen Sharing logins. Findings cover suspicious command lines (pipe-to-shell, decoded payloads, reverse shells, quarantine removal, Gatekeeper or SIP being switched off, Office/browser/chat apps starting shells), programs launched from temp or hidden folders, and third-party programs running for the first time after a 24-hour baseline.
  - **TCC database**: an hourly, read-only copy of the system permission database. Flags new high-impact grants and grants held by programs in odd locations.
  - **Background-item changes**: each `sfltool dumpbtm` snapshot is compared with the last; additions and removals are listed for 7 days.
  - **Programs with internet connections**: connections joined to the process that made them, with signer, and a finding when one talks to a flagged address.
  - **Little Snitch traffic** when Little Snitch is installed and "Allow access via Terminal" is on: per-program destinations, bytes, denied attempts, accepted inbound connections and large uploads.
  - **File integrity**: hourly hashes of SSH authorized keys (with key fingerprints), sudoers, PAM, sshd config, authorization plugins, login and logout hooks, the hosts file, scheduled scripts and shell startup files.
  - **Browser extensions** for Chrome, Brave, Edge, Arc, Vivaldi, Opera, Firefox and Safari: sideloaded or unsigned extensions, new extensions, and ones with all-sites access plus powerful permissions.
  - **Certificate trust**: new certificates in the System keychain and new admin or user trust settings (a newly trusted root is rated high).
  - **Download provenance** from the quarantine database, with download hosts sent through threat intel.
- **Vulnerabilities tab.** macOS and Safari versions against Apple's security-release index, with CISA's Known Exploited Vulnerabilities (KEV) catalog showing which missing fixes are being exploited; installed apps matched to KEV products and flagged when KEV gained entries after the app last changed; pending Apple updates; and Homebrew advisories from `brew vulns` (Homebrew 6.0.11+), falling back to OSV.dev.
- `./argus.sh install-telemetry`, `uninstall-telemetry` and `telemetry-status` for the two optional jobs that need Full Disk Access: `eslogger` and the TCC reader. They're separate from `install-collector`, so Argus works without them.
- Feeds: HaGeZi newly registered domains (`nrd7` and `nrd14-8`, about 5.7 million domains held as hashes, roughly 50 MB of RAM), HaGeZi DGA domains (14 days), the Tor exit list and DShield's top attacking /24s.
- urlscan.io as an enrichment provider (`URLSCAN_API_KEY`); `./argus.sh init` asks for the key.
- Posture: automatic login, guest account, Screen Sharing, File Sharing, Remote Apple Events and XProtect bundle age.
- Password failures from `opendirectoryd` and `loginwindow` in the unified-log slice.
- The Posture card hides passing checks behind a "Show N passing checks" link.
- The smoke test covers the new refresh endpoint and the new report sections.

### Security

- After signing in with `?token=`, the dashboard always redirects to its home page instead of echoing the requested path, which a link like `//other-site` or `/\other-site` could turn into an open redirect. Thanks to the Sentinel report for spotting the first form.
- The dashboard sends `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, so other pages can't frame it.

### Changed

- The unified-log filter no longer includes Little Snitch's own log messages; its traffic history comes from its command-line tool instead.

### Upgrading from 1.1.0

`git pull`, then `./argus.sh install-collector`, `./argus.sh build` and `./argus.sh restart`. `./argus.sh install-telemetry` is optional; see [Endpoint telemetry](docs/INSTALL.md#endpoint-telemetry-optional).

## 1.1.0 (2026-10-20)

### Security

- The dashboard needs an access token. `./argus.sh init` generates `ARGUS_TOKEN`, and `./argus.sh open` signs your browser in with it. Everything except `/api/health` is refused without it.
- The dashboard only answers to `127.0.0.1`, `localhost` and `::1`, which blocks DNS rebinding, and it refuses POST requests from other websites.
- The collector inbox is locked to root and the account that installed the collector (`0700` plus one ACL entry). The root job re-applies the lock on every run.
- `install-collector` and `stream on` refuse to install a script unless root alone can change it and every folder above it, and they strip ACLs from the script and its folder.

### Added

- `./argus.sh init` asks for each credential (Pi-hole, IntelOwl, CrowdSec console, threat-intel API keys). Enter skips, secrets aren't shown, and re-running it keeps what you've set. `--no-prompt` skips the questions.
- `./argus.sh status` warns when the installed collector is older than the repo's, when the collector path could be changed by a non-root account, and when the root job hasn't run for 15 minutes.
- The dashboard explains how to sign in again when its sign-in cookie expires.
- [docs/INSTALL.md](docs/INSTALL.md), a step-by-step install, upgrade and uninstall guide.
- A README section, How isolation reduces risk, with a layer diagram and what each layer protects against and leaves exposed.
- A README section on how Apple's `container` runtime shapes Argus: one VM per container, mounts read through your account, network isolation, loopback-only ports and the builder VM.
- GitHub Actions checks: shell and JavaScript syntax, ShellCheck, and a smoke test of the dashboard's access rules.

### Fixed

- Saving a value to `argus.env` no longer breaks on secrets that contain `|`, `&`, `\` or quotes.

### Upgrading from 1.0.0

Follow [Upgrading](docs/INSTALL.md#upgrading). Running `./argus.sh init` is what creates the access token. Until you do, `./argus.sh up` warns that the dashboard is open to anything on the Mac.

## 1.0.0 (2026-10-20)

First public release.
