# Security

Argus runs on a Mac you administer and reads security-relevant data about that
Mac. This document explains the trust boundaries, what data leaves the
machine and where it goes, how secrets are handled, and how the container is
hardened. Read it before pointing Argus at anything you care about.

## What Argus is (and isn't)

Argus is a **detection-only** tool. It reads logs, scores indicators, and
shows you findings on a dashboard. It does not install a firewall bouncer,
does not block traffic, and does not modify anything on the host beyond the
collector's own log exports. Nothing on the Mac is quarantined, killed, or
blocked as a result of what Argus finds — you read the dashboard and decide
what to do.

CrowdSec runs *inside* the container in detection mode only. No bouncer is
installed, so its decisions never reach the Mac's actual network stack.

## Trust boundaries and host access

The README's [How isolation reduces risk](README.md#how-isolation-reduces-risk) walks through each layer, what it protects against, and what it leaves exposed.

| Access | Scope |
|---|---|
| Read-only | the collector's inbox (a root-owned folder only root and your account can open), `/private/var/log`, `/Library/Logs`, `~/Library/Logs` (the last three only if `ARGUS_MOUNT_HOST_LOGS=1`) |
| Read-write on the host | `$ARGUS_HOME/data` only — reports, CSV exports, and optionally `$ARGUS_HOME/data/config/feeds.json` |
| Container-internal storage | named volumes `argus-state`, `argus-cs-config`, `argus-cs-data`, managed by Apple's `container` runtime rather than a folder on your Mac you'd browse |
| Root file system | read-only by default (`ARGUS_READONLY_ROOT=1`); `/tmp`, `/run`, `/var/log` are tmpfs |
| Inbound network | the dashboard (`127.0.0.1:7080` by default, access token required) and the syslog listener (`127.0.0.1` unless you deliberately bind it to a LAN address) |
| Dropped capabilities | `NET_RAW`, `MKNOD`, `SYS_CHROOT`, `AUDIT_WRITE`, `SETFCAP` |

**The host collector runs as root.** It's installed once, root-owned, at
`/usr/local/libexec/argus/` by `./argus.sh install-collector`, and invoked by
a root `LaunchDaemon`. A root-run script must never live somewhere your own
account (or an app running as you) can edit — that's why the installer places
it outside your home directory and `chmod`s it so only root can write to it.
Owning the file isn't enough: anyone who can write to a folder above it can
swap it out. `./argus.sh install-collector` checks every folder from `/` down
to the script and refuses to install if a non-root account could change any of
them, and `./argus.sh status` repeats that check. If it ever fails, fix the
folders it lists and reinstall with `./argus.sh install-collector`.
[docs/INSTALL.md](docs/INSTALL.md) describes each install step and what it
changes on the Mac.

**Optional endpoint telemetry** (`./argus.sh install-telemetry`) adds two
root LaunchDaemons that run Apple binaries directly, `/usr/bin/eslogger` and
`/usr/bin/sqlite3`, and both need Full Disk Access. launchd makes each binary
its own "responsible process", so the grant covers those two programs only,
not bash, Terminal or the collector script. Either one, started as root, can
read anything on the disk; using the grant still needs root, because only root
can create a LaunchDaemon. No script is involved, so there is nothing for a
non-root account to swap out. Remove both from Full Disk Access when you
uninstall.

### What the inbox holds

The 1.2.0 telemetry puts more sensitive material in the inbox (root and your
account only):

- **Process launches with full command lines** (Endpoint Security). A password
  or token passed as a command argument by any process ends up here, the same
  caveat as sudo logging but for every program.
- The permission (TCC) grants on record, download URLs from the quarantine
  database, browser extension IDs and permissions, certificate names from the
  System and login keychains (names and hashes only, never private keys),
  per-program network destinations from Little Snitch, and hashes and SSH key
  fingerprints for the watched files. The watched files' contents are never
  copied, only hashed.
- The Wi-Fi networks you join (name, BSSID, security), your DNS resolvers and
  VPN state, and the names, IDs and serial numbers of USB and Bluetooth devices.

The unified log itself cannot be parsed by a Linux container (it's a binary
store only macOS's own `log` tool understands), which is the entire reason
the root collector exists: it's the only process with the privilege and the
tooling to read it, and it exports a filtered slice, not the raw store.

## What leaves the Mac

Nothing Argus does requires cloud infrastructure of its own, but several
pieces legitimately make outbound calls once configured:

**Threat feed downloads** (pulling data in, no indicators sent out): HaGeZi
(threat intelligence from GitHub; newly registered and DGA domains from
cdn.jsdelivr.net), FireHOL, IPsum, Spamhaus DROP, Emerging Threats, CINS,
blocklist.de, OpenPhish, the Tor Project's exit list, DShield's block list,
and abuse.ch's Feodo/URLhaus/ThreatFox lists. These are plain GET requests
for public blocklists.

**Vulnerability data** (pulling data in): CISA's KEV catalog
(cisa.gov) and Apple's security-release index (support.apple.com), twice a
day. Nothing about your Mac is sent.

**Alerts**, only if you configure them: ntfy (`ARGUS_NTFY_URL`), Pushover or
a webhook receive the alert title, the host name, the finding title and its
first evidence line (often a file path or command line). Nothing else is sent.
A topic on the public ntfy.sh server is readable by anyone who knows its
name, so use a long random topic, an access token, or your own ntfy server.
macOS notifications stay on the Mac.

**Homebrew advisories** are checked by `brew vulns` on the Mac, which
fetches Homebrew's advisory database. Only when `brew vulns` isn't available
does the container fall back to OSV.dev, and then it **sends the source
repository URL and installed version of each Homebrew formula** you have
installed (one batch a day, plus detail lookups for any advisories found).
Upgrade Homebrew to 6.0.11 or later to keep that inventory local.

**Sigma rules** are fetched weekly from GitHub (`api.github.com` for the file
list, `raw.githubusercontent.com` for the rules). Nothing is sent.

**Container image scans**, if you install `grype` or `trivy`, run on the Mac
under your account and download that scanner's vulnerability database. The
images themselves are scanned locally; nothing about them is uploaded.

**CrowdSec**, if `DISABLE_ONLINE_API=false` (the default), talks to
`version.crowdsec.net` and the CrowdSec hub for collection updates, and
`app.crowdsec.net` if you set `ENROLL_KEY`. Set `DISABLE_ONLINE_API=true` to
keep CrowdSec fully offline (parsers/scenarios already installed keep
working; you lose hub auto-updates and community blocklist sync).

**IP owner tables**: once a week Argus downloads `ip2asn-v4.tsv.gz` and
`ip2asn-v6.tsv.gz` from `iptoasn.com` (about 10 MB together). Nothing is sent with the request, and owner
lookups run locally against that copy. `ARGUS_ASN=0` stops the download.

**Triage backups** (`data/backups/triage-*.json`) hold finding titles, your
notes and allow-list entries. They sit in `$ARGUS_HOME`, so if that folder is
synced, they're synced too.

**Indicator enrichment is where your own data goes out**, and only for
indicators Argus has observed (public IPs, domains, SSH/Screen
Sharing/firewall sources, DNS queries, flagged values) — never your full log
stream. Each configured provider only receives the specific indicator being
looked up:

| Provider | Sent | Requires a key |
|---|---|---|
| Shodan InternetDB | public IP | no |
| rdap.org | domain | no |
| crt.sh | domain (manual lookups only) | no |
| CrowdSec CTI | IP/domain | `CROWDSEC_CTI_KEY` |
| AbuseIPDB | IP | `ABUSEIPDB_KEY` |
| GreyNoise Community | IP | `GREYNOISE_KEY` |
| VirusTotal | IP/domain | `VT_API_KEY` |
| AlienVault OTX | IP/domain | `OTX_API_KEY` |
| urlscan.io (search only, nothing is submitted for scanning) | IP/domain | `URLSCAN_API_KEY` |
| abuse.ch URLhaus / ThreatFox | domain | `ABUSECH_AUTH_KEY` |
| IntelOwl | IP/domain (to **your own** local instance) | `INTELOWL_TOKEN` |

A provider stays off entirely if its key is blank — nothing is sent to it.
Daily caps (`CROWDSEC_CTI_DAILY`, `INTELOWL_DAILY_LIMIT`, `ARGUS_RDAP_DAILY`)
bound how much you can send even with a key configured, both to protect free
tiers and to limit how much indicator data reasonably leaves the Mac per day.

To cut outbound traffic as far as current settings allow, set every
`*_KEY`/`*_TOKEN` blank, set `DISABLE_ONLINE_API=true`, `ARGUS_RDAP_DAILY=0`
and `INTELOWL_AUTO=0`, list the feeds you don't want fetched in
`ARGUS_FEEDS_DISABLE`, and set `ARGUS_NRD_LISTS=none`. Shodan InternetDB lookups for public IPs currently have
no off switch, so Argus is not fully offline even then. The macOS log
analysis, CrowdSec's already-installed scenarios, and Pi-hole/syslog
ingestion keep working without any of the above.

## Secrets

Everything sensitive lives in one file: `$ARGUS_HOME/config/argus.env`,
created by `./argus.sh init` and `chmod 600` (owner read/write only). It
holds the CrowdSec bouncer key, the dashboard access token, Pi-hole app password, IntelOwl token, and any
OSINT API keys you add. **Never commit this file.** `argus.env.example` in
this repo is a template with every value blank — copy it, don't fill in the
example and commit that.

Use Pi-hole's **app password**, not your Pi-hole login password — it's
scoped to the API and can be individually revoked from Pi-hole's own
settings without touching your admin login.

## Supply chain

- `sbom.json` at the repo root is a CycloneDX 1.6 bill of materials covering
  the npm dependency tree (`app/package-lock.json`), the Docker base images,
  the Alpine packages added in `image/Dockerfile`, and the CDN-loaded
  dashboard libraries (Tabler, Alpine.js, Chart.js, PapaParse). Regenerate the
  npm portion with `npx @cyclonedx/cyclonedx-npm` from `app/`; the rest is
  hand-maintained alongside `image/Dockerfile` and `app/public/index.html`.
- `image/Dockerfile` currently pulls `crowdsecurity/crowdsec:latest` and
  `node:24-alpine` by floating tag, not a pinned digest. For anything beyond
  local/dev use, pin both to a specific digest (`@sha256:...`) so a build is
  reproducible and an upstream image change can't silently change what you're
  running.
- The dashboard loads Tabler, Alpine.js, Chart.js and PapaParse from
  `cdn.jsdelivr.net` using floating major-version tags (e.g. `chart.js@4`).
  This keeps the dashboard current without a frontend build step, at the cost
  of trusting jsDelivr and each library's own minor/patch releases. Vendor
  these files into `app/public/vendor/` instead if you need the dashboard to
  work fully offline or want byte-for-byte reproducibility.
- The dashboard and the weekly edition load the Fraunces and Source Serif 4
  typefaces from Google Fonts (fonts.googleapis.com, fonts.gstatic.com), so
  your browser contacts Google when it opens them. Nothing about the Mac is
  sent; without a connection the pages fall back to Georgia.
- `npm ci --omit=dev` is run at build time from the checked-in
  `package-lock.json`, so Node dependency versions are pinned and
  reproducible as long as the lockfile is kept up to date.

## Data source terms

Argus downloads every feed at runtime and stores nothing from them in this
repository. Check each source's terms against how you use Argus, especially
at work:

- **HaGeZi** lists are GPL-3.0.
- **DShield** data is CC BY-NC-SA (non-commercial). Add `dshield_block` to
  `ARGUS_FEEDS_DISABLE` for commercial use.
- **CISA KEV** is US government work, free to use.
- **Apple's security-release page** is read as a web page; Argus keeps only
  release names, versions and dates.
- **OSV.dev** data carries per-source licenses (mostly CC-BY 4.0).
- **Sigma rules** are under the Detection Rule License (DRL) 1.1, which asks
  for attribution; Argus shows each matching rule's title, author and link.
- **urlscan.io** and the other keyed providers have their own API terms tied
  to your account.

## Reporting a problem

Please report security issues privately. On GitHub, open this repository's
**Security** tab and choose **Report a vulnerability**. Don't open a public
issue, and don't send a pull request that demonstrates the problem, since
either one publishes it before there's a fix.

This is a personal, self-hosted project, not a product with an SLA, but
reports are read and answered.

## Known security-relevant limits

- **CrowdSec ignores private/RFC1918 IPs by default.** Brute-force attempts
  from your own LAN (café Wi-Fi, a compromised IoT device) won't raise a
  CrowdSec alert on their own — Argus's own SSH/Screen Sharing findings still
  flag that traffic, but through a separate path.
- **Root-only logs** (crash reports and logs readable only by root) reach
  Argus through the root collector, not the read-only bind mounts available
  to your own account — by design, since a container running as a normal
  user can't read them directly either.
- **Syslog bound to a LAN address** accepts RFC 3164 messages from anything
  that can reach that port, unauthenticated — syslog has no built-in auth.
  Only bind `ARGUS_SYSLOG_BIND` to your LAN IP on a network you trust.
- **Dashboard access.** Everything except `/api/health` needs `ARGUS_TOKEN`,
  which `argus.sh init` generates, and the server only answers to localhost
  Host names, which blocks DNS rebinding. POST requests from another origin
  are refused. Anyone holding the token can read everything Argus knows, so
  treat it like a password. If `ARGUS_TOKEN` is blank, anything on the Mac can
  read the dashboard. See [Security hardening](README.md#security-hardening)
  in the README.
