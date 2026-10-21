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

| Access | Scope |
|---|---|
| Read-only | the collector's inbox (a root-owned folder only root and your account can open), `/private/var/log`, `/Library/Logs`, `~/Library/Logs` (the last three only if `ARGUS_MOUNT_HOST_LOGS=1`) |
| Read-write on the host | `$ARGUS_HOME/data` only — reports, CSV exports, and optionally `$ARGUS_HOME/data/config/feeds.json` |
| Container-internal storage | named volumes `argus-state`, `argus-cs-config`, `argus-cs-data` — live inside the Apple `container` VM, not on your Mac's file system directly |
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

The unified log itself cannot be parsed by a Linux container (it's a binary
store only macOS's own `log` tool understands), which is the entire reason
the root collector exists: it's the only process with the privilege and the
tooling to read it, and it exports a filtered slice, not the raw store.

## What leaves the Mac

Nothing Argus does requires cloud infrastructure of its own, but several
pieces legitimately make outbound calls once configured:

**Threat feed downloads** (pulling data in, no indicators sent out): HaGeZi,
FireHOL, IPsum, Spamhaus DROP, Emerging Threats, CINS, blocklist.de,
OpenPhish, and abuse.ch's Feodo/URLhaus/ThreatFox lists. These are plain
GET requests for public blocklists.

**CrowdSec**, if `DISABLE_ONLINE_API=false` (the default), talks to
`version.crowdsec.net` and the CrowdSec hub for collection updates, and
`app.crowdsec.net` if you set `ENROLL_KEY`. Set `DISABLE_ONLINE_API=true` to
keep CrowdSec fully offline (parsers/scenarios already installed keep
working; you lose hub auto-updates and community blocklist sync).

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
| abuse.ch URLhaus / ThreatFox | domain | `ABUSECH_AUTH_KEY` |
| IntelOwl | IP/domain (to **your own** local instance) | `INTELOWL_TOKEN` |

A provider stays off entirely if its key is blank — nothing is sent to it.
Daily caps (`CROWDSEC_CTI_DAILY`, `INTELOWL_DAILY_LIMIT`, `ARGUS_RDAP_DAILY`)
bound how much you can send even with a key configured, both to protect free
tiers and to limit how much indicator data reasonably leaves the Mac per day.

To cut outbound traffic as far as current settings allow, set every
`*_KEY`/`*_TOKEN` blank, set `DISABLE_ONLINE_API=true`, `ARGUS_RDAP_DAILY=0`
and `INTELOWL_AUTO=0`, and list the feeds you don't want fetched in
`ARGUS_FEEDS_DISABLE`. Shodan InternetDB lookups for public IPs currently have
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
- `npm ci --omit=dev` is run at build time from the checked-in
  `package-lock.json`, so Node dependency versions are pinned and
  reproducible as long as the lockfile is kept up to date.

## Reporting a problem

This is a personal/self-hosted project, not a maintained product with an SLA.
If you find a security issue, open an issue in this repository (or, if it's
sensitive enough that you don't want it public immediately, say so in the
issue title and a maintainer will follow up privately) rather than a pull
request that demonstrates it live.

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
  read the dashboard. See "Security hardening" in the README.
