# Security and Codebase Review Summary: Argus

**Model / Agent:** Claude Opus 5.5
**Date:** October 20, 2026
**Target Repository:** `rgregory/argus`

---

## Executive Summary

Argus is a local log-analysis and security detection system for macOS running Apple's `container` engine. It combines local unified log slices, system posture reports, background items/launchd configurations, container logs, Pi-hole DNS query logs, and network syslog into a single local dashboard while screening indicators against threat feeds, CrowdSec scenarios, and OSINT lookup providers.

A comprehensive review of the repository structure, code syntax, architectural design, data flows, and security posture was conducted. Overall, the codebase exhibits strong security boundaries, well-isolated execution environments, robust input/origin checking, and clear data-handling policies.

---

## 1. System Architecture & Components

### 1.1 Host Collector (`collector/`)
- **`com.argus.collect` (LaunchDaemon)**:
  - Runs as `root` every 5 minutes at low priority (`LowPriorityIO`).
  - Exports security-relevant unified log slices (`sudo`, `authd`, `sshd`, Gatekeeper, XProtect, TCC, application firewall) into `/Users/Shared/Argus/inbox`.
  - Captures `lsof` TCP/UDP listeners/connections, `sfltool dumpbtm` background items, system extensions, MDM profiles, login history, and system diagnostic/crash reports.
  - Hardened location (`/usr/local/libexec/argus/argus-collect.sh`) with `root:wheel 0755` permissions to prevent privilege escalation via file modification.
  - Inbox directory `/Users/Shared/Argus/inbox` is restricted (`0700` owned by root, with ACL granting access solely to the installing user).
- **`com.argus.collect.user` (LaunchAgent)**:
  - Runs as the unprivileged user every 15 minutes. Refuses to run as `root`.
  - Collects user `launchctl` jobs, crontabs, container logs, and Ollama server logs.
- **`com.argus.logstream` (Optional LaunchDaemon)**:
  - Streams security events live to syslog-ng over TCP when enabled (`./argus.sh stream on`).

### 1.2 Container Runtime (`image/`)
- Built from `crowdsecurity/crowdsec` (Alpine base) + Node.js 24 + syslog-ng.
- Supervised entrypoint manages syslog-ng (UDP 5514 / TCP 5515), CrowdSec, and Argus Node service.
- Container security controls:
  - **Read-only Root File System**: Enforced with `ARGUS_READONLY_ROOT=1` (`/tmp`, `/run`, `/var/log` mounted as `tmpfs`).
  - **Dropped Capabilities**: `NET_RAW`, `MKNOD`, `SYS_CHROOT`, `AUDIT_WRITE`, and `SETFCAP` are dropped.
  - **Volume Isolation**: Data state and CrowdSec storage reside in isolated named volumes (`argus-state`, `argus-cs-config`, `argus-cs-data`). Read-write host mounts are restricted strictly to `$ARGUS_HOME/data`.

### 1.3 Service Layer (`app/`)
- **Express.js HTTP Server (`server.js`)**:
  - Exposes dashboard and API at `127.0.0.1:7080`.
  - Native SQLite backing store (`lib/store.js`) using `node:sqlite`.
- **Analysis & Enrichment Engines**:
  - `lib/engine.js`: macOS log slice and posture analysis.
  - `lib/feeds.js`: Threat feed aggregator (HaGeZi, FireHOL, IPsum, Spamhaus, abuse.ch, etc.).
  - `lib/intel.js`: Multi-tier priority queue for OSINT indicator lookups (Shodan InternetDB, RDAP, CrowdSec CTI, AbuseIPDB, GreyNoise, VirusTotal, OTX, IntelOwl).
  - `lib/crowdsec.js`: CrowdSec LAPI integration.
  - `lib/ingest.js`: Inbox reader, syslog reader, and Pi-hole API query collector.

---

## 2. Security Controls & Hardening Assessment

| Security Control | Implementation | Status |
|---|---|---|
| **Detection-Only Design** | No bouncer installed; container only watches and reports. No host changes made. | Verified |
| **Host Name Validation** | `Host` header strictly checked against `localhost`, `127.0.0.1`, `::1` to prevent DNS rebinding. | Verified |
| **Cross-Origin Protection** | Non-GET/HEAD requests validate `Origin` header against allowed localhost domains. | Verified |
| **Authentication & Tokens** | All non-health routes require `ARGUS_TOKEN` via `Bearer` token or HttpOnly cookie. | Verified |
| **Timing-Safe Token Checks** | `crypto.timingSafeEqual` used for token comparisons to prevent timing attacks. | Verified |
| **Collector Protection** | Collector script installed outside user space with `root:wheel` ownership. Inbox locked via ACL. | Verified |
| **Data Minimization** | Only observed public IPs and domains sent to OSINT lookups. Raw log streams never leave host. | Verified |
| **Secret Management** | Credentials stored in `~/.argus/config/argus.env` with `0600` permissions. | Verified |

---

## 3. Verification & Health Checks

1. **Syntax Validation**:
   - `node --check app/server.js app/lib/*.js`: PASSED (0 errors).
   - `bash -n argus.sh collector/*.sh image/*.sh`: PASSED (0 errors).
2. **SBOM & Dependency Tree**:
   - `sbom.json` exists at root compliant with CycloneDX specifications.
   - Node dependencies locked in `app/package-lock.json`.

---

## 4. Recommendations & Supply Chain Hardening

1. **Docker Base Image Pinning**: Pin base image tags in `image/Dockerfile` (`crowdsecurity/crowdsec` and `node:24-alpine`) to explicit `@sha256:` digests for reproducible builds.
2. **CDN Assets Vendoring**: For fully offline environments, vendor frontend JS/CSS assets (Tabler, Alpine.js, Chart.js, PapaParse) into `app/public/vendor/`.
3. **Sensitive Command Lines**: Be mindful that commands run via `sudo` containing inline secrets/tokens will appear in unified log slices.

---

*End of Review Summary.*
