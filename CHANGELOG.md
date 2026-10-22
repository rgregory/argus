# Changelog

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
