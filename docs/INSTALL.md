# Installing Argus

This covers everything from a fresh Mac to a running dashboard, the optional integrations, and how to remove Argus again. For what Argus is and how it works, see the [README](../README.md).

## What you need

- A Mac with Apple silicon running macOS 26. Apple's `container` runtime doesn't support Intel Macs or older versions of macOS.
- Apple's `container` CLI. Install the signed package from its [releases page](https://github.com/apple/container/releases), then run `container system start` once. `container system status` should report that it's running.
- An admin account. Installing the host collector uses `sudo`.

That's all. Pi-hole, IntelOwl, CrowdSec enrollment and the OSINT API keys are optional, and each stays off until you configure it.

## 1. Get the code

```bash
git clone https://github.com/rgregory/argus.git
cd argus
```

## 2. Create your config

```bash
./argus.sh init
```

This creates `~/.argus`, copies `argus.env.example` to `~/.argus/config/argus.env` (readable only by you), and sets up `~/.argus/data` for reports and exports. It generates two keys for you: one Argus uses to read CrowdSec's local API, and an access token for the dashboard.

Then it asks for each credential in turn: the Pi-hole app password, IntelOwl's address and API token, a CrowdSec console enroll key, and the free threat-intel API keys (abuse.ch, CrowdSec CTI, AbuseIPDB, VirusTotal, OTX, GreyNoise). Each question says where to get the key. Every one is optional, so press Enter to skip it. Secrets aren't shown as you type.

Run `./argus.sh init` again any time to add or change credentials. Values you've already set show as `[set]`, Enter keeps them, and `-` clears one. `./argus.sh init --no-prompt` sets up the folders and keys without asking anything.

It's fine to skip every question on the first run. Argus works with all credentials blank, and [Optional setup](#optional-setup) explains what each integration adds.

## 3. Build the image

```bash
./argus.sh build
```

This builds `argus:latest` from the official CrowdSec Alpine image plus Node 24 and syslog-ng. The first build downloads both base images, so give it a few minutes. If the builder VM can't resolve host names, which happens a lot when your Mac uses a local Pi-hole for DNS, the script resets the builder with public DNS servers and tries again on its own.

## 4. Install the host collector

```bash
./argus.sh install-collector
```

It asks for your password, then:

- copies `argus-collect.sh` to `/usr/local/libexec/argus/`, owned by root
- creates the inbox at `/Users/Shared/Argus/inbox`
- loads a LaunchDaemon (`com.argus.collect`) that runs as root every 5 minutes and exports the security slice of the unified log
- loads a LaunchAgent (`com.argus.collect.user`) that runs as you every 15 minutes and picks up container logs, launchd jobs and Ollama

The first batch lands in the inbox within a minute. If something looks wrong, check `/var/log/argus-collect.log`. [The host collector](../README.md#the-host-collector) lists everything both jobs do.

## 5. Start Argus

```bash
./argus.sh up
```

This starts the container, waits until the dashboard answers, and prints its address. Then run `./argus.sh open`. It opens the dashboard and signs your browser in with the access token, which lasts 90 days in that browser. Going straight to <http://127.0.0.1:7080> without signing in shows a page asking for the token.

The CrowdSec tab can show `connection refused` for the first minute while CrowdSec finishes its own startup. That's normal and clears by itself.

## 6. Check that it's working

```bash
./argus.sh status
```

You should see the `argus` container running, followed by `dashboard answering`, `collector daemon installed` and `collector agent installed`. macOS findings start appearing in the dashboard once the first collector batch has been read, usually within five minutes.

## Changing settings

Change credentials with `./argus.sh init`, or edit `~/.argus/config/argus.env` directly for any other setting, then run `./argus.sh restart`. Restarting replaces the container, but indicators, CrowdSec state and the feed cache live in volumes and carry over.

To replace the dashboard token, clear `ARGUS_TOKEN` in `argus.env`, run `./argus.sh init` (it generates a new one), then `./argus.sh restart` and `./argus.sh open`.

`$ARGUS_HOME` defaults to `~/.argus`. To use a different folder, set `ARGUS_HOME` in your shell before running `argus.sh`, and keep the path lowercase. The default Mac file system is case-insensitive, so a path like `~/Stuff/Argus` can quietly land in the same folder as another one, and you end up editing an `argus.env` that isn't the one being read. The default path is already lowercase, but nothing checks a custom one for you.

## Where things live

| What | Where |
|---|---|
| Your settings | `~/.argus/config/argus.env` |
| Reports and CSV exports | `~/.argus/data/` |
| Collector inbox | `/Users/Shared/Argus/inbox` |
| Collector script | `/usr/local/libexec/argus/argus-collect.sh` |
| Collector logs | `/var/log/argus-collect.log` and `~/Library/Logs/argus-collect-user.log` |
| Argus and CrowdSec state | container volumes `argus-state`, `argus-cs-config`, `argus-cs-data` |

Two of these are settings: move the inbox with `ARGUS_INBOX` in `argus.env`, and `~/.argus` with `ARGUS_HOME` as described above. The collector script and log paths are fixed.

## Uninstalling

```bash
./argus.sh stream off            # only if you turned on live streaming
./argus.sh uninstall-collector   # removes the LaunchDaemon, LaunchAgent and collector script
./argus.sh destroy               # removes the container and its volumes (asks you to type "destroy")
```

None of these touch your config, your reports or the inbox. Delete `~/.argus` and `/Users/Shared/Argus` yourself if you want those gone too.

## Optional setup

### Pi-hole

Leave `PIHOLE_URL` blank and `argus.sh up` looks for a running container with `pihole` in its name on the default network. Set `PIHOLE_PASSWORD` to an app password from Pi-hole's Settings → Web interface / API.

### IntelOwl

Apple `container` networks are isolated from each other, so Argus can only reach IntelOwl when both are on the same named network. Put IntelOwl's containers on the network Argus uses (`default`, unless you've changed it), find `intelowl-nginx`'s address with `container inspect intelowl-nginx`, and set `INTELOWL_URL` to it. Then paste an API token into `INTELOWL_TOKEN`. If `INTELOWL_URL` is blank, IntelOwl enrichment stays off.

Flagged indicators run the `FREE_TO_USE_ANALYZERS` playbook, up to 50 a day, and each job links back to `http://localhost:7001`.

### Syslog from other devices

Set `ARGUS_SYSLOG_BIND` to the Mac's LAN IP, run `./argus.sh restart`, and point your devices at `<mac-ip>:5514/udp` or `:5515/tcp`. Argus expects RFC 3164 (BSD) format, one message per line. `./argus.sh syslog-test` sends a test line so you can check it arrives.

### Send this Mac's own logs as syslog

```bash
./argus.sh stream on      # stream off | stream status
```

This turns on two feeds:

1. A live copy of the unified log. A root LaunchDaemon (`com.argus.logstream`) runs `log stream`, rewrites each line as RFC 3164 syslog and sends it over TCP to the listener, so CrowdSec sees SSH and sudo failures within seconds instead of waiting for the next five-minute batch. The default, `ARGUS_STREAM_MODE=slice`, sends only the security events. `all` sends the whole default-level log, which runs to hundreds of events a second, so save it for short investigations.
2. Legacy syslogd. It appends `*.* @127.0.0.1:5514` to `/etc/syslog.conf` (keeping a backup) and reloads `syslogd`. On current macOS that only covers the small stream you see in `/var/log/system.log` and `install.log`. Everything else goes to the unified log, which the first feed already handles.

`stream on` also sets `ARGUS_MACOS_TO_CROWDSEC=0` and restarts Argus so CrowdSec doesn't count the same event twice. The five-minute collector keeps running and still feeds the dashboard's macOS views. `stream off` puts everything back the way it was.

## Next

[Everyday commands](../README.md#everyday-commands), [Security hardening](../README.md#security-hardening) and [Known limits](../README.md#known-limits) are in the README.
