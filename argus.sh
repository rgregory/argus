#!/bin/bash
# =============================================================================
# argus.sh — build and run the Argus log-analysis container on Apple's
# `container` runtime, and install the host collector.
# Step-by-step install guide: docs/INSTALL.md
#
#   ./argus.sh init [--no-prompt]   create $ARGUS_HOME (default ~/.argus), config, keys; asks for credentials
#   ./argus.sh build                build the image (argus:latest); fixes builder DNS if needed
#   ./argus.sh builder-reset        recreate the builder VM with ARGUS_BUILD_DNS servers
#   ./argus.sh up | down | restart  start / stop the container
#   ./argus.sh update               build, restart, roll back automatically if it doesn't come up
#   ./argus.sh rollback             go back to the image before the last update
#   ./argus.sh backup               save acknowledgements and the allow list to data/backups (also nightly)
#   ./argus.sh restore [file]       merge a backup back in (newest if no file given)
#   ./argus.sh install-collector    install the root LaunchDaemon + your LaunchAgent
#   ./argus.sh uninstall-collector
#   ./argus.sh install-telemetry    eslogger + TCC.db LaunchDaemons (then grant Full Disk Access)
#   ./argus.sh uninstall-telemetry | telemetry-status
#   ./argus.sh status | logs | shell | open    (open signs the browser in with ARGUS_TOKEN)
#   ./argus.sh cscli <args>         run cscli inside the container
#   ./argus.sh stream on|off|status live-stream this Mac's logs to the syslog listener
#   ./argus.sh syslog-test          send a test message to the listener
#   ./argus.sh host-access          let containers reach services on this Mac's 127.0.0.1
#   ./argus.sh destroy              remove container + volumes (keeps $ARGUS_HOME)
#
# What the container can touch:
#   read-only : collector inbox, /private/var/log, /Library/Logs, ~/Library/Logs
#   read-write: $ARGUS_HOME/data (reports, exports) + its own named volumes
#   root fs   : read-only (ARGUS_READONLY_ROOT=1), tmpfs for /tmp /run /var/log
# =============================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
# Lowercase by design: on the default case-insensitive APFS volume, a
# differently-cased ARGUS_HOME you set yourself (e.g. ~/stuff/argus) can
# silently resolve to the same directory as this default and mask which
# config file is actually being read. Override with your own ARGUS_HOME if
# you want a different location; keep it lowercase to avoid the same trap.
[ -n "${ARGUS_HOME:-}" ] && ARGUS_HOME_SET=1 || ARGUS_HOME_SET=0
ARGUS_HOME="${ARGUS_HOME:-$HOME/.argus}"
CFG_DIR="$ARGUS_HOME/config"
ENV_FILE="$CFG_DIR/argus.env"
RUNTIME_ENV="$CFG_DIR/runtime.env"
DATA_DIR="$ARGUS_HOME/data"
NAME="argus"
IMAGE="${ARGUS_IMAGE:-argus:latest}"
VOLUMES="argus-state argus-cs-config argus-cs-data"
LIBEXEC="/usr/local/libexec/argus"
DAEMON_LABEL="com.argus.collect"
AGENT_LABEL="com.argus.collect.user"
NOTIFY_LABEL="com.argus.notify"
NOTIFY_PLIST="$HOME/Library/LaunchAgents/$NOTIFY_LABEL.plist"
DAEMON_PLIST="/Library/LaunchDaemons/$DAEMON_LABEL.plist"
AGENT_PLIST="$HOME/Library/LaunchAgents/$AGENT_LABEL.plist"
STREAM_LABEL="com.argus.logstream"
STREAM_PLIST="/Library/LaunchDaemons/$STREAM_LABEL.plist"
SYSLOG_CONF="/etc/syslog.conf"
SYSLOG_MARK="# argus-forward (added by argus.sh stream on)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# Where the running container's /data comes from: $ARGUS_HOME/data on the host.
running_home() {
  command -v container >/dev/null 2>&1 || return 0
  container inspect "$NAME" 2>/dev/null | tr ',{}' '\n\n\n' \
    | sed -n 's/.*"source" *: *"\(\/[^"]*\)\/data".*/\1/p' | head -1
}

# ARGUS_HOME wasn't set and the default has no config: adopt the folder the
# running container was started from, so restart/up keep working. Otherwise
# point at any config sitting in a known older location.
resolve_home() {
  [ -f "$ENV_FILE" ] && return 0
  local h; h="$(running_home)"
  if [ -n "$h" ] && [ "$h" != "$ARGUS_HOME" ] && [ -f "$h/config/argus.env" ] && [ "$ARGUS_HOME_SET" != 1 ]; then
    warn "using ARGUS_HOME=$h (the running container's config). Add 'export ARGUS_HOME=$h' to ~/.zshrc to make it explicit"
    ARGUS_HOME="$h"; CFG_DIR="$ARGUS_HOME/config"; ENV_FILE="$CFG_DIR/argus.env"; RUNTIME_ENV="$CFG_DIR/runtime.env"; DATA_DIR="$ARGUS_HOME/data"
  fi
}

# Dies before anything is stopped or changed when there is no config.
require_config() {
  [ -f "$ENV_FILE" ] && return 0
  local c found=""
  for c in "$HOME/sync/containers/argus" "$HOME/.argus" "$(running_home)"; do
    [ -n "$c" ] && [ "$c" != "$ARGUS_HOME" ] && [ -f "$c/config/argus.env" ] && { found="$c"; break; }
  done
  [ -n "$found" ] && die "no config at $ENV_FILE, but there is one in $found. Run: export ARGUS_HOME=$found (and add it to ~/.zshrc). Don't run init; it would start a new config"
  die "no config yet: run ./argus.sh init"
}

# Read KEY from argus.env without sourcing it (values may contain spaces).
env_val() {
  local v
  v="$(grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  v="$(strip_quotes "$v")"
  printf '%s' "${v:-${2:-}}"
}
# argus.env isn't shell-sourced (we grep/cut it, and the container's --env-file parses it
# the same flat way Docker does), so neither strips quotes - a value copied in as "like
# this" or 'like this' would otherwise reach the container with the quote characters baked
# into the literal value. Strip one matching wrapping pair, if present.
strip_quotes() {
  local v="$1"
  case "$v" in
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
  esac
  printf '%s' "$v"
}
set_env_val() { # KEY VALUE - writes the value literally (any character but a newline)
  # awk reads KEY and VALUE from the environment, so pasted secrets containing | & \ or
  # quotes can't break the edit the way they would in a sed expression.
  local tmp
  tmp="$(mktemp "$ENV_FILE.XXXXXX")" || die "can't write next to $ENV_FILE"
  K="$1" V="$2" awk '
    BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
    index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 } next }
    { print }
    END { if (!done) print k "=" v }
  ' "$ENV_FILE" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$ENV_FILE"
}

preflight() {
  [ "$(uname -s)" = "Darwin" ] || die "run this on the Mac"
  command -v container >/dev/null || die "Apple's 'container' CLI not found (https://github.com/apple/container)"
  container system status >/dev/null 2>&1 || { log "starting container services"; container system start; }
  require_config
}

exists()  { container inspect "$1" >/dev/null 2>&1; }
running() { container list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$1"; }
container_ip() { # first IPv4 of a container
  # shellcheck disable=SC2020
  container inspect "$1" 2>/dev/null | tr ',{}' '\n\n\n' | grep -m1 -o '"ipv4Address" *: *"[0-9.]*' | grep -o '[0-9.]*$' || true
}
host_tz() { readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##'; }

# Root runs the collector scripts, so nobody but root may be able to change them: not
# the files, and not any directory on the way to them, because whoever can write a
# directory can rename what's in it and drop in a replacement. Checks every path
# component for a non-root owner, group/other write bits (group wheel is allowed) and
# ACL entries that allow changes. Prints each problem; returns 1 if there are any.
root_only_path() { # PATH
  local p="$1" bad=0 owner group perm m acl
  while :; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      read -r owner group perm <<<"$(stat -f '%Su %Sg %Lp' "$p" 2>/dev/null)"
      m=$((8#${perm:-0}))
      [ "$owner" = root ] || { echo "$p is owned by ${owner:-unknown}, not root"; bad=1; }
      [ $((m & 2)) -eq 0 ] || { echo "$p is writable by every account"; bad=1; }
      if [ $((m & 16)) -ne 0 ] && [ "$group" != wheel ]; then echo "$p is writable by group $group"; bad=1; fi
      acl="$(ls -led "$p" 2>/dev/null | sed 1d | grep -E ' allow .*(write|append|add_file|add_subdirectory|delete_child|chown)' || true)"
      [ -z "$acl" ] || { echo "$p has an ACL that allows changes:$(printf ' %s' $acl)"; bad=1; }
    fi
    [ "$p" = / ] && break
    p="$(dirname "$p")"
  done
  return "$bad"
}

# Install one collector script to $LIBEXEC, then refuse to go on unless root alone can
# change it. On failure, stop any job already pointing at it so root never runs it.
install_root_script() { # SRC NAME LABEL...
  local src="$1" name="$2" problems lbl; shift 2
  sudo mkdir -p "$LIBEXEC"
  sudo chown root:wheel "$LIBEXEC"; sudo chmod 0755 "$LIBEXEC"
  sudo install -o root -g wheel -m 0755 "$src" "$LIBEXEC/$name"
  sudo chmod -N "$LIBEXEC" "$LIBEXEC/$name" 2>/dev/null || true
  if ! problems="$(root_only_path "$LIBEXEC/$name")"; then
    for lbl in "$@"; do sudo launchctl bootout "system/$lbl" >/dev/null 2>&1 || true; done
    printf '%s\n' "$problems" | sed 's/^/    /' >&2
    die "$LIBEXEC/$name could be replaced by a non-root account (above), so it won't be run as root. Fix the listed folders (sudo chown root:wheel <dir> && sudo chmod go-w <dir> && sudo chmod -N <dir>) and run this again."
  fi
  ok "$LIBEXEC/$name: only root can change it or any folder above it"
}

# ------------------------------------------------------------------ commands
# Ask for one setting. Secrets are read without echo. Enter keeps the current value
# (or skips if there isn't one); a single "-" clears it.
ask() { # KEY LABEL HELP [secret]
  local key="$1" label="$2" help="$3" secret="${4:-}" cur v shown
  cur="$(env_val "$key")"
  printf '\n  %s\n' "$label"
  [ -n "$help" ] && printf '  \033[2m%s\033[0m\n' "$help"
  if [ -n "$cur" ]; then
    if [ -n "$secret" ]; then shown="set"; else shown="$cur"; fi
    printf '  [%s] Enter to keep, - to clear: ' "$shown"
  else
    printf '  Enter to skip: '
  fi
  if [ -n "$secret" ]; then IFS= read -rs v || v=""; echo; else IFS= read -r v || v=""; fi
  case "$v" in
    '') ;;
    -)  set_env_val "$key" "" ;;
    *)  set_env_val "$key" "$v" ;;
  esac
}

cmd_init() {
  local prompt=1 k set_list=""
  [ "${1:-}" = "--no-prompt" ] && prompt=0
  [ -t 0 ] || prompt=0
  mkdir -p "$CFG_DIR" "$DATA_DIR/reports" "$DATA_DIR/exports" "$DATA_DIR/config"
  if [ ! -f "$ENV_FILE" ]; then
    cp "$REPO/argus.env.example" "$ENV_FILE"
    ok "created $ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
  if [ -z "$(env_val BOUNCER_KEY_argus)" ]; then
    set_env_val BOUNCER_KEY_argus "$(openssl rand -hex 24)"
    ok "generated CrowdSec bouncer key"
  fi
  if [ -z "$(env_val ARGUS_TOKEN)" ]; then
    set_env_val ARGUS_TOKEN "$(openssl rand -hex 24)"
    ok "generated dashboard access token (./argus.sh open signs you in with it)"
  fi

  if [ "$prompt" = 1 ]; then
    echo
    log "credentials: all optional, Enter skips any of them, re-run ./argus.sh init to change them later"
    printf '\n\033[1mPi-hole\033[0m'
    ask PIHOLE_URL "Pi-hole URL" "blank = find a running container with pihole in its name"
    ask PIHOLE_PASSWORD "Pi-hole app password" "Pi-hole > Settings > Web interface / API > Configure app password (not your login password)" secret
    printf '\n\033[1mIntelOwl\033[0m'
    ask INTELOWL_URL "IntelOwl URL" "blank = off. Must be reachable from the Argus network, e.g. http://<intelowl-nginx address> (container inspect intelowl-nginx)"
    ask INTELOWL_TOKEN "IntelOwl API token" "IntelOwl > Account > API access > Generate token" secret
    printf '\n\033[1mCrowdSec console\033[0m'
    ask ENROLL_KEY "CrowdSec enroll key" "optional: links this CrowdSec to app.crowdsec.net" secret
    printf '\n\033[1mThreat-intel API keys\033[0m (each provider stays off without its key)'
    ask ABUSECH_AUTH_KEY "abuse.ch Auth-Key" "free: https://auth.abuse.ch (needed for the Feodo, URLhaus and ThreatFox feeds)" secret
    ask CROWDSEC_CTI_KEY "CrowdSec CTI key" "free: app.crowdsec.net > Settings > CTI API keys" secret
    ask ABUSEIPDB_KEY "AbuseIPDB key" "free: abuseipdb.com > Account > API" secret
    ask VT_API_KEY "VirusTotal key" "free: virustotal.com > your profile > API key" secret
    ask OTX_API_KEY "AlienVault OTX key" "free: otx.alienvault.com > Settings > API key" secret
    ask GREYNOISE_KEY "GreyNoise key" "free Community key: viz.greynoise.io > Account > API key" secret
    ask URLSCAN_API_KEY "urlscan.io key" "free: urlscan.io > Settings & API > API keys (looks up flagged domains/IPs for malicious scan verdicts)" secret
    echo
  fi

  for k in PIHOLE_PASSWORD INTELOWL_TOKEN ENROLL_KEY ABUSECH_AUTH_KEY CROWDSEC_CTI_KEY ABUSEIPDB_KEY VT_API_KEY OTX_API_KEY GREYNOISE_KEY URLSCAN_API_KEY; do
    [ -n "$(env_val "$k")" ] && set_list="$set_list $k"
  done
  ok "Argus home: $ARGUS_HOME"
  echo "    credentials set:${set_list:- none (Argus runs fine without them)}"
  if exists "$NAME" 2>/dev/null; then
    echo "    Argus is already installed: ./argus.sh restart to apply"
  else
    echo "    next: ./argus.sh build && ./argus.sh install-collector && ./argus.sh up && ./argus.sh open"
    echo "    full guide: docs/INSTALL.md"
  fi
}

builder_reset() {
  local d args=()
  for d in $1; do args+=(--dns "$d"); done
  log "recreating the builder VM with DNS: $1"
  container builder stop >/dev/null 2>&1 || true
  container builder delete --force >/dev/null 2>&1 || true
  container builder start "${args[@]}"
}

cmd_build() {
  command -v container >/dev/null || die "container CLI not found"
  container system status >/dev/null 2>&1 || container system start
  local dns logf
  dns="$(env_val ARGUS_BUILD_DNS '1.1.1.1 9.9.9.9')"
  logf="$(mktemp -t argus-build)"
  log "building $IMAGE (first build pulls crowdsecurity/crowdsec and node:24-alpine)"
  if ! container build -t "$IMAGE" -f "$REPO/image/Dockerfile" "$REPO" 2>&1 | tee "$logf"; then
    if grep -qiE 'DNS|name resolution|could not resolve|EAI_AGAIN|ENOTFOUND' "$logf"; then
      warn "the builder VM could not resolve host names; retrying with its own DNS servers"
      builder_reset "$dns"
      container build -t "$IMAGE" -f "$REPO/image/Dockerfile" "$REPO" || die "build failed again; see the output above"
    else
      rm -f "$logf"; die "build failed; see the output above"
    fi
  fi
  rm -f "$logf"
  ok "built $IMAGE"
}

ensure_volumes() {
  local v
  for v in $VOLUMES; do
    container volume inspect "$v" >/dev/null 2>&1 || { container volume create "$v" >/dev/null; ok "created volume $v"; }
  done
}

write_runtime_env() {
  local pihole_url intelowl_url ip
  # drop comments/blank lines and the keys computed below (duplicates are ambiguous in env files).
  # ARGUS_INBOX is a host-side path used to compute the --mount below; inside the container the
  # inbox is always the mount target (/host/inbox, the util.js default), so it's dropped here too.
  # Every other key (API keys included) passes straight into --env-file, so strip wrapping
  # quotes here too - see strip_quotes above.
  grep -vE '^[[:space:]]*(#|$)' "$ENV_FILE" \
    | grep -vE '^(TZ|ARGUS_MAC_HOST|PIHOLE_URL|INTELOWL_URL|ARGUS_INBOX)=' \
    | sed -E 's/^([A-Za-z_][A-Za-z0-9_]*)="(.*)"$/\1=\2/' \
    | sed -E "s/^([A-Za-z_][A-Za-z0-9_]*)='(.*)'\$/\1=\2/" \
    > "$RUNTIME_ENV"
  pihole_url="$(env_val PIHOLE_URL)"
  if [ -z "$pihole_url" ]; then
    local c
    c="$(container list 2>/dev/null | awk 'NR>1 && tolower($1) ~ /pi-?hole/ {print $1; exit}')"
    if [ -n "$c" ]; then
      ip="$(container_ip "$c")"
      [ -n "$ip" ] && pihole_url="http://$ip" && ok "Pi-hole: container $c at $pihole_url"
    fi
  fi
  # No auto-attach: Apple container networks are isolated from each other, so this only
  # works if IntelOwl's own containers are already on the same network as Argus (default,
  # below). Set INTELOWL_URL in argus.env explicitly once you've confirmed that.
  intelowl_url="$(env_val INTELOWL_URL)"
  {
    echo "TZ=$(host_tz)"
    echo "ARGUS_MAC_HOST=$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
    echo "PIHOLE_URL=$pihole_url"
    echo "INTELOWL_URL=$intelowl_url"
  } >> "$RUNTIME_ENV"
  chmod 600 "$RUNTIME_ENV"
}

cmd_up() {
  preflight
  container image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found: run ./argus.sh build"
  local inbox port bind udp tcp
  inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"
  port="$(env_val ARGUS_HTTP_PORT 7080)"
  bind="$(env_val ARGUS_SYSLOG_BIND 127.0.0.1)"
  udp="$(env_val ARGUS_SYSLOG_UDP_PORT 5514)"
  tcp="$(env_val ARGUS_SYSLOG_TCP_PORT 5515)"
  [ -d "$inbox" ] || warn "inbox $inbox does not exist yet (run ./argus.sh install-collector); mounting an empty folder"
  [ -d "$inbox" ] || sudo mkdir -p "$inbox"
  mkdir -p "$DATA_DIR/reports" "$DATA_DIR/exports" "$DATA_DIR/config"
  ensure_volumes
  write_runtime_env
  if exists "$NAME"; then log "replacing existing container"; container stop "$NAME" >/dev/null 2>&1 || true; container delete "$NAME" >/dev/null 2>&1 || true; fi

  local args=(run -d --name "$NAME"
    --cpus "$(env_val ARGUS_CPUS 2)" --memory "$(env_val ARGUS_MEMORY 2G)"
    --env-file "$RUNTIME_ENV"
    --network default
    --mount "type=bind,source=$inbox,target=/host/inbox,readonly"
    --mount "type=bind,source=$DATA_DIR,target=/data"
    --volume "argus-state:/var/lib/argus"
    --volume "argus-cs-config:/etc/crowdsec"
    --volume "argus-cs-data:/var/lib/crowdsec/data"
    --cap-drop NET_RAW --cap-drop MKNOD --cap-drop SYS_CHROOT --cap-drop AUDIT_WRITE --cap-drop SETFCAP
    -p "127.0.0.1:${port}:7080")
  local d
  for d in $(env_val ARGUS_DNS); do args+=(--dns "$d"); done
  if [ "$(env_val ARGUS_MOUNT_HOST_LOGS 1)" = "1" ]; then
    args+=(--mount "type=bind,source=/private/var/log,target=/host/var/log,readonly"
           --mount "type=bind,source=/Library/Logs,target=/host/Library/Logs,readonly"
           --mount "type=bind,source=$HOME/Library/Logs,target=/host/home/Library/Logs,readonly")
  fi
  if [ "$(env_val ARGUS_READONLY_ROOT 1)" = "1" ]; then
    args+=(--read-only --tmpfs /tmp --tmpfs /run --tmpfs /var/log)
  fi
  if [ "$(env_val ARGUS_SYSLOG 1)" = "1" ]; then
    args+=(-p "${bind}:${udp}:5514/udp" -p "${bind}:${tcp}:5515/tcp")
  fi
  args+=("$IMAGE")

  log "starting $NAME"
  container "${args[@]}" >/dev/null
  UP_OK=0
  printf '    waiting for the dashboard '
  local i
  for i in $(seq 1 90); do
    if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then echo; UP_OK=1; ok "dashboard: http://127.0.0.1:${port} (./argus.sh open signs you in)"; break; fi
    printf '.'; sleep 2
    [ "$i" = 90 ] && { echo; warn "not answering yet; check ./argus.sh logs"; }
  done
  if [ "$(env_val ARGUS_SYSLOG 1)" = "1" ]; then
    ok "syslog: udp ${bind}:${udp}  tcp ${bind}:${tcp}"
  fi
  [ -f "$DAEMON_PLIST" ] || warn "host collector not installed: ./argus.sh install-collector"
  [ -n "$(env_val ARGUS_TOKEN)" ] || warn "no ARGUS_TOKEN: anything on this Mac can read the dashboard. Run ./argus.sh init, then ./argus.sh restart"
}

PREV_IMAGE="${IMAGE%:*}:prev"

# Build, keep the running image as :prev, restart, and go back to :prev if the
# new one doesn't answer. A failed build changes nothing: the old container keeps running.
cmd_update() {
  preflight
  local had=0
  if container image inspect "$IMAGE" >/dev/null 2>&1; then
    container image tag "$IMAGE" "$PREV_IMAGE" >/dev/null 2>&1 && had=1 || warn "couldn't keep a copy of the current image; no rollback point"
  fi
  cmd_build
  cmd_down
  cmd_up
  if [ "$UP_OK" = 1 ]; then ok "updated$( [ "$had" = 1 ] && echo "; the previous image is kept as $PREV_IMAGE (./argus.sh rollback)")"; return 0; fi
  [ "$had" = 1 ] || die "the new image didn't come up and there's no previous image to go back to; check ./argus.sh logs"
  warn "the new image didn't answer; going back to the previous one"
  container logs "$NAME" 2>/dev/null | tail -20 >&2 || true
  container image tag "$PREV_IMAGE" "$IMAGE" >/dev/null 2>&1 || die "couldn't restore $PREV_IMAGE"
  cmd_down; cmd_up
  [ "$UP_OK" = 1 ] && die "update failed; rolled back to the previous image (the log lines above show why)" || die "update failed and the previous image didn't answer either; check ./argus.sh logs"
}

cmd_rollback() {
  preflight
  container image inspect "$PREV_IMAGE" >/dev/null 2>&1 || die "no previous image ($PREV_IMAGE); it's kept by ./argus.sh update"
  container image tag "$PREV_IMAGE" "$IMAGE" >/dev/null 2>&1 || die "couldn't tag $PREV_IMAGE as $IMAGE"
  cmd_down; cmd_up
  [ "$UP_OK" = 1 ] && ok "running the previous image" || die "the previous image didn't answer; check ./argus.sh logs"
}

cmd_down() {
  command -v container >/dev/null || die "container CLI not found"
  if exists "$NAME"; then
    log "stopping $NAME"
    container stop "$NAME" >/dev/null 2>&1 || true
    container delete "$NAME" >/dev/null 2>&1 || true
    ok "stopped (volumes and $ARGUS_HOME kept)"
  else
    ok "not running"
  fi
}

cmd_status() {
  container list --all 2>/dev/null | awk -v n="$NAME" 'NR==1 || $1==n'
  local port; port="$(env_val ARGUS_HTTP_PORT 7080)"
  if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then ok "dashboard answering on http://127.0.0.1:${port}"; else warn "dashboard not answering"; fi
  if [ -f "$DAEMON_PLIST" ]; then
    ok "collector daemon installed ($(sudo -n launchctl print "system/$DAEMON_LABEL" 2>/dev/null | awk -F'= ' '/last exit code/ {print "last exit " $2; exit}' || echo 'status needs sudo'))"
  else warn "collector daemon not installed"; fi
  if [ -f "$AGENT_PLIST" ]; then ok "collector agent installed"; else warn "collector agent not installed"; fi
  local inbox last age have want problems
  inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"
  [ -f "$inbox/meta.json" ] && echo "    inbox: $(cat "$inbox/meta.json")"
  if [ -f "$DAEMON_PLIST" ]; then
    # a git pull updates the repo copy, not the one root runs
    have="$(/bin/bash "$LIBEXEC/argus-collect.sh" version 2>/dev/null || true)"
    want="$(/bin/bash "$REPO/collector/argus-collect.sh" version 2>/dev/null || true)"
    if [ -n "$want" ] && [ "$have" != "$want" ]; then
      warn "installed collector is ${have:-missing}, this repo has $want: run ./argus.sh install-collector"
    fi
    if problems="$(root_only_path "$LIBEXEC/argus-collect.sh")"; then ok "collector path is root-only"
    else printf '%s\n' "$problems" | sed 's/^/    /' >&2; warn "the collector could be replaced by a non-root account: see above"; fi
    # macOS lets you switch background jobs off under Login Items without uninstalling them
    last="$(sed -n 's/.*"system_last_run":\([0-9]*\).*/\1/p' "$inbox/meta.json" 2>/dev/null)"
    if [ -n "$last" ]; then
      age=$(( $(date +%s) - last ))
      [ "$age" -le 900 ] || warn "the root collector last ran $((age / 60)) min ago. Is it switched off in System Settings > General > Login Items & Extensions?"
    fi
  fi
}

cmd_install_collector() {
  require_config
  local inbox me uid
  inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"
  me="$(id -un)"; uid="$(id -u)"
  log "installing collector to $LIBEXEC (root-owned)"
  install_root_script "$REPO/collector/argus-collect.sh" argus-collect.sh "$DAEMON_LABEL"

  log "preparing inbox $inbox"
  local spool; spool="$(dirname "$inbox")/spool"
  sudo mkdir -p "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/.state" "$inbox/user" "$inbox/containers" "$inbox/apps" "$inbox/es" "$inbox/ls" "$spool"
  sudo chown root:wheel "$(dirname "$inbox")" "$inbox" "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/.state" "$inbox/es" "$inbox/ls" "$spool"
  sudo chown "$me":staff "$inbox/user" "$inbox/containers" "$inbox/apps"
  sudo chmod 0755 "$(dirname "$inbox")" "$inbox" "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/user" "$inbox/containers" "$inbox/apps" "$inbox/es" "$inbox/ls"
  sudo chmod 0700 "$inbox/.state" "$spool"
  # Lock the inbox to root and you. The folder itself is root-only (0700), and a
  # single ACL entry lets your account list and enter it. Any other account stops
  # at this folder, whatever the modes of the files inside. The container reads
  # the inbox through your account, so it still has access.
  sudo chmod 0700 "$inbox"
  sudo chmod -N "$inbox"
  sudo chmod +a "user:$me allow list,search,readattr,readextattr,readsecurity" "$inbox"
  ok "inbox readable by root and $me only"

  log "writing $DAEMON_PLIST"
  sudo tee "$DAEMON_PLIST" >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$DAEMON_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$LIBEXEC/argus-collect.sh</string><string>system</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>ARGUS_INBOX</key><string>$inbox</string><key>ARGUS_USER</key><string>$me</string><key>ARGUS_SPOOL</key><string>$spool</string></dict>
  <key>StartInterval</key><integer>300</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>/var/log/argus-collect.log</string>
  <key>StandardErrorPath</key><string>/var/log/argus-collect.log</string>
</dict>
</plist>
EOF
  sudo chown root:wheel "$DAEMON_PLIST"; sudo chmod 0644 "$DAEMON_PLIST"
  sudo launchctl bootout "system/$DAEMON_LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$DAEMON_PLIST"

  log "writing $AGENT_PLIST"
  mkdir -p "$(dirname "$AGENT_PLIST")"
  cat > "$AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$LIBEXEC/argus-collect.sh</string><string>user</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>ARGUS_INBOX</key><string>$inbox</string></dict>
  <key>StartInterval</key><integer>900</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/argus-collect-user.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/argus-collect-user.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$uid/$AGENT_LABEL" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$uid" "$AGENT_PLIST"

  # macOS notifications for alerts: launchd runs the notifier the moment the
  # container appends to data/alerts/outbox.tsv.
  log "writing $NOTIFY_PLIST"
  local alerts="$DATA_DIR/alerts" port
  port="$(env_val ARGUS_HTTP_PORT 7080)"
  sudo install -o root -g wheel -m 0755 "$REPO/collector/argus-notify.sh" "$LIBEXEC/argus-notify.sh"
  mkdir -p "$alerts" "$HOME/Library/Application Support/Argus"
  # start from the end so old alerts are not replayed
  stat -f %z "$alerts/outbox.tsv" 2>/dev/null > "$HOME/Library/Application Support/Argus/notify.offset" || echo 0 > "$HOME/Library/Application Support/Argus/notify.offset"
  cat > "$NOTIFY_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$NOTIFY_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$LIBEXEC/argus-notify.sh</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>ARGUS_ALERTS</key><string>$alerts</string><key>ARGUS_URL</key><string>http://127.0.0.1:$port/</string></dict>
  <key>WatchPaths</key><array><string>$alerts</string></array>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/argus-notify.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/argus-notify.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$uid/$NOTIFY_LABEL" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$uid" "$NOTIFY_PLIST"
  ok "alert notifier watching $alerts (test it from Sources & feeds › Alerts › Send a test)"
  ok "collector running: system every 5 min (log /var/log/argus-collect.log), user every 15 min"
  echo "    first unified-log batch appears in $inbox/unified within a minute"
}

cmd_uninstall_collector() {
  log "removing collector"
  sudo launchctl bootout "system/$DAEMON_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)/$AGENT_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)/$NOTIFY_LABEL" >/dev/null 2>&1 || true
  sudo rm -f "$DAEMON_PLIST"; rm -f "$AGENT_PLIST" "$NOTIFY_PLIST"
  sudo rm -rf "$LIBEXEC"
  ok "collector removed (inbox left in place; delete it yourself if you want)"
}

# ------------------------------------------------- extra telemetry
# eslogger and sqlite3 are launched directly by launchd so each is its own
# "responsible process" for TCC: Full Disk Access is granted to those two Apple
# binaries only (not to bash or Terminal). Without the grant they fail closed.
ES_WANT="exec btm_launch_item_add btm_launch_item_remove authentication xp_malware_detected xp_malware_remediated sudo su profile_add profile_remove tcc_modify openssh_login screensharing_attach login_login"

cmd_install_telemetry() {
  require_config
  local inbox me home avail ev events=() xml=""
  inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"; me="$(id -un)"; home="$HOME"
  local SPOOL; SPOOL="$(dirname "$inbox")/spool"
  [ -d "$inbox/snapshots" ] || die "install the collector first: ./argus.sh install-collector"
  avail="$(/usr/bin/eslogger --list-events 2>/dev/null || true)"
  for ev in $(env_val ARGUS_ES_EVENTS "$ES_WANT"); do
    if printf '%s\n' "$avail" | grep -qx "$ev"; then events+=("$ev"); else warn "eslogger on this macOS has no '$ev' event; skipping it"; fi
  done
  [ "${#events[@]}" -gt 0 ] || die "eslogger offered none of the wanted events"
  for ev in "${events[@]}"; do xml="$xml<string>$ev</string>"; done

  log "writing $ES_PLIST (events: ${events[*]})"
  sudo mkdir -p "$SPOOL"; sudo chown root:wheel "$SPOOL"; sudo chmod 0700 "$SPOOL"
  sudo tee "$ES_PLIST" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$ES_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/eslogger</string><string>--format</string><string>json</string>$xml</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>5</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>$SPOOL/es.ndjson</string>
  <key>StandardErrorPath</key><string>/var/log/argus-eslogger.log</string>
</dict>
</plist>
PLIST
  sudo chown root:wheel "$ES_PLIST"; sudo chmod 0644 "$ES_PLIST"
  sudo launchctl bootout "system/$ES_LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$ES_PLIST"

  log "writing $TCC_PLIST (hourly read-only copy of the system and your TCC.db)"
  local q="SELECT service, client, client_type, auth_value, auth_reason, last_modified, IFNULL(indirect_object_identifier,'') FROM access;"
  # Per-user TCC.db only exists on some macOS releases; include it only when present.
  local udb="$home/Library/Application Support/com.apple.TCC/TCC.db" user_xml=""
  if sudo test -f "$udb"; then
    user_xml="    <string>-cmd</string><string>.open --readonly '$udb'</string>
    <string>-cmd</string><string>.output '$inbox/snapshots/tcc-user.tsv'</string>
    <string>-cmd</string><string>$q</string>"
  else
    warn "no per-user TCC.db on this macOS; reading the system database only"
    sudo rm -f "$inbox/snapshots/tcc-user.tsv"
  fi
  sudo tee "$TCC_PLIST" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$TCC_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/sqlite3</string><string>-batch</string>
    <string>-cmd</string><string>.mode tabs</string>
    <string>-cmd</string><string>.open --readonly '/Library/Application Support/com.apple.TCC/TCC.db'</string>
    <string>-cmd</string><string>.output '$inbox/snapshots/tcc-system.tsv'</string>
    <string>-cmd</string><string>$q</string>
$user_xml
    <string>-cmd</string><string>.output stdout</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Umask</key><integer>18</integer>
  <key>StandardInPath</key><string>/dev/null</string>
  <key>StandardOutPath</key><string>/var/log/argus-tcc.log</string>
  <key>StandardErrorPath</key><string>/var/log/argus-tcc.log</string>
</dict>
</plist>
PLIST
  sudo chown root:wheel "$TCC_PLIST"; sudo chmod 0644 "$TCC_PLIST"
  sudo launchctl bootout "system/$TCC_LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$TCC_PLIST"

  ok "installed. Now grant Full Disk Access (System Settings > Privacy & Security > Full Disk Access > +,"
  echo "    then Cmd-Shift-G) to exactly these two Apple binaries:"
  echo "      /usr/bin/eslogger"
  echo "      /usr/bin/sqlite3"
  echo "    then: sudo launchctl kickstart -k system/$ES_LABEL && sudo launchctl kickstart -k system/$TCC_LABEL"
  echo "    check: ./argus.sh telemetry-status"
}

cmd_uninstall_telemetry() {
  local SPOOL; SPOOL="$(dirname "$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)")/spool"
  log "removing eslogger + TCC jobs"
  sudo launchctl bootout "system/$ES_LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootout "system/$TCC_LABEL" >/dev/null 2>&1 || true
  sudo rm -f "$ES_PLIST" "$TCC_PLIST"
  ok "removed (spool $SPOOL left in place; remove the two Full Disk Access entries yourself)"
}

cmd_telemetry_status() {
  local inbox SPOOL; inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"; SPOOL="$(dirname "$inbox")/spool"
  if [ -f "$ES_PLIST" ]; then
    ok "eslogger job installed"
    sudo -n tail -n 3 /var/log/argus-eslogger.log 2>/dev/null | sed 's/^/      /'
    sudo -n ls -la "$SPOOL" 2>/dev/null | sed 's/^/      /' || echo "      (spool listing needs sudo)"
    echo "    es chunks: $(find "$inbox/es" -name '*.ndjson' 2>/dev/null | wc -l | tr -d ' ')"
  else warn "eslogger job not installed"; fi
  if [ -f "$TCC_PLIST" ]; then
    ok "TCC job installed"
    for f in tcc-system.tsv tcc-user.tsv; do
      if [ "$f" = tcc-user.tsv ] && [ ! -e "$inbox/snapshots/$f" ]; then echo "    $f: not used (no per-user TCC.db on this macOS)"; continue; fi
      if [ -s "$inbox/snapshots/$f" ]; then echo "    $f: $(wc -l < "$inbox/snapshots/$f" | tr -d ' ') rows"; else warn "$f empty: sqlite3 lacks Full Disk Access?"; fi
    done
  else warn "TCC job not installed"; fi
}

# ------------------------------------------------------------- live stream
stream_target() { # where the Mac sends syslog: the listener's bind address
  local b; b="$(env_val ARGUS_SYSLOG_BIND 127.0.0.1)"
  [ "$b" = "0.0.0.0" ] && b=127.0.0.1
  printf '%s' "$b"
}

restart_if_running() {
  if exists "$NAME"; then log "restarting $NAME to apply ARGUS_MACOS_TO_CROWDSEC"; cmd_down; cmd_up; fi
}

stream_on() {
  require_config
  [ "$(env_val ARGUS_SYSLOG 1)" = "1" ] || die "the syslog listener is off (ARGUS_SYSLOG=0 in argus.env)"
  local dest tcp udp mode
  dest="$(stream_target)"
  tcp="$(env_val ARGUS_SYSLOG_TCP_PORT 5515)"
  udp="$(env_val ARGUS_SYSLOG_UDP_PORT 5514)"
  mode="$(env_val ARGUS_STREAM_MODE slice)"
  [ "$mode" = "all" ] && warn "ARGUS_STREAM_MODE=all ships the whole unified log: hundreds of events/s, gigabytes per day"

  log "unified log ($mode) -> $dest:$tcp/tcp via LaunchDaemon $STREAM_LABEL"
  install_root_script "$REPO/collector/argus-logstream.sh" argus-logstream.sh "$STREAM_LABEL"
  sudo tee "$STREAM_PLIST" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$STREAM_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$LIBEXEC/argus-logstream.sh</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>ARGUS_STREAM_MODE</key><string>$mode</string>
    <key>ARGUS_STREAM_HOST</key><string>$dest</string>
    <key>ARGUS_STREAM_TCP_PORT</key><string>$tcp</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>/var/log/argus-logstream.log</string>
  <key>StandardErrorPath</key><string>/var/log/argus-logstream.log</string>
</dict>
</plist>
PLIST
  sudo chown root:wheel "$STREAM_PLIST"; sudo chmod 0644 "$STREAM_PLIST"
  sudo launchctl bootout "system/$STREAM_LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootstrap system "$STREAM_PLIST"

  log "legacy syslogd (the /var/log/system.log stream) -> $dest:$udp/udp"
  if ! grep -qF "$SYSLOG_MARK" "$SYSLOG_CONF" 2>/dev/null; then
    sudo cp "$SYSLOG_CONF" "$SYSLOG_CONF.argus-backup" 2>/dev/null || true
    printf '%s\n*.*\t\t\t\t\t\t@%s:%s\n' "$SYSLOG_MARK" "$dest" "$udp" | sudo tee -a "$SYSLOG_CONF" >/dev/null
  fi
  sudo killall -HUP syslogd 2>/dev/null || true

  set_env_val ARGUS_MACOS_TO_CROWDSEC 0
  ok "streaming; CrowdSec now reads the live copy (5-minute batches still feed the dashboard)"
  restart_if_running
}

stream_off() {
  log "stopping the live stream"
  sudo launchctl bootout "system/$STREAM_LABEL" >/dev/null 2>&1 || true
  sudo rm -f "$STREAM_PLIST" "$LIBEXEC/argus-logstream.sh"
  if grep -qF "$SYSLOG_MARK" "$SYSLOG_CONF" 2>/dev/null; then
    local tmp; tmp="$(mktemp -t argus-syslog)"
    awk -v m="$SYSLOG_MARK" '$0 == m { skip = 1; next } skip { skip = 0; next } { print }' "$SYSLOG_CONF" > "$tmp"
    sudo cp "$tmp" "$SYSLOG_CONF"; rm -f "$tmp"
    sudo killall -HUP syslogd 2>/dev/null || true
    ok "removed the forwarding rule from $SYSLOG_CONF"
  fi
  if [ -f "$ENV_FILE" ]; then set_env_val ARGUS_MACOS_TO_CROWDSEC 1; fi
  restart_if_running
}

stream_status() {
  if [ -f "$STREAM_PLIST" ]; then ok "live stream installed ($(env_val ARGUS_STREAM_MODE slice) mode)"; else warn "live stream not installed"; fi
  if grep -qF "$SYSLOG_MARK" "$SYSLOG_CONF" 2>/dev/null; then
    ok "syslogd forwarding: $(grep -A1 -F "$SYSLOG_MARK" "$SYSLOG_CONF" | tail -n 1 | tr -s '\t' ' ')"
  else
    warn "syslogd forwarding not configured"
  fi
  if [ -r /var/log/argus-logstream.log ]; then
    echo "    last log lines:"; tail -n 3 /var/log/argus-logstream.log | sed 's/^/      /'
  fi
}

cmd_stream() {
  case "${1:-status}" in
    on) stream_on ;;
    off) stream_off ;;
    status) stream_status ;;
    *) die "usage: ./argus.sh stream on|off|status" ;;
  esac
}

cmd_logs()  { container logs -n "${1:-200}" -f "$NAME"; }
cmd_shell() { container exec -it "$NAME" /bin/bash; }
cmd_cscli() { container exec "$NAME" cscli "$@"; }
# POST to the dashboard API; the token (if any) goes in a header, never in the URL.
api_post() {
  local tok; tok="$(env_val ARGUS_TOKEN)"
  curl -fsS -X POST -H 'Content-Type: application/json' ${tok:+-H "Authorization: Bearer $tok"} \
    -d "$2" "http://127.0.0.1:$(env_val ARGUS_HTTP_PORT 7080)$1"
}

# Acknowledgements and the allow list, to $ARGUS_HOME/data/backups (also written nightly).
cmd_backup() {
  require_config; running "$NAME" || die "argus isn't running: ./argus.sh up"
  local out; out="$(api_post /api/triage/backup '{}')" || die "backup failed; see ./argus.sh logs"
  ok "wrote $DATA_DIR/backups/$(printf '%s' "$out" | sed -n 's/.*"file":"\([^"]*\)".*/\1/p')"
}

# Merges a triage backup back in (adds missing entries, keeps whatever is newer).
cmd_restore() {
  require_config; running "$NAME" || die "argus isn't running: ./argus.sh up"
  local f="${1:-}"
  if [ -z "$f" ]; then
    f="$(ls -t "$DATA_DIR"/backups/triage-*.json 2>/dev/null | head -1)"
    [ -n "$f" ] || die "no backups in $DATA_DIR/backups"
    log "restoring the newest backup, $(basename "$f")"
  fi
  [ -f "$f" ] || f="$DATA_DIR/backups/$f"
  [ -f "$f" ] || die "no such file: ${1:-}"
  case "$(cd "$(dirname "$f")" && pwd)" in "$DATA_DIR/backups") ;; *) cp "$f" "$DATA_DIR/backups/" || die "couldn't copy $f into $DATA_DIR/backups" ;; esac
  local out; out="$(api_post /api/triage/restore "{\"file\":\"$(basename "$f")\"}")" || die "restore failed; see ./argus.sh logs"
  ok "restored: $(printf '%s' "$out" | sed -n 's/.*"acks":\([0-9]*\).*"allow":\([0-9]*\).*/\1 acknowledgement(s), \2 allow-list entries/p')"
}

cmd_open()  { # signs the browser in: the server swaps ?token= for a cookie and redirects
  local tok; tok="$(env_val ARGUS_TOKEN)"
  open "http://127.0.0.1:$(env_val ARGUS_HTTP_PORT 7080)/${tok:+?token=$tok}"
}

cmd_syslog_test() {
  local port; port="$(env_val ARGUS_SYSLOG_UDP_PORT 5514)"
  # macOS logger(1) cannot send to a remote host, so hand-build an RFC 3164 line.
  printf '<14>%s %s argus-test: test message from %s\n' "$(LC_ALL=C date '+%b %e %H:%M:%S')" "$(hostname -s)" "$(whoami)" \
    | nc -u -w1 127.0.0.1 "$port"
  ok "sent; it shows under Syslog in the dashboard within ~30 s"
}

cmd_host_access() {
  log "creating host.container.internal -> this Mac's 127.0.0.1 (needs sudo)"
  warn "this turns off iCloud Private Relay and is removed on reboot (Apple runtime limitation)"
  sudo container system dns create host.container.internal --localhost 203.0.113.113
  ok "containers can now reach services published on 127.0.0.1 via host.container.internal"
}

cmd_destroy() {
  echo "This deletes the $NAME container and volumes: $VOLUMES (indicators, CrowdSec state, feed cache)."
  echo "$ARGUS_HOME (config, reports, triage backups) is kept; acknowledgements and the allow list are backed up first."
  printf 'Type "destroy" to continue: '; read -r a
  [ "$a" = "destroy" ] || die "aborted"
  if running "$NAME" && [ -f "$ENV_FILE" ]; then cmd_backup || warn "couldn't back up acknowledgements and the allow list first"; fi
  cmd_down
  local v; for v in $VOLUMES; do container volume delete "$v" >/dev/null 2>&1 && ok "deleted volume $v" || true; done
}

case "${1:-}" in init) ;; *) resolve_home ;; esac

case "${1:-}" in
  init) shift; cmd_init "$@" ;;
  build) cmd_build ;;
  builder-reset) builder_reset "$(env_val ARGUS_BUILD_DNS '1.1.1.1 9.9.9.9')" ;;
  up|start) cmd_up ;;
  down|stop) cmd_down ;;
  update) cmd_update ;;
  backup) cmd_backup ;;
  restore) shift; cmd_restore "${1:-}" ;;
  rollback) cmd_rollback ;;
  restart) preflight; container image inspect "$IMAGE" >/dev/null 2>&1 || die "image $IMAGE not found: run ./argus.sh build"; cmd_down; cmd_up ;;
  status) cmd_status ;;
  logs) shift; cmd_logs "$@" ;;
  shell) cmd_shell ;;
  cscli) shift; cmd_cscli "$@" ;;
  open) cmd_open ;;
  install-collector) cmd_install_collector ;;
  install-telemetry) cmd_install_telemetry ;;
  uninstall-telemetry) cmd_uninstall_telemetry ;;
  telemetry-status) cmd_telemetry_status ;;
  uninstall-collector) cmd_uninstall_collector ;;
  stream) shift; cmd_stream "$@" ;;
  syslog-test) cmd_syslog_test ;;
  host-access) cmd_host_access ;;
  destroy) cmd_destroy ;;
  *) awk 'NR > 2 && /^# =====/ { exit } NR > 2' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
