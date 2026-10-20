#!/bin/bash
# =============================================================================
# argus.sh — build and run the Argus log-analysis container on Apple's
# `container` runtime, and install the host collector.
#
#   ./argus.sh init                 create $ARGUS_HOME (default ~/.argus), config, bouncer key
#   ./argus.sh build                build the image (argus:latest); fixes builder DNS if needed
#   ./argus.sh builder-reset        recreate the builder VM with ARGUS_BUILD_DNS servers
#   ./argus.sh up | down | restart  start / stop the container
#   ./argus.sh install-collector    install the root LaunchDaemon + your LaunchAgent
#   ./argus.sh uninstall-collector
#   ./argus.sh status | logs | shell | open
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
set_env_val() { # KEY VALUE
  if grep -qE "^$1=" "$ENV_FILE"; then
    sed -i '' "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
  fi
}

preflight() {
  [ "$(uname -s)" = "Darwin" ] || die "run this on the Mac"
  command -v container >/dev/null || die "Apple's 'container' CLI not found (https://github.com/apple/container)"
  container system status >/dev/null 2>&1 || { log "starting container services"; container system start; }
  [ -f "$ENV_FILE" ] || die "no config yet: run ./argus.sh init"
}

exists()  { container inspect "$1" >/dev/null 2>&1; }
running() { container list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$1"; }
container_ip() { # first IPv4 of a container
  # shellcheck disable=SC2020
  container inspect "$1" 2>/dev/null | tr ',{}' '\n\n\n' | grep -m1 -o '"ipv4Address" *: *"[0-9.]*' | grep -o '[0-9.]*$' || true
}
host_tz() { readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##'; }

# ------------------------------------------------------------------ commands
cmd_init() {
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
  ok "Argus home: $ARGUS_HOME"
  echo "    edit $ENV_FILE (Pi-hole password, IntelOwl token, optional API keys), then:"
  echo "    ./argus.sh build && ./argus.sh install-collector && ./argus.sh up"
}

# Recreate the builder VM with explicit nameservers. Its default resolver is the
# host, which fails when the Mac's DNS points at a local Pi-hole or after network changes.
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
  printf '    waiting for the dashboard '
  local i
  for i in $(seq 1 90); do
    if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then echo; ok "dashboard: http://127.0.0.1:${port}"; break; fi
    printf '.'; sleep 2
    [ "$i" = 90 ] && { echo; warn "not answering yet; check ./argus.sh logs"; }
  done
  if [ "$(env_val ARGUS_SYSLOG 1)" = "1" ]; then
    ok "syslog: udp ${bind}:${udp}  tcp ${bind}:${tcp}"
  fi
  [ -f "$DAEMON_PLIST" ] || warn "host collector not installed: ./argus.sh install-collector"
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
  local inbox; inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"
  [ -f "$inbox/meta.json" ] && echo "    inbox: $(cat "$inbox/meta.json")"
}

cmd_install_collector() {
  [ -f "$ENV_FILE" ] || die "run ./argus.sh init first"
  local inbox me uid
  inbox="$(env_val ARGUS_INBOX /Users/Shared/Argus/inbox)"
  me="$(id -un)"; uid="$(id -u)"
  log "installing collector to $LIBEXEC (root-owned)"
  sudo mkdir -p "$LIBEXEC"
  sudo install -o root -g wheel -m 0755 "$REPO/collector/argus-collect.sh" "$LIBEXEC/argus-collect.sh"

  log "preparing inbox $inbox"
  sudo mkdir -p "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/.state" "$inbox/user" "$inbox/containers" "$inbox/apps"
  sudo chown root:wheel "$(dirname "$inbox")" "$inbox" "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/.state"
  sudo chown "$me":staff "$inbox/user" "$inbox/containers" "$inbox/apps"
  sudo chmod 0755 "$(dirname "$inbox")" "$inbox" "$inbox/unified" "$inbox/snapshots" "$inbox/crash" "$inbox/user" "$inbox/containers" "$inbox/apps"
  sudo chmod 0700 "$inbox/.state"

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
  <dict><key>ARGUS_INBOX</key><string>$inbox</string></dict>
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
  ok "collector running: system every 5 min (log /var/log/argus-collect.log), user every 15 min"
  echo "    first unified-log batch appears in $inbox/unified within a minute"
}

cmd_uninstall_collector() {
  log "removing collector"
  sudo launchctl bootout "system/$DAEMON_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$(id -u)/$AGENT_LABEL" >/dev/null 2>&1 || true
  sudo rm -f "$DAEMON_PLIST"; rm -f "$AGENT_PLIST"
  sudo rm -rf "$LIBEXEC"
  ok "collector removed (inbox left in place; delete it yourself if you want)"
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
  [ -f "$ENV_FILE" ] || die "run ./argus.sh init first"
  [ "$(env_val ARGUS_SYSLOG 1)" = "1" ] || die "the syslog listener is off (ARGUS_SYSLOG=0 in argus.env)"
  local dest tcp udp mode
  dest="$(stream_target)"
  tcp="$(env_val ARGUS_SYSLOG_TCP_PORT 5515)"
  udp="$(env_val ARGUS_SYSLOG_UDP_PORT 5514)"
  mode="$(env_val ARGUS_STREAM_MODE slice)"
  [ "$mode" = "all" ] && warn "ARGUS_STREAM_MODE=all ships the whole unified log: hundreds of events/s, gigabytes per day"

  log "unified log ($mode) -> $dest:$tcp/tcp via LaunchDaemon $STREAM_LABEL"
  sudo mkdir -p "$LIBEXEC"
  sudo install -o root -g wheel -m 0755 "$REPO/collector/argus-logstream.sh" "$LIBEXEC/argus-logstream.sh"
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
cmd_open()  { open "http://127.0.0.1:$(env_val ARGUS_HTTP_PORT 7080)"; }

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
  echo "$ARGUS_HOME (config, reports) is kept."
  printf 'Type "destroy" to continue: '; read -r a
  [ "$a" = "destroy" ] || die "aborted"
  cmd_down
  local v; for v in $VOLUMES; do container volume delete "$v" >/dev/null 2>&1 && ok "deleted volume $v" || true; done
}

case "${1:-}" in
  init) cmd_init ;;
  build) cmd_build ;;
  builder-reset) builder_reset "$(env_val ARGUS_BUILD_DNS '1.1.1.1 9.9.9.9')" ;;
  up|start) cmd_up ;;
  down|stop) cmd_down ;;
  restart) cmd_down; cmd_up ;;
  status) cmd_status ;;
  logs) shift; cmd_logs "$@" ;;
  shell) cmd_shell ;;
  cscli) shift; cmd_cscli "$@" ;;
  open) cmd_open ;;
  install-collector) cmd_install_collector ;;
  uninstall-collector) cmd_uninstall_collector ;;
  stream) shift; cmd_stream "$@" ;;
  syslog-test) cmd_syslog_test ;;
  host-access) cmd_host_access ;;
  destroy) cmd_destroy ;;
  *) awk 'NR > 2 && /^# =====/ { exit } NR > 2' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
