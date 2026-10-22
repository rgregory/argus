#!/bin/bash
# =============================================================================
# argus-collect.sh — host-side collector for Argus (runs on the Mac, not in
# the container). Writes into the inbox the container mounts read-only.
#
#   system   root LaunchDaemon, every 5 min:
#              * security slice of the unified log for the time since the last
#                run (log show --start/--end, so nothing is missed or duplicated)
#              * established TCP connections
#              * hourly snapshots: posture, persistence, listening ports, login
#                history, sleep/wake, install history, crash reports
#   user     your LaunchAgent, every 15 min: Apple container logs, your
#            launchd jobs and crontab, Ollama log
#   once     run both now (asks for sudo for the system part)
#
# Installed by `argus.sh install-collector` to /usr/local/libexec/argus/ as
# root:wheel 0755 (a root job must never run a script the user can edit).
# Compatible with macOS's bash 3.2.
# =============================================================================
set -uo pipefail
VERSION="1.1.0"

INBOX="${ARGUS_INBOX:-/Users/Shared/Argus/inbox}"
MAX_BACKLOG_MIN="${ARGUS_MAX_BACKLOG_MIN:-60}"     # catch-up limit after sleep/reboot
SNAPSHOT_MIN="${ARGUS_SNAPSHOT_MIN:-60}"
INBOX_DAYS="${ARGUS_INBOX_DAYS:-3}"
PIHOLE_QUERYLOG="${ARGUS_PIHOLE_QUERYLOG:-0}"       # 1 = also copy the Pi-hole query log (if not using the API)
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Security-relevant slice of the unified log + all faults.
PREDICATE='process == "sudo" OR process == "authd" OR process == "SecurityAgent"
  OR process == "sshd" OR process == "sshd-session" OR process == "sshd-auth" OR process == "screensharingd"
  OR (process == "loginwindow" AND eventMessage CONTAINS "screenIs")
  OR process == "syspolicyd" OR process BEGINSWITH[c] "xprotect"
  OR process == "socketfilterfw"
  OR subsystem == "com.apple.TCC"
  OR subsystem == "com.apple.backgroundtaskmanagement"
  OR process BEGINSWITH[c] "little snitch" OR process BEGINSWITH[c] "littlesnitch"
  OR subsystem BEGINSWITH[c] "at.obdev.littlesnitch"
  OR messageType == fault'
PREDICATE="$(printf '%s' "$PREDICATE" | tr '\n' ' ')"

log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${MODE:-?}" "$*"; }

# Write stdin to $1 atomically. Files are 0644 so the container (which reads the
# inbox through your account) can open them; the inbox folder itself is
# root + your account only (see lock_inbox), so other accounts can't reach them.
put() {
  local dest="$1" tmp="$1.tmp.$$"
  cat > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$dest"
}

stamp_due() { # name minutes -> 0 if due
  local f="$INBOX/.state/$1.stamp"
  [ -f "$f" ] || return 0
  [ -n "$(find "$f" -mmin +"$2" 2>/dev/null)" ]
}
stamp_set() { mkdir -p "$INBOX/.state"; touch "$INBOX/.state/$1.stamp"; }

# --------------------------------------------------------------------- system
unified_window() {
  local last_f="$INBOX/.state/unified.last" now end start s e day out
  now=$(date +%s); end=$((now - 5))
  start=$(cat "$last_f" 2>/dev/null || echo $((end - 300)))
  case "$start" in ''|*[!0-9]*) start=$((end - 300));; esac
  if [ $((end - start)) -gt $((MAX_BACKLOG_MIN * 60)) ]; then
    log "backlog $(( (end - start) / 60 )) min > ${MAX_BACKLOG_MIN} min; skipping ahead"
    start=$((end - MAX_BACKLOG_MIN * 60))
  fi
  [ "$end" -gt "$start" ] || return 0
  s=$(date -r "$start" '+%Y-%m-%d %H:%M:%S'); e=$(date -r "$end" '+%Y-%m-%d %H:%M:%S')
  day=$(date -r "$start" +%Y%m%d)
  mkdir -p "$INBOX/unified/$day"; chmod 0755 "$INBOX/unified/$day"
  out="$INBOX/unified/$day/$(date -r "$start" +%H%M%S)-$(date -r "$end" +%H%M%S).ndjson"
  if /usr/bin/log show --start "$s" --end "$e" --style ndjson --predicate "$PREDICATE" 2>/dev/null | put "$out"; then
    echo $((end + 1)) > "$last_f"
    log "unified $s → $e: $(wc -l < "$out" | tr -d ' ') lines"
  else
    rm -f "$out"; log "log show failed"
  fi
}

posture() {
  echo "== Host"; scutil --get LocalHostName 2>/dev/null || hostname -s
  echo; echo "== macOS"; sw_vers
  echo; echo "== SIP"; csrutil status 2>&1
  echo; echo "== Gatekeeper"; spctl --status 2>&1
  echo; echo "== FileVault"; fdesetup status 2>&1
  echo; echo "== App firewall"
  /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1
  /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1
  /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>&1
  echo; echo "== Remote Login"
  local rl; rl=$(systemsetup -getremotelogin 2>/dev/null)
  if printf '%s' "$rl" | grep -q 'Remote Login:'; then echo "$rl"
  elif launchctl print-disabled system 2>/dev/null | grep -Eq '"com.openssh.sshd" => (enabled|false)'; then echo "Remote Login: On"
  else echo "Remote Login: Off"; fi
  echo; echo "== Software Update prefs"; defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>&1
}

launch_items() {
  local dirs=(/Library/LaunchAgents /Library/LaunchDaemons) h d f
  for h in /Users/*; do [ -d "$h/Library/LaunchAgents" ] && dirs+=("$h/Library/LaunchAgents"); done
  for d in "${dirs[@]}"; do echo "== $d"; ls -la "$d" 2>&1; echo; done | put "$INBOX/snapshots/launch-dirs.txt"
  for d in "${dirs[@]}"; do
    for f in "$d"/*.plist; do [ -e "$f" ] || continue; echo "== $f"; plutil -p "$f" 2>&1; echo; done
  done | put "$INBOX/snapshots/launch-plists.txt"
}

snapshots() {
  local S="$INBOX/snapshots"
  posture | put "$S/posture.txt"
  launch_items
  sfltool dumpbtm 2>&1 | put "$S/background-items.txt"
  systemextensionsctl list 2>&1 | put "$S/system-extensions.txt"
  profiles list 2>&1 | put "$S/profiles.txt"
  last 2>/dev/null | head -n 400 | put "$S/logins.txt"
  pmset -g log 2>/dev/null | grep -E ' (Sleep|Wake|DarkWake) ' | tail -n 2000 | put "$S/sleep-wake.txt"
  softwareupdate --history 2>&1 | put "$S/update-history.txt"
  tail -n 20000 /var/log/install.log 2>/dev/null | put "$S/install.log"
  lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | put "$S/listening-tcp.txt"
  lsof -nP -iUDP 2>/dev/null | put "$S/listening-udp.txt"
  # crash reports only root can read
  mkdir -p "$INBOX/crash/system"
  find /Library/Logs/DiagnosticReports -maxdepth 2 -type f -mtime -14 \
       \( -name '*.ips' -o -name '*.panic' -o -name '*.diag' -o -name '*.spin' -o -name '*.hang' -o -name '*.crash' \) 2>/dev/null |
  while IFS= read -r f; do
    dest="$INBOX/crash/system/$(basename "$f")"
    [ -e "$dest" ] || { cp "$f" "$dest" && chmod 0644 "$dest"; }
  done
  log "snapshots refreshed"
}

prune() {
  find "$INBOX/unified" -type f -mtime +"$INBOX_DAYS" -delete 2>/dev/null
  find "$INBOX/unified" -mindepth 1 -type d -empty -delete 2>/dev/null
  find "$INBOX/crash" -type f -mtime +14 -delete 2>/dev/null
  find "$INBOX" -name '*.tmp.*' -mmin +60 -delete 2>/dev/null
}

write_meta() {
  local tz host os
  tz=$(readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')
  host=$(scutil --get LocalHostName 2>/dev/null || hostname -s)
  os=$(sw_vers -productVersion 2>/dev/null)
  printf '{"host":"%s","os":"%s","tz":"%s","version":"%s","system_last_run":%s}\n' "$host" "$os" "$tz" "$VERSION" "$(date +%s)" | put "$INBOX/meta.json"
}

# Keep the inbox folder root-only (0700) with one ACL entry for the account that
# installed the collector (ARGUS_USER, set in the root-owned LaunchDaemon plist).
# Re-applied every run in case something loosened it.
lock_inbox() {
  [ -n "${ARGUS_USER:-}" ] || return 0   # never lock without knowing who to let in
  chmod 0700 "$INBOX"
  # ls -le is the only stock way to read a folder's ACL; this greps ACL lines, not file names
  # shellcheck disable=SC2010
  if ! ls -led "$INBOX" 2>/dev/null | grep -q " user:$ARGUS_USER allow "; then
    chmod -N "$INBOX" 2>/dev/null
    chmod +a "user:$ARGUS_USER allow list,search,readattr,readextattr,readsecurity" "$INBOX" &&
      log "inbox ACL restored for $ARGUS_USER"
  fi
}

run_system() {
  [ "$(id -u)" -eq 0 ] || { echo "system mode must run as root" >&2; exit 1; }
  umask 022
  mkdir -p "$INBOX/unified" "$INBOX/snapshots" "$INBOX/crash" "$INBOX/.state"
  lock_inbox
  unified_window
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | put "$INBOX/snapshots/established-tcp.txt"
  if stamp_due snapshots "$SNAPSHOT_MIN"; then snapshots; stamp_set snapshots; fi
  prune
  write_meta
}

# ----------------------------------------------------------------------- user
run_user() {
  [ "$(id -u)" -ne 0 ] || { echo "user mode must run as your account, not root" >&2; exit 1; }
  umask 022
  local C="$INBOX/containers" U="$INBOX/user" A="$INBOX/apps" c
  mkdir -p "$C" "$U" "$A" 2>/dev/null
  launchctl list 2>&1 | put "$U/launchctl-user.txt"
  crontab -l 2>&1 | put "$U/crontab.txt"
  if command -v container >/dev/null 2>&1 && container list --all >/dev/null 2>&1; then
    container list --all 2>&1 | put "$C/_list.txt"
    for c in $(container list --all --quiet 2>/dev/null); do
      container logs -n 5000 "$c" 2>&1 | put "$C/$c.log"
      if [ "$PIHOLE_QUERYLOG" = "1" ]; then
        case "$c" in *pihole*|*pi-hole*)
          container exec "$c" sh -c 'tail -n 100000 /var/log/pihole/pihole.log' 2>/dev/null | put "$C/$c-querylog.txt" ;;
        esac
      fi
    done
    container system logs --last 15m 2>&1 | tail -n 5000 | put "$C/_runtime.log"
  fi
  [ -f "$HOME/.ollama/logs/server.log" ] && tail -n 20000 "$HOME/.ollama/logs/server.log" | put "$A/ollama-server.log"
  printf '{"user":"%s","user_last_run":%s}\n' "$(id -un)" "$(date +%s)" | put "$U/meta.json"
  log "user snapshots refreshed"
}

MODE="${1:-}"
case "$MODE" in
  system) run_system ;;
  user)   run_user ;;
  once)   sudo ARGUS_INBOX="$INBOX" ARGUS_USER="$(id -un)" /bin/bash "$0" system && run_user ;;
  version) echo "$VERSION" ;;
  *) echo "usage: $0 system|user|once" >&2; exit 2 ;;
esac
