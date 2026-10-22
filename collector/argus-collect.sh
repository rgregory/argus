#!/bin/bash
# =============================================================================
# argus-collect.sh — host-side collector for Argus (runs on the Mac, not in
# the container). Writes into the inbox the container mounts read-only.
#
#   system   root LaunchDaemon, every 5 min:
#              * security slice of the unified log for the time since the last
#                run (log show --start/--end, so nothing is missed or duplicated)
#              * established TCP connections + process list
#              * Endpoint Security batches from the eslogger spool (optional job)
#              * Little Snitch traffic history (if installed and Terminal access is on)
#              * hourly snapshots: posture, persistence, listening ports, login
#                history, sleep/wake, install history, crash reports, file
#                integrity hashes, System keychain certificates + trust settings
#   user     your LaunchAgent, every 15 min: Apple container logs, your
#            launchd jobs and crontab, Ollama log, download history; every hour
#            browser extensions and your certificate trust; every 6 h app and
#            Homebrew inventory (brew vulns daily)
#   once     run both now (asks for sudo for the system part)
#
# Installed by `argus.sh install-collector` to /usr/local/libexec/argus/ as
# root:wheel 0755 (a root job must never run a script the user can edit).
# Compatible with macOS's bash 3.2.
# =============================================================================
set -uo pipefail
VERSION="1.3.0"

INBOX="${ARGUS_INBOX:-/Users/Shared/Argus/inbox}"
SPOOL="${ARGUS_SPOOL:-/Users/Shared/Argus/spool}"     # eslogger writes here (root-only)
ES_MAX_MB="${ARGUS_ES_MAX_MB:-64}"                   # most Endpoint Security data shipped per 5-min run
ES_SPOOL_MAX_MB="${ARGUS_ES_SPOOL_MAX_MB:-256}"       # truncate the spool once fully shipped and this big
ES_KEEP_HOURS="${ARGUS_ES_KEEP_HOURS:-12}"
INVENTORY_MIN="${ARGUS_INVENTORY_MIN:-360}"          # app / Homebrew inventory every 6 h
BREW_VULNS_MIN="${ARGUS_BREW_VULNS_MIN:-1440}"       # brew vulns once a day
MAX_BACKLOG_MIN="${ARGUS_MAX_BACKLOG_MIN:-60}"     # catch-up limit after sleep/reboot
SNAPSHOT_MIN="${ARGUS_SNAPSHOT_MIN:-60}"
INBOX_DAYS="${ARGUS_INBOX_DAYS:-3}"
PIHOLE_QUERYLOG="${ARGUS_PIHOLE_QUERYLOG:-0}"       # 1 = also copy the Pi-hole query log (if not using the API)
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Security-relevant slice of the unified log + all faults.
PREDICATE='process == "sudo" OR process == "authd" OR process == "SecurityAgent"
  OR process == "sshd" OR process == "sshd-session" OR process == "sshd-auth" OR process == "screensharingd"
  OR (process == "loginwindow" AND eventMessage CONTAINS "screenIs")
  OR (process == "loginwindow" AND (eventMessage CONTAINS[c] "authentication fail" OR eventMessage CONTAINS[c] "login fail" OR eventMessage CONTAINS[c] "incorrect password"))
  OR (process == "opendirectoryd" AND (eventMessage CONTAINS[c] "authentication fail" OR eventMessage CONTAINS[c] "failed authentication" OR eventMessage CONTAINS[c] "ODRecordVerifyPassword" OR eventMessage CONTAINS[c] "password verification failed"))
  OR process == "syspolicyd" OR process BEGINSWITH[c] "xprotect"
  OR process == "socketfilterfw"
  OR subsystem == "com.apple.TCC"
  OR subsystem == "com.apple.backgroundtaskmanagement"
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
  echo; echo "== Automatic login"
  local al; al=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
  if [ -n "$al" ]; then echo "Automatic login: On ($al)"; else echo "Automatic login: Off"; fi
  echo; echo "== Guest account"
  case "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" in 1) echo "Guest account: On";; *) echo "Guest account: Off";; esac
  echo; echo "== Sharing services"
  local svc dis; dis=$(launchctl print-disabled system 2>/dev/null)
  for svc in com.apple.screensharing com.apple.smbd com.apple.ftp-proxy com.apple.AEServer; do
    if launchctl print "system/$svc" >/dev/null 2>&1 && ! printf '%s' "$dis" | grep -Eq "\"$svc\" => (disabled|true)"; then echo "$svc: loaded"; else echo "$svc: off"; fi
  done
  echo; echo "== Time Machine"
  tmutil destinationinfo 2>&1 | grep -E '^(Name|Kind|Mount Point|ID)|No destinations' | head -n 12
  echo "AutoBackup: $(defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null || echo unknown)"
  local tm; tm=$(defaults read /Library/Preferences/com.apple.TimeMachine 2>/dev/null | grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8} [+-][0-9]{4}' | sort | tail -n 1)
  [ -n "$tm" ] && echo "Last backup: $tm"
  echo; echo "== XProtect"
  defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null | sed 's/^/XProtect version: /'
  stat -f 'XProtect updated: %Sm' -t '%Y-%m-%d %H:%M:%S' /Library/Apple/System/Library/CoreServices/XProtect.bundle 2>/dev/null
}

launch_items() {
  local dirs=(/Library/LaunchAgents /Library/LaunchDaemons) h d f
  for h in /Users/*; do [ -d "$h/Library/LaunchAgents" ] && dirs+=("$h/Library/LaunchAgents"); done
  for d in "${dirs[@]}"; do echo "== $d"; ls -la "$d" 2>&1; echo; done | put "$INBOX/snapshots/launch-dirs.txt"
  for d in "${dirs[@]}"; do
    for f in "$d"/*.plist; do [ -e "$f" ] || continue; echo "== $f"; plutil -p "$f" 2>&1; echo; done
  done | put "$INBOX/snapshots/launch-plists.txt"
}

# File integrity: hashes of files commonly abused for persistence or
# privilege (sudoers, PAM, SSH keys, shell startup files, auth plugins, hooks).
FIM_FILES="/etc/hosts /etc/sudoers /etc/ssh/sshd_config /etc/ssh/ssh_config /etc/profile /etc/zshrc /etc/zprofile /etc/zshenv /etc/bashrc /etc/paths /etc/crontab /etc/rc.common /etc/launchd.conf /etc/pf.conf /etc/auto_master"
FIM_DIRS="/etc/sudoers.d /etc/pam.d /etc/ssh/sshd_config.d /etc/paths.d /etc/periodic /etc/emond.d /private/var/at/tabs /Library/Security/SecurityAgentPlugins /Library/ScriptingAdditions /Library/DirectoryServices/PlugIns /Library/InputManagers"
FIM_HOME=".ssh/authorized_keys .ssh/authorized_keys2 .ssh/config .ssh/rc .ssh/environment .zshrc .zshenv .zprofile .zlogin .zlogout .bashrc .bash_profile .bash_login .profile .config/fish/config.fish .tmux.conf"
fim_line() { # path
  local f="$1" h m
  [ -f "$f" ] && [ ! -L "$f" ] || return 0
  h=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
  m=$(stat -f '%Sp\t%Su\t%m\t%z' "$f" 2>/dev/null)
  printf 'F\t%s\t%s\t%s\n' "${h:-unreadable}" "$m" "$f"
}
fim() {
  local f d h u k
  for f in $FIM_FILES; do fim_line "$f"; done
  for d in $FIM_DIRS; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 6 -type f -size -20M 2>/dev/null | head -n 400 | while IFS= read -r f; do fim_line "$f"; done
  done
  for h in /Users/* /var/root; do
    [ -d "$h" ] && [ "$h" != /Users/Shared ] || continue
    for f in $FIM_HOME; do fim_line "$h/$f"; done
    for k in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [ -f "$k" ] && ssh-keygen -lf "$k" 2>/dev/null | while IFS= read -r l; do printf 'K\t%s\t%s\n' "$k" "$l"; done
    done
  done
  for k in LoginHook LogoutHook; do
    for d in /Library/Preferences/com.apple.loginwindow /var/root/Library/Preferences/com.apple.loginwindow; do
      u=$(defaults read "$d" "$k" 2>/dev/null) && printf 'H\t%s\t%s\t%s\n' "$k" "$d" "$u"
    done
  done
}

# Certificates in the System keychain and certificates with admin trust settings
# (a trusted root added here can intercept TLS for every app).
certs_system() {
  echo "== system.keychain"; security find-certificate -a -Z /Library/Keychains/System.keychain 2>&1
  echo "== admin trust"; security dump-trust-settings -d 2>&1
}

# Wi-Fi network, DNS resolvers and VPN state (every run, so joins and DNS
# changes are seen within 5 minutes). wdutil only shows the SSID to root.
network_state() {
  local m
  echo "== wifi"; wdutil info 2>/dev/null | grep -E '^[[:space:]]+(SSID|BSSID|Security|Interface Name|Power|Primary IPv4|DNS Addresses)[[:space:]]+:' | sed 's/^ *//'
  echo "== dns"; scutil --dns 2>/dev/null | awk '/^resolver #1/{f=1;next} /^resolver #/{f=0} f && /nameserver\[/ {print $3}' | head -n 8
  echo "== route"; route -n get default 2>/dev/null | awk '/interface:|gateway:/ {print $1, $2}'
  echo "== vpn"; scutil --nc list 2>/dev/null | grep -E '\(Connected\)' | sed 's/^ *//' | head -n 5
  for m in /usr/local/bin/mullvad "/Applications/Mullvad VPN.app/Contents/Resources/mullvad"; do
    [ -x "$m" ] && { echo "mullvad: $("$m" status 2>/dev/null | head -n 1)"; break; }
  done
}

# USB and Bluetooth devices (hourly; new ones are reported)
devices() { system_profiler -json -detailLevel mini SPUSBHostDataType SPUSBDataType SPBluetoothDataType 2>/dev/null; }

snapshots() {
  local S="$INBOX/snapshots"
  devices | put "$S/devices.json"
  fim | put "$S/fim.txt"
  certs_system | put "$S/certs-system.txt"
  posture | put "$S/posture.txt"
  launch_items
  sfltool dumpbtm 2>&1 | put "$S/background-items.txt"
  systemextensionsctl list 2>&1 | put "$S/system-extensions.txt"
  profiles list 2>&1 | put "$S/profiles.txt"
  last 2>/dev/null | head -n 400 | put "$S/logins.txt"
  pmset -g log 2>/dev/null | grep -E ' (Sleep|Wake|DarkWake) ' | tail -n 2000 | put "$S/sleep-wake.txt"
  softwareupdate --history 2>&1 | put "$S/update-history.txt"
  if stamp_due softwareupdate-list 360; then
    softwareupdate --list --no-scan 2>&1 | put "$S/software-updates.txt"; stamp_set softwareupdate-list
  fi
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

# Little Snitch traffic history (needs Settings > Security > "Allow access via
# Terminal"). Ships the CSV for the time since the last run, like the unified log.
LS_BIN="${ARGUS_LITTLESNITCH:-}"
ls_ship() {
  local bin="$LS_BIN" lastf="$INBOX/.state/ls.last" now end start s e day out tmp n
  if [ -z "$bin" ]; then
    for bin in /Applications/Little\ Snitch*.app/Contents/Components/littlesnitch; do [ -x "$bin" ] && break; done
  fi
  [ -n "$bin" ] && [ -x "$bin" ] || return 0
  now=$(date +%s); end=$((now - 5))
  start=$(cat "$lastf" 2>/dev/null || echo $((end - 300)))
  case "$start" in ''|*[!0-9]*) start=$((end - 300));; esac
  [ $((end - start)) -gt $((MAX_BACKLOG_MIN * 60)) ] && start=$((end - MAX_BACKLOG_MIN * 60))
  [ "$end" -gt "$start" ] || return 0
  s=$(date -r "$start" '+%Y-%m-%d %H:%M:%S'); e=$(date -r "$end" '+%Y-%m-%d %H:%M:%S')
  day=$(date -r "$start" +%Y%m%d); mkdir -p "$INBOX/ls/$day"; chmod 0755 "$INBOX/ls" "$INBOX/ls/$day"
  out="$INBOX/ls/$day/$(date -r "$start" +%H%M%S)-$(date -r "$end" +%H%M%S).csv"; tmp="$out.tmp.$$"
  if "$bin" log-traffic -b "$s" -e "$e" > "$tmp" 2>/dev/null && head -n 1 "$tmp" | grep -q '^date,direction'; then
    chmod 0644 "$tmp"; mv -f "$tmp" "$out"; echo $((end + 1)) > "$lastf"
    n=$(($(wc -l < "$out") - 1)); log "littlesnitch: $n rows"
  else
    rm -f "$tmp"; stamp_due ls-warn 60 && { log "littlesnitch log-traffic failed (enable Settings > Security > Allow access via Terminal)"; stamp_set ls-warn; }
  fi
}

# Endpoint Security: eslogger (its own LaunchDaemon) appends JSON lines to the
# root-only spool; every run ships the new bytes, cut at the last full line, into
# the inbox. launchd opens the spool with O_APPEND, so truncating it is safe.
es_ship() {
  local spool="$SPOOL/es.ndjson" offf="$INBOX/.state/es.offset" size off len max part day out tmp
  [ -f "$spool" ] || return 0
  size=$(stat -f %z "$spool" 2>/dev/null || echo 0)
  off=$(cat "$offf" 2>/dev/null || echo 0); case "$off" in ''|*[!0-9]*) off=0;; esac
  [ "$size" -lt "$off" ] && off=0
  len=$((size - off)); max=$((ES_MAX_MB * 1048576))
  if [ "$len" -gt "$max" ]; then
    log "es: $((len / 1048576)) MB backlog > ${ES_MAX_MB} MB; skipping $(((len - max) / 1048576)) MB"
    off=$((size - max)); len=$max
  fi
  if [ "$len" -gt 0 ]; then
    day=$(date +%Y%m%d); mkdir -p "$INBOX/es/$day"; chmod 0755 "$INBOX/es/$day"
    out="$INBOX/es/$day/$(date +%H%M%S)-$off.ndjson"; tmp="$out.tmp.$$"
    tail -c +"$((off + 1))" "$spool" | head -c "$len" > "$tmp"
    part=0
    if [ -s "$tmp" ] && [ "$(tail -c 1 "$tmp" | od -An -c | tr -d ' ')" != '\n' ]; then part=$(tail -n 1 "$tmp" | wc -c | tr -d ' '); fi
    if [ "$part" -ge "$len" ]; then rm -f "$tmp"; return 0; fi      # only a partial line so far
    if [ "$part" -gt 0 ]; then head -c "$((len - part))" "$tmp" > "$tmp.2" && mv -f "$tmp.2" "$tmp"; fi
    chmod 0644 "$tmp" && mv -f "$tmp" "$out"
    off=$((off + len - part)); echo "$off" > "$offf"
    log "es: shipped $(((len - part) / 1024)) KB, $(wc -l < "$out" | tr -d ' ') events"
  fi
  if [ "$off" -ge "$size" ] && [ "$size" -gt $((ES_SPOOL_MAX_MB * 1048576)) ]; then
    : > "$spool"; echo 0 > "$offf"; log "es: spool truncated"
  fi
}

prune() {
  find "$INBOX/ls" -type f -mtime +"$INBOX_DAYS" -delete 2>/dev/null
  find "$INBOX/ls" -mindepth 1 -type d -empty -delete 2>/dev/null
  find "$INBOX/es" -type f -mmin +$((ES_KEEP_HOURS * 60)) -delete 2>/dev/null
  find "$INBOX/es" -mindepth 1 -type d -empty -delete 2>/dev/null
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
  es_ship
  ls_ship
  lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | put "$INBOX/snapshots/established-tcp.txt"
  ps -axo pid=,ppid=,uid=,comm= 2>/dev/null | put "$INBOX/snapshots/procs.txt"
  network_state | put "$INBOX/snapshots/network.txt"
  if stamp_due snapshots "$SNAPSHOT_MIN"; then snapshots; stamp_set snapshots; fi
  prune
  write_meta
}

# ----------------------------------------------------------------------- user
ustamp_due() { local f="$INBOX/user/.stamps/$1"; [ -f "$f" ] || return 0; [ -n "$(find "$f" -mmin +"$2" 2>/dev/null)" ]; }
ustamp_set() { mkdir -p "$INBOX/user/.stamps"; touch "$INBOX/user/.stamps/$1"; }

# Download provenance: LaunchServices records the URL of every quarantined
# download. Last 30 days, tab-separated. Times are Mac absolute (2001-01-01).
quarantine_events() {
  local db="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
  [ -f "$db" ] || return 0
  /usr/bin/sqlite3 -readonly -separator $'\t' "$db" \
    "SELECT LSQuarantineTimeStamp, IFNULL(LSQuarantineAgentName,''), IFNULL(LSQuarantineAgentBundleIdentifier,''), IFNULL(LSQuarantineDataURLString,''), IFNULL(LSQuarantineOriginURLString,''), IFNULL(LSQuarantineSenderName,''), IFNULL(LSQuarantineTypeNumber,'') FROM LSQuarantineEvent WHERE LSQuarantineTimeStamp > (strftime('%s','now') - 978307200 - 30*86400) ORDER BY LSQuarantineTimeStamp" \
    2>/dev/null | tr -d '\r' | put "$INBOX/user/quarantine.tsv"
}

# Software inventory for vulnerability correlation (apps, Homebrew).
inventory() {
  if ustamp_due inventory "$INVENTORY_MIN"; then
    system_profiler -json -detailLevel basic SPApplicationsDataType 2>/dev/null | put "$INBOX/user/apps.json"
    if command -v brew >/dev/null 2>&1; then
      HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew list --versions 2>/dev/null | put "$INBOX/user/brew-versions.txt"
      HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew info --json=v2 --installed 2>/dev/null | put "$INBOX/user/brew-info.json"
    fi
    ustamp_set inventory
  fi
  if command -v brew >/dev/null 2>&1 && ustamp_due brew-vulns "$BREW_VULNS_MIN"; then
    if HOMEBREW_NO_AUTO_UPDATE=1 brew vulns --help >/dev/null 2>&1; then
      # exits non-zero when it finds something, so ignore the status; keep JSON if this brew has --json
      local tmpv; tmpv=$(mktemp -t argus-brew-vulns)
      HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew vulns --json > "$tmpv" 2>/dev/null
      case "$(head -c 1 "$tmpv")" in
        '{'|'[') put "$INBOX/user/brew-vulns.json" < "$tmpv"; rm -f "$INBOX/user/brew-vulns.txt" ;;
        *) HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew vulns 2>&1 | put "$INBOX/user/brew-vulns.txt"; rm -f "$INBOX/user/brew-vulns.json" ;;
      esac
      rm -f "$tmpv"
    else
      echo "brew vulns not available (needs Homebrew 6.0.11+); Argus falls back to OSV" | put "$INBOX/user/brew-vulns.txt"
    fi
    ustamp_set brew-vulns
  fi
}

# Browser extensions: Chromium-family manifests + install metadata, Firefox
# extensions.json, Safari app extensions (pluginkit). Raw sections; parsed in Argus.
JXA_PREFS='function run(a){ObjC.import("Foundation");var s=$.NSString.stringWithContentsOfFileEncodingError(a[0],$.NSUTF8StringEncoding,null);if(!s||s.isNil())return "{}";try{var j=JSON.parse(s.js);var x=(j.extensions&&j.extensions.settings)||{};var o={};for(var k in x){var e=x[k]||{};o[k]={location:e.location,from_webstore:e.from_webstore,install_time:e.install_time||e.first_install_time||null,state:e.state,disable_reasons:e.disable_reasons,by_default:e.was_installed_by_default,by_oem:e.was_installed_by_oem,path:e.path||""};}return JSON.stringify(o);}catch(err){return "{}";}}'
browser_extensions() {
  local base root prof pname ext id v loc
  for base in "Google/Chrome" "Google/Chrome Beta" "Google/Chrome Canary" "Chromium" "BraveSoftware/Brave-Browser" "Microsoft Edge" "Vivaldi" "Arc/User Data" "com.operasoftware.Opera"; do
    root="$HOME/Library/Application Support/$base"; [ -d "$root" ] || continue
    for prof in "$root"/*/; do
      [ -d "$prof/Extensions" ] || continue
      pname=$(basename "$prof")
      for v in "Secure Preferences" "Preferences"; do
        [ -f "$prof/$v" ] || continue
        printf '=== chromium-prefs\t%s\t%s\n' "$base" "$pname"
        osascript -l JavaScript -e "$JXA_PREFS" "$prof/$v" 2>/dev/null || echo '{}'
      done
      for ext in "$prof"Extensions/*/; do
        id=$(basename "$ext")
        for v in "$ext"*/; do
          [ -f "$v/manifest.json" ] || continue
          printf '=== chromium-manifest\t%s\t%s\t%s\t%s\n' "$base" "$pname" "$id" "$(basename "$v")"
          head -c 200000 "$v/manifest.json"; echo
          for loc in en en_US en_GB; do
            if [ -f "$v/_locales/$loc/messages.json" ]; then printf '=== chromium-messages\t%s\t%s\t%s\n' "$base" "$pname" "$id"; head -c 100000 "$v/_locales/$loc/messages.json"; echo; break; fi
          done
        done
      done
    done
  done
  for prof in "$HOME/Library/Application Support/Firefox/Profiles"/*/; do
    [ -f "$prof/extensions.json" ] || continue
    printf '=== firefox\t%s\n' "$(basename "$prof")"; head -c 3000000 "$prof/extensions.json"; echo
  done
  printf '=== safari\n'; pluginkit -mAvvv -p com.apple.Safari.web-extension 2>/dev/null; pluginkit -mAvvv -p com.apple.Safari.extension 2>/dev/null
}

# Vulnerability scan of the images your running containers use, with grype or
# trivy if installed (brew install grype). Daily; each image is saved to a temp
# OCI archive, scanned offline-style by the tool, then the archive is deleted.
image_scan() {
  local tool ref tmp out safe
  if command -v grype >/dev/null 2>&1; then tool=grype; elif command -v trivy >/dev/null 2>&1; then tool=trivy; else return 0; fi
  command -v container >/dev/null 2>&1 || return 0
  mkdir -p "$INBOX/user/images"
  tmp=$(mktemp -d -t argus-scan) || return 0
  for ref in $(container list --format json 2>/dev/null | grep -o '"reference" *: *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' | sort -u); do
    safe=$(printf '%s' "$ref" | tr -c 'A-Za-z0-9._-' '_')
    out="$INBOX/user/images/$safe.json"
    if container image save --output "$tmp/img.tar" "$ref" >/dev/null 2>&1; then
      {
        printf '{"tool":"%s","image":"%s","scanned":%s,"report":' "$tool" "$ref" "$(date +%s)"
        if [ "$tool" = grype ]; then grype "oci-archive:$tmp/img.tar" -o json -q 2>/dev/null || echo null
        else trivy image --input "$tmp/img.tar" -f json -q 2>/dev/null || echo null; fi
        printf '}\n'
      } | put "$out"
    else
      printf '{"tool":"%s","image":"%s","scanned":%s,"error":"container image save failed"}\n' "$tool" "$ref" "$(date +%s)" | put "$out"
    fi
    rm -f "$tmp/img.tar"
  done
  rmdir "$tmp" 2>/dev/null
  find "$INBOX/user/images" -name '*.json' -mtime +7 -delete 2>/dev/null
}

certs_user() {
  echo "== login.keychain"; security find-certificate -a -Z "$HOME/Library/Keychains/login.keychain-db" 2>&1
  echo "== user trust"; security dump-trust-settings 2>&1
}

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
  quarantine_events
  inventory
  if ustamp_due image-scan "${ARGUS_IMAGE_SCAN_MIN:-1440}"; then image_scan; ustamp_set image-scan; fi
  if ustamp_due extensions 60; then browser_extensions | put "$INBOX/user/browser-extensions.txt"; certs_user | put "$INBOX/user/certs-user.txt"; ustamp_set extensions; fi
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
