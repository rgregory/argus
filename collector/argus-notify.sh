#!/bin/bash
# Argus macOS notifier. launchd starts this whenever the alerts folder changes
# (WatchPaths), and it shows each new line of outbox.tsv as a notification.
# outbox.tsv is written by the Argus container: epoch-ms <TAB> severity <TAB> title <TAB> body
# Installed by ./argus.sh install-collector as the com.argus.notify LaunchAgent.
set -u
export LC_ALL=C   # byte-accurate offsets

DIR="${ARGUS_ALERTS:?ARGUS_ALERTS is not set}"
URL="${ARGUS_URL:-}"
OUT="$DIR/outbox.tsv"
STATE="$HOME/Library/Application Support/Argus"
OFF="$STATE/notify.offset"
mkdir -p "$STATE"
[ -f "$OUT" ] || exit 0

size=$(stat -f %z "$OUT" 2>/dev/null || echo 0)
off=$(cat "$OFF" 2>/dev/null || echo 0)
case "$off" in ''|*[!0-9]*) off=0 ;; esac
[ "$size" -lt "$off" ] && off=0          # Argus rotated the file
[ "$size" -gt "$off" ] || exit 0

TN=""
for t in /opt/homebrew/bin/terminal-notifier /usr/local/bin/terminal-notifier; do [ -x "$t" ] && { TN="$t"; break; }; done

notify() { # title body severity
  local sound=""
  [ "$3" = "high" ] && sound="Basso"
  if [ -n "$TN" ]; then
    "$TN" -title "$1" -message "$2" ${URL:+-open "$URL"} ${sound:+-sound "$sound"} >/dev/null 2>&1 && return
  fi
  /usr/bin/osascript - "$1" "$2" "$sound" >/dev/null 2>&1 <<'OSA'
on run argv
  if (item 3 of argv) is "" then
    display notification (item 2 of argv) with title (item 1 of argv)
  else
    display notification (item 2 of argv) with title (item 1 of argv) sound name (item 3 of argv)
  end if
end run
OSA
}

used=0; n=0; titles=""; worst=""
lines=()
while IFS= read -r line; do               # a trailing partial line is left for next time
  used=$((used + ${#line} + 1))
  lines+=("$line")
done < <(tail -c +"$((off + 1))" "$OUT" | head -c "$((size - off))")

for line in "${lines[@]+"${lines[@]}"}"; do
  rest=${line#*$'\t'}; sev=${rest%%$'\t'*}; rest=${rest#*$'\t'}; title=${rest%%$'\t'*}; body=${rest#*$'\t'}
  [ -n "$title" ] || continue
  n=$((n + 1))
  if [ "$n" -le 3 ]; then notify "$title" "$body" "$sev"; fi
  [ "$sev" = "high" ] && worst=high
  titles="$titles${titles:+; }$title"
done
if [ "$n" -gt 3 ]; then notify "Argus: $((n - 3)) more alerts" "${titles:0:220}" "$worst"; fi

echo $((off + used)) > "$OFF"
