#!/bin/bash
# =============================================================================
# argus-logstream.sh — stream this Mac's unified log, live, to the Argus syslog
# listener over TCP (RFC 3164 lines), so CrowdSec sees events as they happen.
#
#   ARGUS_STREAM_MODE=slice  security-relevant events only (default, < 1 event/s)
#   ARGUS_STREAM_MODE=all    the whole default-level log (hundreds of events/s,
#                            gigabytes per day; only for short investigations)
#
# Run by the LaunchDaemon com.argus.logstream (installed by `argus.sh stream on`).
# Reconnects by itself when Argus restarts. macOS bash 3.2 compatible.
# =============================================================================
set -uo pipefail

MODE="${ARGUS_STREAM_MODE:-slice}"
DEST="${ARGUS_STREAM_HOST:-127.0.0.1}"
PORT="${ARGUS_STREAM_TCP_PORT:-5515}"
HOST="$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Same slice as the 5-minute collector, minus faults (no value to CrowdSec).
PREDICATE='process == "sudo" OR process == "authd" OR process == "SecurityAgent"
  OR process == "sshd" OR process == "sshd-session" OR process == "sshd-auth" OR process == "screensharingd"
  OR (process == "loginwindow" AND eventMessage CONTAINS "screenIs")
  OR process == "syspolicyd" OR process BEGINSWITH[c] "xprotect"
  OR process == "socketfilterfw"
  OR subsystem == "com.apple.TCC"
  OR subsystem == "com.apple.backgroundtaskmanagement"
  OR process BEGINSWITH[c] "little snitch" OR process BEGINSWITH[c] "littlesnitch"
  OR subsystem BEGINSWITH[c] "at.obdev.littlesnitch"'
PREDICATE="$(printf '%s' "$PREDICATE" | tr '\n' ' ')"

# `log stream --style syslog` lines look like
#   2026-10-17 20:55:01.123456-0400  localhost sshd-session[812]: (libsystem) [sub:cat] message
# Rewrite them as  <PRI>Oct 17 20:55:01 <host> sshd[812]: message
# shellcheck disable=SC2016
AWK='
BEGIN { split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ") }
$1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ {
  split($1, d, "-"); t = substr($2, 1, 8)
  rest = $0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ +/, "", rest)
  if (!match(rest, /\[[0-9]+\]: /)) next
  name = substr(rest, 1, RSTART - 1); pid = substr(rest, RSTART + 1, RLENGTH - 4); msg = substr(rest, RSTART + RLENGTH)
  gsub(/[^A-Za-z0-9._-]/, "_", name)
  if (name == "sshd-session" || name == "sshd-auth") name = "sshd"
  sub(/^\([^)]*\) /, "", msg); sub(/^\[[^]]*\] /, "", msg)
  pri = (name ~ /^(sudo|sshd|authd|screensharingd|loginwindow|SecurityAgent)$/) ? 38 : 13
  printf "<%d>%s %2d %s %s %s[%s]: %s\n", pri, M[d[2] + 0], d[3] + 0, t, host, name, pid, msg
  fflush()
}'

echo "$(date '+%F %T') streaming ($MODE) to $DEST:$PORT/tcp"
while true; do
  if [ "$MODE" = "all" ]; then
    /usr/bin/log stream --style syslog --level default 2>/dev/null
  else
    /usr/bin/log stream --style syslog --predicate "$PREDICATE" 2>/dev/null
  fi | /usr/bin/awk -v host="$HOST" "$AWK" | /usr/bin/nc "$DEST" "$PORT"
  echo "$(date '+%F %T') stream ended (Argus down or restarting); retrying in 10 s"
  sleep 10
done
