#!/bin/bash
# Argus container entrypoint. Runs under tini (-g), supervises three services:
#   syslog-ng  (optional network syslog receiver, UDP 5514 / TCP 5515)
#   CrowdSec   (agent + local API, via the base image's own start script)
#   Argus      (Node service: ingest, threat intel, dashboard on :7080)
# Each service is restarted if it exits; TERM/INT stops everything.
set -uo pipefail

STATE="${ARGUS_STATE:-/var/lib/argus}"
mkdir -p "$STATE/logs/remote" "$STATE/feeds" /data/reports /data/exports \
         /etc/crowdsec/acquis.d /var/log /run /tmp

log() { printf '[argus] %s\n' "$*" >&2; }

supervise() {
  local name="$1"; shift
  (
    while true; do
      "$@"
      rc=$?
      log "$name exited ($rc); restarting in 15s"
      sleep 15
    done
  ) &
}

# ---------------------------------------------------------------- CrowdSec
crowdsec_fallback() {
  # Used only if the base image's start script is missing.
  local key="${BOUNCER_KEY_argus:-}"
  [ -f /etc/crowdsec/config.yaml ] || cp -an /staging/etc/crowdsec/. /etc/crowdsec/ 2>/dev/null || true
  cscli hub update >/dev/null 2>&1 || log "cscli hub update failed (offline?)"
  # shellcheck disable=SC2086
  [ -n "${COLLECTIONS:-}" ] && cscli collections install ${COLLECTIONS} >/dev/null 2>&1
  cscli machines add -a --force >/dev/null 2>&1 || true
  if [ "${DISABLE_ONLINE_API:-false}" != "true" ] && ! grep -q login /etc/crowdsec/online_api_credentials.yaml 2>/dev/null; then
    cscli capi register >/dev/null 2>&1 || true
  fi
  if [ -n "$key" ] && ! cscli bouncers list -o raw 2>/dev/null | grep -q '^argus,'; then
    cscli bouncers add argus -k "$key" >/dev/null 2>&1 || true
  fi
  exec crowdsec -c /etc/crowdsec/config.yaml
}

run_crowdsec() {
  cp /etc/argus/acquis-argus.yaml /etc/crowdsec/acquis.d/argus.yaml 2>/dev/null || true
  if [ -f /docker_start.sh ]; then
    bash /docker_start.sh
  else
    crowdsec_fallback
  fi
}

# ------------------------------------------------------------------- start
trap 'trap - TERM INT; log "stopping"; kill 0 2>/dev/null; exit 0' TERM INT

if [ "${ARGUS_SYSLOG:-1}" = "1" ]; then
  log "starting syslog-ng (udp/5514, tcp/5515)"
  supervise syslog-ng syslog-ng -F -e -f /etc/argus/syslog-ng.conf \
    -R "$STATE/syslog-ng.persist" -p /run/syslog-ng.pid -c /run/syslog-ng.ctl
fi

if [ "${ARGUS_CROWDSEC:-1}" = "1" ]; then
  log "starting CrowdSec"
  supervise crowdsec run_crowdsec
fi

log "starting Argus service on :${ARGUS_HTTP_PORT:-7080}"
supervise argus node /opt/argus/app/server.js

wait
