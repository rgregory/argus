#!/bin/bash
# Starts the Argus server with no network-facing parts (no CrowdSec, no syslog, no
# feeds) and checks the dashboard's access rules: token, Host check and Origin check.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
port=17080
token="smoke-test-token"
mkdir -p "$tmp/state" "$tmp/data" "$tmp/inbox"

cd "$root/app"
ARGUS_TOKEN="$token" ARGUS_HTTP_PORT="$port" ARGUS_STATE="$tmp/state" ARGUS_DATA="$tmp/data" \
ARGUS_INBOX="$tmp/inbox" ARGUS_HOST_ROOT="$tmp" ARGUS_CROWDSEC=0 ARGUS_SYSLOG=0 ARGUS_SIGMA=0 \
ARGUS_FEEDS_DISABLE=blocklist_de,cins,et_compromised,feodo,firehol_l1,hagezi_tif,ipsum,openphish,spamhaus_drop,threatfox,urlhaus,hagezi_nrd7,hagezi_nrd14_8,hagezi_dga14,tor_exit,dshield_block \
  node server.js > "$tmp/server.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

u="http://127.0.0.1:$port"
for _ in $(seq 1 30); do curl -fsS "$u/api/health" >/dev/null 2>&1 && break; sleep 1; done

fail=0
expect() { # CODE DESCRIPTION CURL-ARGS...
  local want="$1" what="$2" got; shift 2
  got="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
  if [ "$got" = "$want" ]; then echo "ok    $got  $what"; else echo "FAIL  $got (wanted $want)  $what"; fail=1; fi
}

expect 200 "health check needs no token"         "$u/api/health"
expect 401 "report without a token"              "$u/api/report"
expect 401 "dashboard page without a token"      "$u/"
expect 401 "report with a wrong token"           -H "Authorization: Bearer wrong" "$u/api/report"
expect 200 "report with the bearer token"        -H "Authorization: Bearer $token" "$u/api/report"
expect 302 "?token= swaps for a cookie"          "$u/?token=$token"
expect 401 "?token= with a wrong token"          "$u/?token=wrong"
# after sign-in the redirect must stay on the dashboard, whatever path was asked for
for p in '//evil.example/' '/%5Cevil.example/' '/x/'; do
  loc="$(curl -s -o /dev/null -w '%{redirect_url}' "$u$p?token=$token")"
  if [ "$loc" = "$u/" ]; then echo "ok    302  sign-in redirect stays home ($p)"; else echo "FAIL  sign-in redirect from $p went to $loc"; fail=1; fi
done
if curl -sI -H "Authorization: Bearer $token" "$u/" | grep -qi "^x-frame-options: DENY"; then echo "ok         X-Frame-Options: DENY"; else echo "FAIL       no X-Frame-Options header"; fail=1; fi
expect 200 "report with the cookie"              -H "Cookie: argus_token=$token" "$u/api/report"
expect 403 "foreign Host (DNS rebinding)"        -H "Host: evil.example" -H "Cookie: argus_token=$token" "$u/api/report"
expect 200 "Host localhost:port"                 -H "Host: localhost:$port" -H "Cookie: argus_token=$token" "$u/api/report"
expect 200 "Host [::1]:port"                     -H "Host: [::1]:$port" -H "Cookie: argus_token=$token" "$u/api/report"
expect 403 "POST from another website"           -X POST -H "Origin: http://evil.example" -H "Cookie: argus_token=$token" "$u/api/rescan"
expect 200 "POST from the dashboard itself"      -X POST -H "Origin: $u" -H "Cookie: argus_token=$token" "$u/api/rescan"
expect 401 "POST without a token"                -X POST "$u/api/rescan"
expect 401 "vulnerability refresh without a token" -X POST "$u/api/vulns/refresh"
expect 401 "acknowledge without a token"         -X POST -H "Content-Type: application/json" -d '{"id":"x"}' "$u/api/findings/ack"
expect 403 "acknowledge from another website"    -X POST -H "Origin: http://evil.example" -H "Cookie: argus_token=$token" -H "Content-Type: application/json" -d '{"id":"x"}' "$u/api/findings/ack"
expect 404 "acknowledge an unknown finding"      -X POST -H "Origin: $u" -H "Cookie: argus_token=$token" -H "Content-Type: application/json" -d '{"id":"no-such-finding"}' "$u/api/findings/ack"
expect 401 "digest without a token"              "$u/api/digest"
expect 200 "digest with the token"               -H "Authorization: Bearer $token" "$u/api/digest"
expect 403 "vulnerability refresh from another website" -X POST -H "Origin: http://evil.example" -H "Cookie: argus_token=$token" "$u/api/vulns/refresh"

expect 401 "dossier without a token"              "$u/api/program?path=/bin/ls"
expect 200 "dossier with the token"               -H "Authorization: Bearer $token" "$u/api/program?path=/bin/ls"
expect 400 "dossier for a relative path"          -H "Authorization: Bearer $token" "$u/api/program?path=ls"
expect 200 "program search"                       -H "Authorization: Bearer $token" "$u/api/programs?q=ls"
expect 200 "pipeline health"                      -H "Authorization: Bearer $token" "$u/api/health/checks"
expect 401 "test alert without a token"           -X POST "$u/api/alerts/test"
expect 403 "test alert from another website"      -X POST -H "Origin: http://evil.example" -H "Cookie: argus_token=$token" "$u/api/alerts/test"
expect 200 "test alert from the dashboard"        -X POST -H "Origin: $u" -H "Cookie: argus_token=$token" "$u/api/alerts/test"

expect 401 "weekly edition without a token"       "$u/api/weekly"
expect 200 "weekly edition with the token"        -H "Authorization: Bearer $token" "$u/api/weekly"
expect 200 "Sigma panel"                          -H "Authorization: Bearer $token" "$u/api/sigma"
expect 404 "mute an unknown Sigma rule"           -X POST -H "Origin: $u" -H "Cookie: argus_token=$token" -H "Content-Type: application/json" -d '{"id":"no-such-rule","muted":true}' "$u/api/sigma/mute"
expect 403 "mute a Sigma rule from another website" -X POST -H "Origin: http://evil.example" -H "Cookie: argus_token=$token" -H "Content-Type: application/json" -d '{"id":"x","muted":true}' "$u/api/sigma/mute"

# the report carries the endpoint and vulnerability sections
if curl -fsS -H "Authorization: Bearer $token" "$u/api/report" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const r=JSON.parse(s);process.exit(r.hostsec&&r.vulns&&r.health&&r.alerts&&r.history?0:1)})'; then
  echo "ok         report has hostsec, vulns, health, alerts and history sections"
else echo "FAIL       report is missing hostsec/vulns"; fail=1; fi

if [ "$fail" != 0 ]; then echo "--- server log"; cat "$tmp/server.log"; exit 1; fi
echo "all access checks passed"
