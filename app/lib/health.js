'use strict';
// Pipeline health: is every input still arriving? A stopped collector, a revoked
// Full Disk Access grant or a disabled Little Snitch export otherwise looks exactly
// like a quiet day. Each check returns ok, warn or fail; inputs that were never set
// up are left out rather than reported as broken.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, walk } = require('./util');

const M = 60e3, H = 3600e3, D = 86400e3;
const ago = ms => ms < H ? `${Math.round(ms / M)} min` : ms < 2 * D ? `${Math.round(ms / H)} h` : `${Math.round(ms / D)} days`;

function newest(rel, test) {
  const dir = path.join(cfg.inbox, rel);
  let best = 0;
  try {
    for (const p of walk(dir, (f, n) => test(n))) {
      try { const t = fs.statSync(p).mtimeMs; if (t > best) best = t; } catch (e) { /* gone */ }
    }
  } catch (e) { /* no dir */ }
  return best || null;
}
function stat(rel) { try { const s = fs.statSync(path.join(cfg.inbox, rel)); return { at: s.mtimeMs, size: s.size }; } catch (e) { return null; } }

class Health {
  constructor() { this.since = new Map(); this.lastRun = 0; this.graceUntil = Date.now() + 10 * M; }   // since: id -> when it first went bad

  check({ mac, feeds, cs }) {
    const now = Date.now(), out = [];
    // After the Mac sleeps, the container and the collector wake together and the
    // collector needs a run or two to catch up; staleness then is not a fault.
    if (this.lastRun && now - this.lastRun > 5 * M) this.graceUntil = now + 10 * M;
    this.lastRun = now;
    const put = (id, status, title, detail, fix) => {
      if (status === 'ok') this.since.delete(id);
      else if (!this.since.has(id) || this.since.get(id).status !== status) this.since.set(id, { status, at: (this.since.get(id) || {}).at || now });
      out.push({ id, status, title, detail: detail || '', fix: fix || '', since: status === 'ok' ? null : this.since.get(id).at });
    };
    const meta = mac.meta || {};

    // 1. system collector (LaunchDaemon, every 5 min)
    const sys = meta.system_last_run ? meta.system_last_run * 1000 : null;
    if (!sys) put('collector', 'fail', 'Host collector has not run', 'No meta.json from the system collector, so no unified log, snapshots or telemetry are arriving.', './argus.sh install-collector');
    else {
      const a = now - sys;
      put('collector', a > H ? 'fail' : a > 15 * M ? 'warn' : 'ok', a > 15 * M ? `Host collector last ran ${ago(a)} ago` : 'Host collector running',
        `Runs every 5 minutes as root. Last run ${new Date(sys).toISOString()}.`, a > 15 * M ? 'sudo launchctl kickstart -k system/com.argus.collect; tail /var/log/argus-collect.log' : '');
    }
    // 2. user collector (LaunchAgent, every 15 min; stops while logged out)
    const usr = meta.user_last_run ? meta.user_last_run * 1000 : null;
    if (usr) {
      const a = now - usr;
      put('collector-user', a > 6 * H ? 'fail' : a > 45 * M ? 'warn' : 'ok', a > 45 * M ? `User collector last ran ${ago(a)} ago` : 'User collector running',
        'Runs every 15 minutes in your login session: downloads, app inventory, browser extensions, image scans.', a > 45 * M ? 'launchctl kickstart -k gui/$(id -u)/com.argus.collect.user' : '');
    }
    // 3. unified log batches
    const uni = newest('unified', n => /\.ndjson$/.test(n));
    if (sys && uni) {
      const a = now - uni;
      put('unified', a > H ? 'fail' : a > 20 * M ? 'warn' : 'ok', a > 20 * M ? `No unified-log batch for ${ago(a)}` : 'Unified log arriving', 'The collector exports the unified log every run.', a > 20 * M ? 'tail /var/log/argus-collect.log' : '');
    }
    // 4. Endpoint Security (only once telemetry has been installed)
    const hs = mac.hostsec ? mac.hostsec.status() : {};
    if (hs.esSince) {
      const last = Math.max(newest('es', n => /\.ndjson$/.test(n)) || 0, hs.lastFileAt || 0);
      const a = now - last;
      put('eslogger', a > H ? 'fail' : a > 20 * M ? 'warn' : 'ok', a > 20 * M ? `No Endpoint Security events for ${ago(a)}` : 'Endpoint Security events arriving',
        'eslogger runs as its own LaunchDaemon. A macOS update can drop its Full Disk Access grant.', a > 20 * M ? './argus.sh telemetry-status' : '');
    }
    // 5. TCC.db reader (needs Full Disk Access for /usr/bin/sqlite3)
    const tcc = stat('snapshots/tcc-system.tsv');
    if (tcc) {
      const a = now - tcc.at;
      if (tcc.size === 0) put('tcc', 'fail', 'TCC.db snapshot is empty', '/usr/bin/sqlite3 has lost Full Disk Access, so permission changes are not being seen.', 'System Settings › Privacy & Security › Full Disk Access: re-add /usr/bin/sqlite3, then ./argus.sh telemetry-status');
      else put('tcc', a > 3 * H ? 'warn' : 'ok', a > 3 * H ? `TCC.db snapshot is ${ago(a)} old` : 'TCC.db snapshots arriving', 'Read hourly by the com.argus.tcc job.', a > 3 * H ? './argus.sh telemetry-status' : '');
    }
    // 6. hourly snapshots
    const snap = stat('snapshots/posture.txt');
    if (sys && snap) {
      const a = now - snap.at;
      put('snapshots', a > 3 * H ? 'warn' : 'ok', a > 3 * H ? `Hourly snapshots are ${ago(a)} old` : 'Hourly snapshots current', 'Posture, persistence, certificates, devices and code signatures.', '');
    }
    // 7. Little Snitch export (only if it has worked before)
    const ls = newest('ls', n => /\.csv$/.test(n));
    if (ls && now - ls < 7 * D) {
      const a = now - ls;
      put('littlesnitch', a > H ? 'fail' : a > 20 * M ? 'warn' : 'ok', a > 20 * M ? `No Little Snitch export for ${ago(a)}` : 'Little Snitch traffic arriving',
        'Needs Little Snitch › Settings › Security › Allow access via Terminal.', a > 20 * M ? 'grep littlesnitch /var/log/argus-collect.log | tail' : '');
    }
    // 8. threat-intel feeds
    const fs_ = (feeds.status() || []).filter(f => f.enabled);
    if (fs_.length) {
      const stale = fs_.filter(f => f.error && (!f.updated || now - f.updated > Math.max(2 * f.ttlHours * H, D)));
      const none = fs_.every(f => !f.entries);
      put('feeds', none ? 'fail' : stale.length ? 'warn' : 'ok', none ? 'No threat-intel feed has loaded' : stale.length ? `${stale.length} threat-intel ${stale.length === 1 ? 'feed is' : 'feeds are'} failing` : 'Threat-intel feeds current',
        stale.slice(0, 5).map(f => `${f.name}: ${f.error}`).join('; '), none ? 'check the container has internet access' : '');
    }
    // 9. Sigma rules
    const sg = hs.sigma;
    if (sg && sg.enabled) put('sigma', !sg.rules && sg.error ? 'warn' : 'ok', !sg.rules && sg.error ? 'Sigma rules not loaded' : `${sg.rules} Sigma rules loaded`, sg.error || '', '');
    // 10. CrowdSec
    const c = cs.status();
    if (c.enabled) put('crowdsec', c.error ? 'warn' : 'ok', c.error ? 'CrowdSec not reachable' : 'CrowdSec connected', c.error || '', c.error ? './argus.sh logs' : '');

    const bad = out.filter(x => x.status !== 'ok');
    return { status: bad.some(x => x.status === 'fail') ? 'fail' : bad.length ? 'warn' : 'ok', checks: out, problems: bad.length, at: now, grace: now < this.graceUntil };
  }
}

module.exports = { Health };
