'use strict';
// CrowdSec integration (same container):
//  - decisions via the LAPI bouncer stream (local detections + community blocklist)
//  - alerts via `cscli alerts list -o json`
const { execFile } = require('node:child_process');
const { cfg, logger, fetchJson, ipv4ToInt, cidrRange } = require('./util');

const log = logger('crowdsec');

function cscli(args, timeout = 30000) {
  return new Promise((resolve, reject) => {
    execFile(cfg.crowdsec.cscli, args, { timeout, maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message).trim().split('\n').pop()));
      resolve(stdout);
    });
  });
}

class CrowdSec {
  constructor() {
    this.enabled = cfg.crowdsec.enabled;
    this.ips = new Map();       // ip -> decision
    this.ranges = [];           // [start, end, decision]
    this.alerts = [];
    this.byOrigin = {};
    this.lastStream = null; this.lastAlerts = null; this.error = ''; this.alertError = '';
    this.started = false;
    this.version = 0;
  }
  key(d) { return `${d.scope}|${d.value}`; }
  applyStream(j) {
    let changed = false;
    for (const d of (j && j.deleted) || []) {
      if (/^ip$/i.test(d.scope)) { if (this.ips.delete(d.value)) changed = true; }
      else if (/^range$/i.test(d.scope)) { const n = this.ranges.length; this.ranges = this.ranges.filter(r => r[2].value !== d.value); changed = changed || n !== this.ranges.length; }
    }
    for (const d of (j && j.new) || []) {
      const dec = { value: d.value, scope: d.scope, origin: d.origin || '', scenario: d.scenario || '', type: d.type || 'ban', duration: d.duration || '' };
      if (/^ip$/i.test(d.scope)) { this.ips.set(d.value, dec); changed = true; }
      else if (/^range$/i.test(d.scope)) { const r = cidrRange(d.value); if (r) { this.ranges.push([r[0], r[1], dec]); changed = true; } }
    }
    if (changed) {
      this.ranges.sort((a, b) => a[0] - b[0]);
      this.byOrigin = {};
      for (const d of this.ips.values()) this.byOrigin[d.origin] = (this.byOrigin[d.origin] || 0) + 1;
      for (const r of this.ranges) this.byOrigin[r[2].origin] = (this.byOrigin[r[2].origin] || 0) + 1;
      this.version++;
    }
  }
  async pollDecisions() {
    if (!cfg.crowdsec.bouncerKey) { this.error = 'BOUNCER_KEY_argus not set'; return; }
    const url = `${cfg.crowdsec.lapi}/v1/decisions/stream?startup=${this.started ? 'false' : 'true'}`;
    const r = await fetchJson(url, { headers: { 'X-Api-Key': cfg.crowdsec.bouncerKey }, timeout: 60000 });
    if (!r.ok) { this.error = `LAPI HTTP ${r.status}`; return; }
    this.applyStream(r.json);
    this.started = true; this.lastStream = Date.now(); this.error = '';
  }
  async pollAlerts() {
    try {
      const out = await cscli(['alerts', 'list', '-o', 'json', '--limit', '200']);
      const arr = JSON.parse(out || 'null') || [];
      this.alerts = arr.map(a => ({
        id: a.id, scenario: a.scenario || '', message: a.message || '',
        ip: (a.source && (a.source.ip || a.source.value)) || '', scope: (a.source && a.source.scope) || '',
        cn: (a.source && a.source.cn) || '', as: (a.source && a.source.as_name) || '',
        events: a.events_count || 0, created: a.created_at || a.start_at || '', decisions: (a.decisions || []).length,
      }));
      this.lastAlerts = Date.now(); this.alertError = '';
    } catch (e) { this.alertError = e.message; }
  }
  async poll() {
    if (!this.enabled) return;
    try { await this.pollDecisions(); } catch (e) { this.error = e.message; }
    await this.pollAlerts();
  }
  match(ip) {
    const d = this.ips.get(ip);
    if (d) return d;
    const n = ipv4ToInt(ip);
    if (n === null || !this.ranges.length) return null;
    let lo = 0, hi = this.ranges.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1, r = this.ranges[mid];
      if (n < r[0]) hi = mid - 1; else if (n > r[1]) lo = mid + 1; else return r[2];
    }
    // overlapping ranges are rare in CAPI data; fall back to a linear check
    for (const r of this.ranges) if (n >= r[0] && n <= r[1]) return r[2];
    return null;
  }
  findings() {
    const out = [], groups = new Map();
    const day = Date.now() - 86400e3;
    for (const a of this.alerts) {
      if (a.created && Date.parse(a.created) < day) continue;
      const k = a.scenario + '|' + a.ip;
      const g = groups.get(k) || { ...a, count: 0 };
      g.count++; groups.set(k, g);
    }
    for (const g of groups.values()) {
      out.push({ sev: /bf|brute|exploit|cve|backdoor|rce/i.test(g.scenario) ? 'high' : 'medium', area: 'CrowdSec',
        title: `CrowdSec: ${g.scenario} from ${g.ip || 'unknown'}`, source: 'CrowdSec alert',
        detail: 'A CrowdSec scenario triggered on the ingested logs. Detection only: nothing is blocked on this Mac.',
        evidence: [`${g.count} alert(s), ${g.events} events, last ${g.created}`, g.cn || g.as ? `origin: ${[g.cn, g.as].filter(Boolean).join(' · ')}` : '', g.message].filter(Boolean), count: g.count });
    }
    return out;
  }
  status() {
    return { enabled: this.enabled, decisions: this.ips.size + this.ranges.length, byOrigin: this.byOrigin, alerts: this.alerts.slice(0, 200),
      lastStream: this.lastStream, lastAlerts: this.lastAlerts, error: this.error, alertError: this.alertError };
  }
}

module.exports = { CrowdSec, cscli };
