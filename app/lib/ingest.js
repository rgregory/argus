'use strict';
// Inputs: the host collector's inbox (read-only), read-only host log folders,
// the syslog-ng spool, and the Pi-hole API.
const fs = require('node:fs');
const path = require('node:path');
const engine = require('./engine');
const { cfg, logger, fetchJson, walk, dayKey } = require('./util');

const H = 3600e3;
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const p2 = n => String(n).padStart(2, '0');
const bsd = d => `${MON[d.getMonth()]} ${String(d.getDate()).padStart(2, ' ')} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
const safeName = s => String(s || '').replace(/[^A-Za-z0-9._-]/g, '_') || 'unknown';

// --------------------------------------------------------------- macOS inbox
class MacIngest {
  constructor(store, intel, tp) {
    this.log = logger('macos');
    this.store = store; this.intel = intel; this.tp = tp;
    this.st = engine.newState({ host: cfg.macHost });
    this.dnsSt = engine.newState();
    this.dnsDay = dayKey();
    this.report = null; this.dnsReport = null; this.dirty = true;
    this.snapSeen = new Map(); this.crashSeen = new Set();
    this.lastRebuild = 0; this.meta = {}; this.lastFile = null; this.lastFileAt = null;
    this.logDir = path.join(cfg.state, 'logs');
    fs.mkdirSync(path.join(this.logDir, 'remote'), { recursive: true });
  }
  host() { return safeName(this.meta.host || cfg.macHost || 'mac'); }
  readMeta() {
    const read = f => { try { return JSON.parse(fs.readFileSync(path.join(cfg.inbox, f), 'utf8')); } catch (e) { return {}; } };
    this.meta = { ...read('meta.json'), ...read('user/meta.json') };   // empty until the collector runs
  }
  unifiedFiles() { return walk(path.join(cfg.inbox, 'unified'), (p, n) => n.endsWith('.ndjson')).sort(); }

  *events(text) {
    let start = 0;
    const len = text.length;
    while (start < len) {
      let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
      if (text.charCodeAt(start) === 123) {
        let o = null; try { o = JSON.parse(text.slice(start, nl)); } catch (e) { /* partial */ }
        if (o && o.eventMessage !== undefined) {
          const proc = String(o.processImagePath || '').split('/').pop() || o.process || 'unknown';
          yield { ts: engine.parseTs(o.timestamp), proc, sub: o.subsystem || '', type: String(o.messageType || '').toLowerCase(), msg: String(o.eventMessage || ''), pid: o.processID || 0 };
        }
      }
      start = nl + 1;
    }
  }

  async cycle() {
    this.readMeta();
    if (!this.lastRebuild || Date.now() - this.lastRebuild > 6 * H) this.rebuild();
    const a = this.processNewUnified();
    const b = await this.processSnapshots();
    const c = await this.processCrashes();
    if (cfg.pihole.url && dayKey() !== this.dnsDay) { this.dnsSt = engine.newState(); this.dnsDay = dayKey(); this.dirty = true; }
    if (a || b || c) this.dirty = true;
    if (this.dirty) this.finalize();
  }

  rebuild() {
    const t0 = Date.now();
    this.st = engine.newState({ host: cfg.macHost || this.meta.host || '' });
    this.snapSeen.clear(); this.crashSeen.clear();
    const cutoff = Date.now() - cfg.windowHours * H;
    let n = 0, files = 0;
    for (const f of this.unifiedFiles()) {
      if (!this.store.get('SELECT 1 FROM processed WHERE path = ?', f)) continue;
      let st; try { st = fs.statSync(f); } catch (e) { continue; }
      if (st.mtimeMs < cutoff) continue;
      for (const ev of this.events(fs.readFileSync(f, 'utf8'))) { engine.handleEvent(this.st, ev); n++; }
      files++;
    }
    this.lastRebuild = Date.now(); this.dirty = true;
    this.log.info(`rebuilt ${cfg.windowHours} h window: ${n} events from ${files} files in ${Date.now() - t0} ms`);
  }

  processNewUnified() {
    const cutoff = Date.now() - cfg.windowHours * H;
    let any = false;
    for (const f of this.unifiedFiles()) {
      if (this.store.get('SELECT 1 FROM processed WHERE path = ?', f)) continue;
      let st; try { st = fs.statSync(f); } catch (e) { continue; }
      const mark = () => this.store.run('INSERT OR REPLACE INTO processed(path, size, done_at) VALUES (?, ?, ?)', f, st.size, Date.now());
      if (st.mtimeMs < cutoff) { mark(); continue; }
      const byDay = new Map(); let n = 0, out = 0;
      const host = this.host();
      for (const ev of this.events(fs.readFileSync(f, 'utf8'))) {
        engine.handleEvent(this.st, ev);
        const ts = ev.ts || new Date();
        let prog = safeName(ev.proc);
        if (prog === 'sshd-session' || prog === 'sshd-auth') prog = 'sshd';    // CrowdSec's sshd parser keys on "sshd"
        const line = `${bsd(ts)} ${host} ${prog}[${ev.pid}]: ${ev.msg.replace(/[\r\n]+/g, ' ')}\n`;
        const k = dayKey(ts);
        byDay.set(k, (byDay.get(k) || '') + line);
        n++; out += line.length;
      }
      if (cfg.macosToCrowdsec) {
        for (const [k, text] of byDay) fs.appendFileSync(path.join(this.logDir, `macos-${k}.log`), text);
        this.tp.add('to-crowdsec', n, out);
      }
      this.tp.add('macos', n, st.size);
      mark(); any = true;
      this.lastFile = f; this.lastFileAt = Date.now();
    }
    return any;
  }

  async processSnapshots() {
    let any = false;
    for (const dir of ['snapshots', 'user', 'containers', 'apps']) {
      for (const p of walk(path.join(cfg.inbox, dir), (x, n) => !/\.tmp(\.\d+)?$/.test(n) && !n.startsWith('.') && !n.endsWith('.json'))) {
        let st; try { st = fs.statSync(p); } catch (e) { continue; }
        const key = `${st.mtimeMs}|${st.size}`;
        if (this.snapSeen.get(p) === key) continue;
        this.snapSeen.set(p, key);
        let text; try { text = fs.readFileSync(p, 'utf8'); } catch (e) { continue; }
        const kind = engine.classify(p, text.slice(0, 65536));
        if (kind === 'dns') {
          if (cfg.pihole.url) continue;           // the Pi-hole API is the DNS source
          this.dnsSt = engine.newState();
          await engine.ingest(this.dnsSt, p, text);
        } else await engine.ingest(this.st, p, text);
        this.tp.add('snapshots', 1, st.size);
        any = true;
      }
    }
    return any;
  }

  async processCrashes() {
    const dirs = [path.join(cfg.inbox, 'crash'), path.join(cfg.hostRoot, 'Library/Logs/DiagnosticReports'), path.join(cfg.hostRoot, 'home/Library/Logs/DiagnosticReports')];
    const cutoff = Date.now() - 14 * 24 * H;
    let any = false;
    for (const d of dirs) {
      for (const p of walk(d, (x, n) => /\.(ips|panic|diag|spin|hang|crash)$/.test(n))) {
        let st; try { st = fs.statSync(p); } catch (e) { continue; }
        if (st.mtimeMs < cutoff) continue;
        const key = path.basename(p) + '|' + st.size;
        if (this.crashSeen.has(key)) continue;
        this.crashSeen.add(key);
        let text; try { text = fs.readFileSync(p, 'utf8'); } catch (e) { continue; }   // root-only reports are skipped
        await engine.ingest(this.st, p, text, null, { kind: 'crash' });
        any = true;
      }
    }
    return any;
  }

  finalize() {
    this.report = engine.finalize(this.st);
    this.dnsReport = this.dnsSt.dns ? engine.finalize(this.dnsSt) : null;
    this.intel.addFromEngine(this.report.iocs);
    if (this.dnsReport) this.intel.addFromEngine(this.dnsReport.iocs);
    this.dirty = false;
  }

  prune() {
    const cut = Date.now() - cfg.retainDays * 24 * H;
    const old = walk(this.logDir, (p, n) => /\.(log|tsv)$/.test(n)).filter(p => { try { return fs.statSync(p).mtimeMs < cut; } catch (e) { return false; } });
    old.forEach(p => { try { fs.unlinkSync(p); } catch (e) { /* ignore */ } });
    this.store.run('DELETE FROM processed WHERE done_at < ?', Date.now() - (cfg.retainDays + cfg.windowHours / 24 + 2) * 24 * H);
    if (old.length) this.log.info(`pruned ${old.length} old log files`);
  }

  status() {
    return { meta: this.meta, lastFile: this.lastFile, lastFileAt: this.lastFileAt, events: this.st.u.events, windowHours: cfg.windowHours,
      inboxFiles: this.unifiedFiles().length, lastRebuild: this.lastRebuild };
  }
}

// ------------------------------------------------------------ syslog spool
const RX_IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;

class SyslogTail {
  constructor(store, intel, tp) {
    this.log = logger('syslog');
    this.store = store; this.intel = intel; this.tp = tp;
    this.dir = path.join(cfg.state, 'logs');
    this.hosts = new Map(Object.entries(store.kvGet('syslog.hosts', {})));
    this.recent = [];
  }
  cycle() {
    if (!cfg.syslog.enabled) return;
    let files; try { files = fs.readdirSync(this.dir).filter(n => /^remote-\d{8}\.tsv$/.test(n)).sort().slice(-2); } catch (e) { return; }
    const iocs = new Map();
    for (const name of files) {
      const p = path.join(this.dir, name);
      let size; try { size = fs.statSync(p).size; } catch (e) { continue; }
      let off = this.store.kvGet('tsv:' + name, 0);
      if (size < off) off = 0;
      if (size === off) continue;
      const len = Math.min(size - off, 64 * 1024 * 1024);
      const buf = Buffer.alloc(len);
      const fd = fs.openSync(p, 'r');
      try { fs.readSync(fd, buf, 0, len, off); } finally { fs.closeSync(fd); }
      const text = buf.toString('utf8');
      const lastNl = text.lastIndexOf('\n');
      if (lastNl === -1) continue;
      const body = text.slice(0, lastNl);
      let n = 0;
      for (const line of body.split('\n')) {
        const f = line.split('\t');
        if (f.length < 9) continue;
        const [unix, , host, src, prog, pid, level, fac] = f;
        const msg = f.slice(8).join('\t');
        const h = this.hosts.get(host) || { host, src, messages: 0, first: +unix * 1000, last: 0, programs: {} };
        h.messages++; h.last = +unix * 1000; h.src = src || h.src;
        if (prog) h.programs[prog] = (h.programs[prog] || 0) + 1;
        this.hosts.set(host, h);
        this.recent.push({ ts: +unix * 1000, host, src, prog, pid, level, fac, msg: msg.slice(0, 500) });
        for (const ip of (msg.match(RX_IPV4) || []).slice(0, 4)) {
          if (engine.ipScope(ip) !== 'public') continue;
          const k = host + '|' + ip;
          const x = iocs.get(k) || { value: ip, type: 'ip', source: 'syslog:' + host, context: `${prog}: ${msg.slice(0, 160)}`, hits: 0 };
          x.hits++; iocs.set(k, x);
        }
        n++;
      }
      if (this.recent.length > 500) this.recent.splice(0, this.recent.length - 500);
      this.store.kvSet('tsv:' + name, off + Buffer.byteLength(body, 'utf8') + 1);
      this.tp.add('syslog', n, Buffer.byteLength(body, 'utf8'));
    }
    if (iocs.size) this.intel.observeMany([...iocs.values()]);
    for (const [k, h] of this.hosts) {
      const progs = Object.entries(h.programs).sort((a, b) => b[1] - a[1]).slice(0, 15);
      h.programs = Object.fromEntries(progs);
      if (Date.now() - h.last > 14 * 24 * H) this.hosts.delete(k);
    }
    this.store.kvSet('syslog.hosts', Object.fromEntries(this.hosts));
  }
  status() {
    return { enabled: cfg.syslog.enabled, hosts: [...this.hosts.values()].sort((a, b) => b.last - a.last), recent: this.recent.slice(-200).reverse() };
  }
}

// --------------------------------------------------------------- Pi-hole API
const BLOCKED = /GRAVITY|REGEX|DENYLIST|BLACKLIST|EXTERNAL_BLOCKED|SPECIAL_DOMAIN/i;

class PiHole {
  constructor(mac, intel, store, tp) {
    this.log = logger('pihole');
    this.mac = mac; this.intel = intel; this.store = store; this.tp = tp;
    this.sid = null; this.sidUntil = 0; this.error = ''; this.lastPoll = null; this.total = 0;
  }
  async auth() {
    if (!cfg.pihole.password) { this.sid = null; this.sidUntil = Date.now() + 3600e3; return; }
    const r = await fetchJson(`${cfg.pihole.url}/api/auth`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: cfg.pihole.password }), timeout: 15000 });
    const s = r.json && r.json.session;
    if (!r.ok || !s || !s.valid) throw new Error(`auth failed (HTTP ${r.status}${r.json && r.json.error ? ': ' + r.json.error.message : ''})`);
    this.sid = s.sid; this.sidUntil = Date.now() + Math.max(60, (s.validity || 1800) - 60) * 1000;
  }
  async poll() {
    if (!cfg.pihole.url) return;
    try {
      if (Date.now() > this.sidUntil) await this.auth();
      const now = Math.floor(Date.now() / 1000);
      const from = this.store.kvGet('pihole.last', now - 3600);
      const url = `${cfg.pihole.url}/api/queries?from=${from}&until=${now}&length=20000`;
      let r = await fetchJson(url, { headers: this.sid ? { 'X-FTL-SID': this.sid } : {}, timeout: 60000 });
      if (r.status === 401) { await this.auth(); r = await fetchJson(url, { headers: this.sid ? { 'X-FTL-SID': this.sid } : {}, timeout: 60000 }); }
      if (!r.ok || !r.json) throw new Error(`queries HTTP ${r.status}`);
      const qs = r.json.queries || [];
      const agg = new Map(); let maxT = from;
      for (const q of qs) {
        const t = +q.time || now;
        if (t > maxT) maxT = t;
        const client = (q.client && (q.client.name || q.client.ip)) || '';
        const blocked = BLOCKED.test(q.status || '');
        engine.addDnsQuery(this.mac.dnsSt, { ts: new Date(t * 1000), domain: q.domain, client, type: q.type, blocked });
        const d = String(q.domain || '').toLowerCase();
        const a = agg.get(d) || { value: d, type: 'domain', source: 'dns', context: `queried by ${client}${blocked ? ' (blocked by Pi-hole)' : ''}`, hits: 0 };
        a.hits++; agg.set(d, a);
      }
      if (qs.length >= 20000) this.log.warn('query page limit reached; some queries in this window were skipped');
      this.intel.observeMany([...agg.values()]);
      this.store.kvSet('pihole.last', Math.floor(maxT) + 1);
      this.tp.add('pihole', qs.length, r.text.length);
      this.total += qs.length; this.lastPoll = Date.now(); this.error = '';
      if (qs.length) this.mac.dirty = true;
    } catch (e) { this.error = e.message; this.sidUntil = 0; this.log.warn(e.message); }
  }
  status() { return { configured: !!cfg.pihole.url, url: cfg.pihole.url, error: this.error, lastPoll: this.lastPoll, queries: this.total }; }
}

module.exports = { MacIngest, SyslogTail, PiHole, bsd };
