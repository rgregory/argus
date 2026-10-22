'use strict';
// Who owns an IP address: a local copy of the iptoasn.com IPv4 table (range →
// AS number, country, AS name), refreshed weekly. Lookups are a binary search in
// memory, so nothing about your traffic leaves the Mac. ARGUS_ASN=0 turns it off.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { cfg, env, logger, ipv4ToInt, writeFileAtomic } = require('./util');

const log = logger('asn');
const D = 86400e3;

class Asn {
  constructor() {
    this.on = env('ARGUS_ASN', '1') !== '0';
    this.url = env('ARGUS_ASN_URL', 'https://iptoasn.com/data/ip2asn-v4.tsv.gz');
    this.file = path.join(cfg.state, 'asn', 'ip2asn-v4.tsv.gz');
    this.meta = { updated: 0, ranges: 0, error: '' };
    this.start = new Uint32Array(0); this.end = new Uint32Array(0); this.asn = new Uint32Array(0); this.info = new Uint32Array(0);
    this.names = [];
  }

  // Parses "start\tend\tasn\tcc\tname" lines; AS 0 means "not routed" and is skipped.
  parse(text) {
    const lines = text.split('\n'), n = lines.length;
    const st = new Uint32Array(n), en = new Uint32Array(n), as = new Uint32Array(n), inf = new Uint32Array(n);
    const names = [], nameIdx = new Map();
    let k = 0;
    for (const l of lines) {
      const t = l.split('\t');
      if (t.length < 5 || t[2] === '0') continue;
      const a = ipv4ToInt(t[0]), b = ipv4ToInt(t[1]);
      if (a === null || b === null) continue;
      const key = `${t[3]}\t${t[4].trim()}`;
      let i = nameIdx.get(key);
      if (i === undefined) { i = names.length; names.push(Buffer.from(key).toString()); nameIdx.set(key, i); }   // a copy, so the 25 MB source text can be freed
      st[k] = a; en[k] = b; as[k] = +t[2]; inf[k] = i; k++;
    }
    return { start: st.slice(0, k), end: en.slice(0, k), asn: as.slice(0, k), info: inf.slice(0, k), names };
  }
  use(t) { Object.assign(this, t); this.meta.ranges = t.start.length; }

  load() {
    if (!this.on) return;
    try {
      const m = path.join(path.dirname(this.file), 'meta.json');
      if (fs.existsSync(m)) this.meta = { ...this.meta, ...JSON.parse(fs.readFileSync(m, 'utf8')) };
      if (fs.existsSync(this.file)) { this.use(this.parse(zlib.gunzipSync(fs.readFileSync(this.file)).toString('utf8'))); log.info(`${this.meta.ranges} ranges loaded`); }
    } catch (e) { log.warn(`cached table unusable: ${e.message}`); }
  }

  async refresh(force = false) {
    if (!this.on) return;
    if (!force && this.start.length && Date.now() - this.meta.updated < 7 * D) return;
    if (!force && this.meta.failed && Date.now() - this.meta.failed < 6 * 3600e3) return;
    try {
      const res = await fetch(this.url, { headers: { 'User-Agent': `argus/${cfg.version}` }, redirect: 'follow', signal: AbortSignal.timeout(180000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const gz = Buffer.from(await res.arrayBuffer());
      const t = this.parse(zlib.gunzipSync(gz).toString('utf8'));
      if (t.start.length < 100000) throw new Error(`only ${t.start.length} ranges`);
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      writeFileAtomic(this.file, gz);
      this.use(t);
      this.meta = { updated: Date.now(), ranges: t.start.length, error: '' };
      log.info(`${t.start.length} ranges`);
    } catch (e) {
      const msg = e.message + (e.cause ? ` (${e.cause.code || e.cause.message || e.cause})` : '');
      this.meta = { ...this.meta, failed: Date.now(), error: msg };
      log.warn(msg);
    }
    try { writeFileAtomic(path.join(path.dirname(this.file), 'meta.json'), JSON.stringify(this.meta)); } catch (e) { /* state not writable */ }
  }

  // { asn: 15169, cc: 'US', name: 'GOOGLE', label: 'AS15169 GOOGLE (US)' } or null.
  lookup(ip) {
    const n = ipv4ToInt(String(ip || ''));
    if (n === null || !this.start.length) return null;
    let lo = 0, hi = this.start.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.start[mid] > n) hi = mid - 1;
      else if (this.end[mid] < n) lo = mid + 1;
      else {
        const [cc, name] = this.names[this.info[mid]].split('\t');
        return { asn: this.asn[mid], cc, name, label: `AS${this.asn[mid]} ${name}${cc && cc !== 'None' ? ` (${cc})` : ''}` };
      }
    }
    return null;
  }

  status() { return { enabled: this.on, ...this.meta }; }
}

module.exports = { Asn };
