'use strict';
// Who owns an IP address: local copies of the iptoasn.com IPv4 and IPv6 tables
// (range → AS number, country, AS name), refreshed weekly. Lookups are a binary
// search in memory, so nothing about your traffic leaves the Mac. ARGUS_ASN=0 turns it off.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { cfg, env, logger, ipv4ToInt, writeFileAtomic } = require('./util');

const log = logger('asn');
const D = 86400e3;

// "2001:db8::1" → [hi, lo] as BigInts, or null. Handles "::" and a trailing dotted IPv4.
function ipv6ToBig(ip) {
  let s = String(ip || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (!s.includes(':')) return null;
  const v4 = s.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4) { const n = ipv4ToInt(v4[1]); if (n === null) return null; s = s.slice(0, -v4[1].length) + (n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16); }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const a = halves[0] ? halves[0].split(':') : [], b = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - a.length - b.length : 0;
  if (fill < 0 || (halves.length === 1 && a.length !== 8)) return null;
  const groups = [...a, ...Array(fill).fill('0'), ...b];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  let hi = 0n, lo = 0n;
  for (let i = 0; i < 4; i++) hi = (hi << 16n) | BigInt(parseInt(groups[i], 16));
  for (let i = 4; i < 8; i++) lo = (lo << 16n) | BigInt(parseInt(groups[i], 16));
  return [hi, lo];
}
const cmp6 = (ah, al, bh, bl) => ah < bh ? -1 : ah > bh ? 1 : al < bl ? -1 : al > bl ? 1 : 0;

// Parses "start\tend\tasn\tcc\tname" lines; AS 0 means "not routed" and is skipped.
function parseTable(text, v6) {
  const lines = text.split('\n'), n = lines.length;
  const st = v6 ? [new BigUint64Array(n), new BigUint64Array(n)] : new Uint32Array(n);
  const en = v6 ? [new BigUint64Array(n), new BigUint64Array(n)] : new Uint32Array(n);
  const as = new Uint32Array(n), inf = new Uint32Array(n);
  const names = [], nameIdx = new Map();
  let k = 0;
  for (const l of lines) {
    const t = l.split('\t');
    if (t.length < 5 || t[2] === '0') continue;
    const a = v6 ? ipv6ToBig(t[0]) : ipv4ToInt(t[0]), b = v6 ? ipv6ToBig(t[1]) : ipv4ToInt(t[1]);
    if (a === null || b === null) continue;
    const key = `${t[3]}\t${t[4].trim()}`;
    let i = nameIdx.get(key);
    if (i === undefined) { i = names.length; names.push(Buffer.from(key).toString()); nameIdx.set(key, i); }   // a copy, so the source text can be freed
    if (v6) { st[0][k] = a[0]; st[1][k] = a[1]; en[0][k] = b[0]; en[1][k] = b[1]; } else { st[k] = a; en[k] = b; }
    as[k] = +t[2]; inf[k] = i; k++;
  }
  const cut = x => v6 ? [x[0].slice(0, k), x[1].slice(0, k)] : x.slice(0, k);
  return { v6, start: cut(st), end: cut(en), asn: as.slice(0, k), info: inf.slice(0, k), names, size: k };
}

const empty = v6 => ({ v6, start: v6 ? [new BigUint64Array(0), new BigUint64Array(0)] : new Uint32Array(0), end: null, asn: new Uint32Array(0), info: new Uint32Array(0), names: [], size: 0 });

class Asn {
  constructor() {
    this.on = env('ARGUS_ASN', '1') !== '0';
    const base = env('ARGUS_ASN_URL', 'https://iptoasn.com/data/ip2asn-v4.tsv.gz');
    this.sets = [
      { id: 'v4', url: base, file: path.join(cfg.state, 'asn', 'ip2asn-v4.tsv.gz'), min: 100000, t: empty(false) },
      { id: 'v6', url: env('ARGUS_ASN6_URL', base.replace('-v4.', '-v6.')), file: path.join(cfg.state, 'asn', 'ip2asn-v6.tsv.gz'), min: 10000, t: empty(true) },
    ];
    this.meta = { updated: 0, ranges: 0, ranges6: 0, error: '' };
  }

  // Kept for tests and callers that hand in a table directly.
  parse(text, v6 = false) { return parseTable(text, v6); }
  use(t) { this.sets[t.v6 ? 1 : 0].t = t; this.meta.ranges = this.sets[0].t.size; this.meta.ranges6 = this.sets[1].t.size; }

  load() {
    if (!this.on) return;
    try { const m = path.join(cfg.state, 'asn', 'meta.json'); if (fs.existsSync(m)) this.meta = { ...this.meta, ...JSON.parse(fs.readFileSync(m, 'utf8')) }; } catch (e) { /* none */ }
    for (const s of this.sets) {
      try { if (fs.existsSync(s.file)) this.use(parseTable(zlib.gunzipSync(fs.readFileSync(s.file)).toString('utf8'), s.id === 'v6')); }
      catch (e) { log.warn(`${s.id}: cached table unusable: ${e.message}`); }
    }
    if (this.meta.ranges) log.info(`${this.meta.ranges} IPv4 and ${this.meta.ranges6} IPv6 ranges loaded`);
  }

  async refresh(force = false) {
    if (!this.on) return;
    const have = this.sets.every(s => s.t.size);
    if (!force && have && Date.now() - this.meta.updated < 7 * D) return;
    if (!force && this.meta.failed && Date.now() - this.meta.failed < 6 * 3600e3) return;
    const errors = [];
    for (const s of this.sets) {
      try {
        const res = await fetch(s.url, { headers: { 'User-Agent': `argus/${cfg.version}` }, redirect: 'follow', signal: AbortSignal.timeout(180000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const gz = Buffer.from(await res.arrayBuffer());
        const t = parseTable(zlib.gunzipSync(gz).toString('utf8'), s.id === 'v6');
        if (t.size < s.min) throw new Error(`only ${t.size} ranges`);
        writeFileAtomic(s.file, gz);
        this.use(t);
      } catch (e) {
        errors.push(`${s.id}: ${e.message}${e.cause ? ` (${e.cause.code || e.cause.message || e.cause})` : ''}`);
      }
    }
    if (errors.length) { this.meta = { ...this.meta, failed: Date.now(), error: errors.join('; ') }; log.warn(this.meta.error); }
    else { this.meta = { updated: Date.now(), ranges: this.sets[0].t.size, ranges6: this.sets[1].t.size, error: '' }; log.info(`${this.meta.ranges} IPv4 and ${this.meta.ranges6} IPv6 ranges`); }
    try { writeFileAtomic(path.join(cfg.state, 'asn', 'meta.json'), JSON.stringify(this.meta)); } catch (e) { /* state not writable */ }
  }

  // { asn: 15169, cc: 'US', name: 'GOOGLE', label: 'AS15169 GOOGLE (US)' } or null.
  lookup(ip) {
    const s = String(ip || '');
    let idx = -1, t;
    if (s.includes(':')) {
      t = this.sets[1].t; const b = ipv6ToBig(s);
      if (!b || !t.size) return null;
      if (b[0] === 0n && (b[1] >> 32n) === 0xffffn) return this.lookup([24n, 16n, 8n, 0n].map(sh => Number((b[1] >> sh) & 0xffn)).join('.'));   // ::ffff:1.2.3.4
      let lo = 0, hi = t.size - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (cmp6(t.start[0][mid], t.start[1][mid], b[0], b[1]) > 0) hi = mid - 1;
        else if (cmp6(t.end[0][mid], t.end[1][mid], b[0], b[1]) < 0) lo = mid + 1;
        else { idx = mid; break; }
      }
    } else {
      t = this.sets[0].t; const n = ipv4ToInt(s);
      if (n === null || !t.size) return null;
      let lo = 0, hi = t.size - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (t.start[mid] > n) hi = mid - 1;
        else if (t.end[mid] < n) lo = mid + 1;
        else { idx = mid; break; }
      }
    }
    if (idx < 0) return null;
    const [cc, name] = t.names[t.info[idx]].split('\t');
    return { asn: t.asn[idx], cc, name, label: `AS${t.asn[idx]} ${name}${cc && cc !== 'None' ? ` (${cc})` : ''}` };
  }

  status() { return { enabled: this.on, ...this.meta }; }
}

module.exports = { Asn, ipv6ToBig };
