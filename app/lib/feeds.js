'use strict';
// Threat-intel feeds: downloaded on a schedule, cached in the state volume,
// indexed in memory for exact / CIDR / parent-domain matching.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, logger, fetchText, ipv4ToInt, cidrRange, isDomain, writeFileAtomic } = require('./util');

const log = logger('feeds');
const H = 3600e3;

function defaultFeeds() {
  return [
    { id: 'hagezi_tif', name: `HaGeZi Threat Intelligence (${cfg.feeds.hageziList})`, kind: 'domain', format: 'wildcard', severity: 'high', ttl: 12 * H,
      url: `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/${cfg.feeds.hageziList}.txt`, info: 'Malware, phishing, C2, scam and cryptojacking domains aggregated from many sources.' },
    { id: 'firehol_l1', name: 'FireHOL Level 1', kind: 'ip', format: 'plain', severity: 'medium', ttl: 12 * H,
      url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', info: 'Attacks, malware, botnets and bogons; low false-positive.' },
    { id: 'ipsum', name: 'IPsum (on 3+ lists)', kind: 'ip', format: 'ipsum', minScore: 3, severity: 'medium', ttl: 12 * H,
      url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt', info: 'Daily aggregate of 30+ IP blocklists; only IPs listed on 3 or more are used.' },
    { id: 'feodo', name: 'abuse.ch Feodo Tracker (botnet C2)', kind: 'ip', format: 'plain', severity: 'high', ttl: 6 * H,
      url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', abusech: true, info: 'Active botnet command-and-control servers.' },
    { id: 'spamhaus_drop', name: 'Spamhaus DROP', kind: 'ip', format: 'spamhaus-json', severity: 'high', ttl: 24 * H,
      url: 'https://www.spamhaus.org/drop/drop_v4.json', info: 'Netblocks hijacked or leased by criminals.' },
    { id: 'et_compromised', name: 'Emerging Threats compromised IPs', kind: 'ip', format: 'plain', severity: 'medium', ttl: 24 * H,
      url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', info: 'Hosts seen attacking or compromised.' },
    { id: 'cins', name: 'CINS Army', kind: 'ip', format: 'plain', severity: 'medium', ttl: 24 * H,
      url: 'https://cinsscore.com/list/ci-badguys.txt', info: 'IPs with poor reputation from Sentinel IPS sensors.' },
    { id: 'blocklist_de', name: 'blocklist.de (all)', kind: 'ip', format: 'plain', severity: 'low', ttl: 12 * H,
      url: 'https://lists.blocklist.de/lists/all.txt', info: 'Attackers reported by fail2ban users in the last 48 h.' },
    { id: 'openphish', name: 'OpenPhish community', kind: 'domain', format: 'url', severity: 'high', ttl: 12 * H,
      url: 'https://openphish.com/feed.txt', info: 'Active phishing URLs (hosts are matched exactly).' },
    { id: 'urlhaus', name: 'abuse.ch URLhaus (online)', kind: 'domain', format: 'url', severity: 'high', ttl: 1 * H, needsKey: 'abusech',
      url: 'https://urlhaus.abuse.ch/downloads/text_online/', abusech: true, info: 'Malware distribution URLs that are currently online.' },
    ...cfg.feeds.nrd.filter(n => !/^(none|off)$/i.test(n)).map(n => ({ id: 'hagezi_' + n.replace(/[^a-z0-9]/gi, '_'), name: `HaGeZi newly registered domains (${n})`, kind: 'domain', format: 'domains-hashed', severity: 'low', ttl: 24 * H,
      url: `https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/${n}.txt`, info: 'Every domain registered in this window (millions; hashed in memory). NRDs are favoured for phishing and C2 — a hit alone is a weak signal.' })),
    { id: 'hagezi_dga14', name: 'HaGeZi NRD — high-entropy / DGA (14 days)', kind: 'domain', format: 'domains-hashed', severity: 'medium', ttl: 24 * H,
      url: 'https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/domains/dga14.txt', info: 'Newly registered domains with random-looking names typical of malware domain-generation algorithms.' },
    { id: 'tor_exit', name: 'Tor exit nodes', kind: 'ip', format: 'plain', severity: 'low', ttl: 6 * H,
      url: 'https://check.torproject.org/torbulkexitlist', info: 'Current Tor exit relays. Not malicious by itself; inbound logins from Tor deserve a look.' },
    { id: 'dshield_block', name: 'DShield top attacking /24s', kind: 'ip', format: 'dshield', severity: 'medium', ttl: 12 * H,
      url: 'https://feeds.dshield.org/block.txt', info: 'SANS Internet Storm Center: the 20 netblocks attacking the most sensors in the last 3 days.' },
    { id: 'threatfox', name: 'abuse.ch ThreatFox (7 days)', kind: 'mixed', format: 'threatfox', severity: 'high', ttl: 6 * H, needsKey: 'abusech',
      url: 'https://threatfox-api.abuse.ch/api/v1/', abusech: true, info: 'IOCs (C2 IPs, domains, URLs) tagged with malware family.' },
  ];
}

function emptyIndex() { return { ips: new Set(), ranges: [], domains: new Set(), hashed: null, wildcard: false, labels: new Map(), count: 0 }; }

// Multi-million-entry domain lists (NRD) are kept as sorted 53-bit hashes:
// ~8 bytes per domain instead of ~80 for a Set of strings.
function hash53(s) {
  let h1 = 0x811c9dc5, h2 = 5381;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0; h2 = (Math.imul(h2, 33) + c) >>> 0; }
  return h1 * 2097152 + (h2 & 0x1fffff);
}
function hashedHas(arr, s) {
  const h = hash53(s); let lo = 0, hi = arr.length - 1;
  while (lo <= hi) { const mid = (lo + hi) >> 1; const v = arr[mid]; if (v === h) return true; if (v < h) lo = mid + 1; else hi = mid - 1; }
  return false;
}
function parseHashed(text) {
  let arr = new Float64Array(1 << 20), n = 0, start = 0;
  const len = text.length;
  while (start < len) {
    let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
    let line = text.slice(start, nl).trim().toLowerCase(); start = nl + 1;
    if (!line || line[0] === '#' || line[0] === '!') continue;
    line = line.replace(/^\|\||\^$/g, '').replace(/^\*\./, '').replace(/\.$/, '');
    if (!line.includes('.')) continue;
    if (n === arr.length) { const b = new Float64Array(arr.length * 2); b.set(arr); arr = b; }
    arr[n++] = hash53(line);
  }
  const out = arr.slice(0, n).sort();
  const idx = emptyIndex(); idx.hashed = out; idx.count = n; idx.wildcard = true;
  return idx;
}

function addToken(idx, tok, label) {
  tok = String(tok || '').trim().toLowerCase();
  if (!tok) return;
  if (tok.includes('/') && /^\d/.test(tok)) { const r = cidrRange(tok); if (r) { idx.ranges.push(r); idx.count++; if (label) idx.labels.set(tok, label); } return; }
  if (ipv4ToInt(tok) !== null) { idx.ips.add(tok); idx.count++; if (label) idx.labels.set(tok, label); return; }
  tok = tok.replace(/^\*\./, '').replace(/\.$/, '');
  if (isDomain(tok)) { idx.domains.add(tok); idx.count++; if (label) idx.labels.set(tok, label); }
}
function hostOf(u) {
  try { return new URL(u.trim()).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch (e) { return ''; }
}

function parseFeed(def, text) {
  if (def.format === 'domains-hashed') return parseHashed(text);
  const idx = emptyIndex();
  idx.wildcard = def.format === 'wildcard';
  if (def.format === 'threatfox') {
    let j; try { j = JSON.parse(text); } catch (e) { throw new Error('ThreatFox: invalid JSON'); }
    if (j.query_status && j.query_status !== 'ok') throw new Error(`ThreatFox: ${j.query_status}`);
    for (const x of j.data || []) {
      const label = [x.malware_printable, x.threat_type].filter(Boolean).join(' · ');
      if (/^ip/.test(x.ioc_type)) addToken(idx, String(x.ioc).replace(/:\d+$/, ''), label);
      else if (x.ioc_type === 'domain') addToken(idx, x.ioc, label);
      else if (x.ioc_type === 'url') addToken(idx, hostOf(x.ioc), label);
    }
  } else if (def.format === 'dshield') {
    for (const line of text.split('\n')) {
      const f = line.replace(/#.*$/, '').trim().split(/\s+/);
      if (f.length >= 3 && ipv4ToInt(f[0]) !== null && /^\d+$/.test(f[2])) addToken(idx, `${f[0]}/${f[2]}`, [f[3] ? `${f[3]} targets` : '', f[4] && f[4] !== '-' ? f[4] : ''].filter(Boolean).join(' · '));
    }
  } else if (def.format === 'spamhaus-json') {
    for (const line of text.split('\n')) {
      if (!line.startsWith('{')) continue;
      try { const o = JSON.parse(line); if (o.cidr) addToken(idx, o.cidr, o.sblid || ''); } catch (e) { /* metadata line */ }
    }
  } else {
    for (let line of text.split('\n')) {
      line = line.replace(/[#;].*$/, '').trim();
      if (!line) continue;
      if (def.format === 'ipsum') {
        const [ip, n] = line.split(/\s+/);
        if (+n >= (def.minScore || 1)) addToken(idx, ip, `on ${n} lists`);
      } else if (def.format === 'url') {
        addToken(idx, hostOf(line));
      } else {
        addToken(idx, line.split(/\s+/)[0]);
      }
    }
  }
  idx.ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of idx.ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]); else merged.push([r[0], r[1]]);
  }
  idx.ranges = merged;
  return idx;
}

function inRanges(ranges, n) {
  let lo = 0, hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (n < ranges[mid][0]) hi = mid - 1; else if (n > ranges[mid][1]) lo = mid + 1; else return true;
  }
  return false;
}

class Feeds {
  constructor(store) {
    this.store = store;
    this.dir = path.join(cfg.state, 'feeds');
    fs.mkdirSync(this.dir, { recursive: true });
    this.defs = defaultFeeds();
    const extra = path.join(cfg.data, 'config', 'feeds.json');
    try { if (fs.existsSync(extra)) this.defs.push(...JSON.parse(fs.readFileSync(extra, 'utf8')).map(f => ({ severity: 'medium', ...f, ttl: (f.ttlHours || 12) * H }))); }
    catch (e) { log.warn(`ignoring ${extra}: ${e.message}`); }
    this.idx = new Map();
    this.meta = new Map();
    this.version = 0;
  }
  enabled(def) {
    if (cfg.feeds.disabled.has(def.id)) return { on: false, why: 'disabled in settings' };
    if (def.needsKey && !cfg.keys[def.needsKey]) return { on: false, why: 'needs ABUSECH_AUTH_KEY' };
    return { on: true };
  }
  loadCache() {
    for (const def of this.defs) {
      const f = path.join(this.dir, def.id + '.txt');
      const m = path.join(this.dir, def.id + '.json');
      try { this.meta.set(def.id, JSON.parse(fs.readFileSync(m, 'utf8'))); } catch (e) { /* none yet */ }
      if (!this.enabled(def).on || !fs.existsSync(f)) continue;
      try { this.idx.set(def.id, parseFeed(def, fs.readFileSync(f, 'utf8'))); } catch (e) { log.warn(`${def.id}: cached copy unusable: ${e.message}`); }
    }
    this.version++;
    log.info(`loaded ${this.idx.size} cached feeds`);
  }
  async refresh(force = false) {
    let changed = false;
    for (const def of this.defs) {
      if (!this.enabled(def).on) continue;
      const meta = this.meta.get(def.id) || {};
      if (!force && meta.updated && Date.now() - meta.updated < def.ttl && this.idx.has(def.id)) continue;
      if (!force && meta.failed && Date.now() - meta.failed < 30 * 60e3) continue;
      try {
        const headers = def.abusech && cfg.keys.abusech ? { 'Auth-Key': cfg.keys.abusech } : {};
        const opts = { headers, timeout: 120000, maxBytes: 150e6 };
        if (def.format === 'threatfox') { opts.method = 'POST'; opts.body = JSON.stringify({ query: 'get_iocs', days: 7 }); opts.headers['Content-Type'] = 'application/json'; }
        const r = await fetchText(def.url, opts);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const idx = parseFeed(def, r.text);
        if (idx.count === 0) throw new Error('feed parsed to 0 entries');
        writeFileAtomic(path.join(this.dir, def.id + '.txt'), r.text);
        this.idx.set(def.id, idx);
        this.meta.set(def.id, { updated: Date.now(), count: idx.count, bytes: r.text.length, error: '' });
        changed = true;
        log.info(`${def.id}: ${idx.count} entries`);
      } catch (e) {
        // node's fetch throws a generic "fetch failed" and buries the real reason
        // (DNS, TLS, connection refused) in e.cause — surface it so this is diagnosable.
        const cause = e.cause ? ` (${e.cause.code || e.cause.message || e.cause})` : '';
        const msg = e.message + cause;
        this.meta.set(def.id, { ...meta, failed: Date.now(), error: msg });
        log.warn(`${def.id}: ${msg}`);
      }
      writeFileAtomic(path.join(this.dir, def.id + '.json'), JSON.stringify(this.meta.get(def.id)));
    }
    if (changed) this.version++;
    return changed;
  }
  match(value, type) {
    const hits = [];
    if (type === 'ip') {
      const n = ipv4ToInt(value);
      for (const [id, idx] of this.idx) {
        if (idx.ips.has(value)) hits.push({ feed: id, matched: value, label: idx.labels.get(value) || '' });
        else if (n !== null && idx.ranges.length && inRanges(idx.ranges, n)) hits.push({ feed: id, matched: 'range', label: '' });
      }
    } else if (type === 'domain') {
      const parts = value.split('.');
      for (const [id, idx] of this.idx) {
        if (idx.hashed) {
          for (let i = 0; i < parts.length - 1; i++) {
            const d = parts.slice(i).join('.');
            if (hashedHas(idx.hashed, d)) { hits.push({ feed: id, matched: d, label: '' }); break; }
          }
          continue;
        }
        if (!idx.domains.size) continue;
        if (idx.domains.has(value)) { hits.push({ feed: id, matched: value, label: idx.labels.get(value) || '' }); continue; }
        if (!idx.wildcard) continue;
        for (let i = 1; i < parts.length - 1; i++) {
          const parent = parts.slice(i).join('.');
          if (idx.domains.has(parent)) { hits.push({ feed: id, matched: parent, label: idx.labels.get(parent) || '' }); break; }
        }
      }
    }
    return hits.map(h => ({ ...h, name: (this.defs.find(d => d.id === h.feed) || {}).name || h.feed, severity: (this.defs.find(d => d.id === h.feed) || {}).severity || 'medium' }));
  }
  status() {
    return this.defs.map(d => {
      const m = this.meta.get(d.id) || {}, en = this.enabled(d), idx = this.idx.get(d.id);
      return { id: d.id, name: d.name, kind: d.kind, severity: d.severity, info: d.info, url: d.url, enabled: en.on, why: en.why || '',
        entries: idx ? idx.count : 0, updated: m.updated || null, error: m.error || '', ttlHours: d.ttl / H };
    });
  }
}

module.exports = { Feeds, parseFeed };
