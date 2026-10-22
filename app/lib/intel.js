'use strict';
// Indicators (IPs, domains) seen anywhere, matched against feeds and CrowdSec,
// enriched with OSINT providers, and scored.
const dns = require('node:dns').promises;
const engine = require('./engine');
const { cfg, logger, fetchJson, classifyValue, dayKey } = require('./util');

const log = logger('intel');
const D = 86400e3;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const SOURCE_PRIORITY = { manual: 3, ssh: 2, screensharing: 2, firewall: 2, 'dns-heuristic': 2, download: 2, connection: 1, resolved: 1, syslog: 1, dns: 0 };
const srcPrio = s => SOURCE_PRIORITY[s] ?? SOURCE_PRIORITY[String(s).split(':')[0]] ?? 0;
const verdictScore = { malicious: 80, suspicious: 50 };

function providers(self) {
  const k = cfg.keys;
  const P = [
    { id: 'rdap', name: 'RDAP domain age', types: ['domain'], ttl: 30 * D, daily: cfg.osint.rdapDaily, gap: 1500, minPriority: cfg.osint.enrichDomains ? 0 : 2, enabled: () => true,
      run: v => self.rdap(v) },
    { id: 'internetdb', name: 'Shodan InternetDB', types: ['ip'], ttl: 3 * D, daily: 3000, gap: 400, minPriority: 1, enabled: () => true,
      run: async v => {
        const r = await fetchJson(`https://internetdb.shodan.io/${v}`, { timeout: 15000 });
        if (r.status === 404) return { verdict: 'unknown', summary: 'no Shodan data' };
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const j = r.json, tags = j.tags || [];
        const bad = tags.filter(t => /malware|c2|compromised|botnet/i.test(t));
        const sus = tags.filter(t => /scanner|tor|honeypot/i.test(t));
        return { verdict: bad.length ? 'malicious' : sus.length ? 'suspicious' : 'clean', score: bad.length ? 80 : sus.length ? 45 : 0,
          summary: `ports ${(j.ports || []).slice(0, 12).join(', ') || 'none'}; tags ${tags.join(', ') || 'none'}${(j.hostnames || []).length ? '; ' + j.hostnames.slice(0, 3).join(', ') : ''}${(j.vulns || []).length ? `; ${j.vulns.length} known CVEs` : ''}`,
          link: `https://internetdb.shodan.io/${v}`, data: j };
      } },
    { id: 'crowdsec_cti', name: 'CrowdSec CTI', types: ['ip'], ttl: 1 * D, daily: +process.env.CROWDSEC_CTI_DAILY || 30, gap: 2000, minPriority: 2, enabled: () => !!k.crowdsecCti,
      run: async v => {
        const r = await fetchJson(`https://cti.api.crowdsec.net/v2/smoke/${v}`, { headers: { 'x-api-key': k.crowdsecCti }, timeout: 15000 });
        if (r.status === 404) return { verdict: 'clean', summary: 'not seen by the CrowdSec network', link: `https://app.crowdsec.net/cti/${v}` };
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const j = r.json, rep = j.reputation || 'unknown';
        const beh = (j.behaviors || []).map(b => b.label || b.name).slice(0, 4).join(', ');
        return { verdict: rep === 'malicious' ? 'malicious' : rep === 'suspicious' ? 'suspicious' : rep === 'safe' ? 'clean' : 'unknown',
          score: rep === 'malicious' ? 85 : rep === 'suspicious' ? 55 : 0, summary: `${rep}${beh ? '; ' + beh : ''}${j.as_name ? '; ' + j.as_name : ''}`,
          link: `https://app.crowdsec.net/cti/${v}`, data: { reputation: rep, behaviors: j.behaviors, classifications: j.classifications, scores: j.scores } };
      } },
    { id: 'abuseipdb', name: 'AbuseIPDB', types: ['ip'], ttl: 1 * D, daily: 900, gap: 1000, minPriority: 1, enabled: () => !!k.abuseipdb,
      run: async v => {
        const r = await fetchJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(v)}&maxAgeInDays=90`, { headers: { Key: k.abuseipdb, Accept: 'application/json' }, timeout: 15000 });
        if (!r.ok || !r.json || !r.json.data) throw new Error(`HTTP ${r.status}`);
        const d = r.json.data, c = d.abuseConfidenceScore || 0;
        return { verdict: c >= 75 ? 'malicious' : c >= 25 ? 'suspicious' : 'clean', score: c >= 25 ? Math.max(40, c) : 0,
          summary: `confidence ${c}%, ${d.totalReports || 0} reports; ${d.isp || ''} ${d.countryCode ? '(' + d.countryCode + ')' : ''}`.trim(), link: `https://www.abuseipdb.com/check/${v}`, data: d };
      } },
    { id: 'greynoise', name: 'GreyNoise', types: ['ip'], ttl: 1 * D, daily: 100, gap: 2000, minPriority: 1, enabled: () => !!k.greynoise,
      run: async v => {
        const r = await fetchJson(`https://api.greynoise.io/v3/community/${v}`, { headers: { key: k.greynoise, Accept: 'application/json' }, timeout: 15000 });
        if (r.status === 404) return { verdict: 'unknown', summary: 'not observed scanning the internet' };
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const j = r.json;
        const verdict = j.classification === 'malicious' ? 'malicious' : j.riot || j.classification === 'benign' ? 'clean' : j.noise ? 'suspicious' : 'unknown';
        return { verdict, score: verdict === 'malicious' ? 75 : verdict === 'suspicious' ? 40 : 0, summary: `${j.classification || 'unknown'}${j.noise ? ', internet scanner' : ''}${j.riot ? ', common business service' : ''}${j.name ? ' — ' + j.name : ''}`, link: j.link || '', data: j };
      } },
    { id: 'virustotal', name: 'VirusTotal', types: ['ip', 'domain'], ttl: 1 * D, daily: 450, gap: 16000, minPriority: 2, enabled: () => !!k.virustotal,
      run: async (v, t) => {
        const kind = t === 'ip' ? 'ip_addresses' : 'domains';
        const r = await fetchJson(`https://www.virustotal.com/api/v3/${kind}/${v}`, { headers: { 'x-apikey': k.virustotal }, timeout: 20000 });
        if (r.status === 404) return { verdict: 'unknown', summary: 'unknown to VirusTotal' };
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const s = (r.json.data && r.json.data.attributes && r.json.data.attributes.last_analysis_stats) || {};
        const m = s.malicious || 0, sus = s.suspicious || 0, total = m + sus + (s.harmless || 0) + (s.undetected || 0);
        return { verdict: m >= 3 ? 'malicious' : (m >= 1 || sus >= 2) ? 'suspicious' : 'clean', score: m >= 3 ? Math.min(95, 75 + m) : (m >= 1 || sus >= 2) ? 50 : 0,
          summary: `${m} malicious / ${sus} suspicious of ${total} engines`, link: `https://www.virustotal.com/gui/${t === 'ip' ? 'ip-address' : 'domain'}/${v}`, data: s };
      } },
    { id: 'otx', name: 'AlienVault OTX', types: ['ip', 'domain'], ttl: 1 * D, daily: 2000, gap: 1000, minPriority: 1, enabled: () => !!k.otx,
      run: async (v, t) => {
        const kind = t === 'domain' ? 'domain' : v.includes(':') ? 'IPv6' : 'IPv4';
        const r = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/${kind}/${v}/general`, { headers: { 'X-OTX-API-KEY': k.otx }, timeout: 20000 });
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const p = r.json.pulse_info || {}, n = p.count || 0;
        return { verdict: n ? 'suspicious' : 'clean', score: n >= 3 ? 55 : n ? 40 : 0, summary: n ? `${n} OTX pulses: ${(p.pulses || []).slice(0, 3).map(x => x.name).join('; ')}` : 'no OTX pulses',
          link: `https://otx.alienvault.com/indicator/${t === 'domain' ? 'domain' : 'ip'}/${v}` };
      } },
    { id: 'urlscan', name: 'urlscan.io', types: ['domain', 'ip'], ttl: 1 * D, daily: +process.env.URLSCAN_DAILY || 300, gap: 2500, minPriority: 2, enabled: () => !!k.urlscan,
      run: async (v, t) => {
        const q = `${t === 'ip' ? 'page.ip' : 'page.domain'}:"${v}" AND verdicts.malicious:true`;
        const r = await fetchJson(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`, { headers: { 'API-Key': k.urlscan, Accept: 'application/json' }, timeout: 20000 });
        if (r.status === 429) throw new Error('rate limited (429)');
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const n = r.json.total || (r.json.results || []).length || 0;
        const last = (r.json.results || [])[0];
        return { verdict: n >= 2 ? 'malicious' : n ? 'suspicious' : 'unknown', score: n >= 2 ? 80 : n ? 55 : 0,
          summary: n ? `${n} scan(s) with a malicious verdict${last && last.task ? `; latest ${String(last.task.time || '').slice(0, 10)} ${last.page && last.page.url ? last.page.url.slice(0, 120) : ''}` : ''}` : 'no malicious verdicts on urlscan.io',
          link: `https://urlscan.io/search/#${encodeURIComponent(t === 'ip' ? 'page.ip:"' + v + '"' : 'page.domain:"' + v + '"')}` };
      } },
    { id: 'urlhaus', name: 'abuse.ch URLhaus', types: ['domain', 'ip'], ttl: 1 * D, daily: 3000, gap: 500, minPriority: 1, enabled: () => !!k.abusech,
      run: async v => {
        const r = await fetchJson('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: { 'Auth-Key': k.abusech, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `host=${encodeURIComponent(v)}`, timeout: 20000 });
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        const j = r.json;
        if (j.query_status === 'no_results') return { verdict: 'clean', summary: 'no malware URLs on this host' };
        if (j.query_status !== 'ok') throw new Error(j.query_status || 'bad response');
        const online = (j.urls || []).filter(u => u.url_status === 'online').length;
        return { verdict: online ? 'malicious' : 'suspicious', score: online ? 90 : 60, summary: `${j.url_count || 0} malware URLs (${online} online)`, link: `https://urlhaus.abuse.ch/host/${v}/` };
      } },
    { id: 'threatfox', name: 'abuse.ch ThreatFox', types: ['domain', 'ip'], ttl: 1 * D, daily: 2000, gap: 1000, minPriority: 2, enabled: () => !!k.abusech,
      run: async v => {
        const r = await fetchJson('https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': k.abusech, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'search_ioc', search_term: v }), timeout: 20000 });
        if (!r.ok || !r.json) throw new Error(`HTTP ${r.status}`);
        if (r.json.query_status !== 'ok') return { verdict: 'clean', summary: 'not in ThreatFox' };
        const d = r.json.data || [];
        return { verdict: 'malicious', score: 90, summary: `${d.length} IOC(s): ${[...new Set(d.map(x => x.malware_printable))].slice(0, 4).join(', ')}`, link: `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(v)}` };
      } },
    { id: 'dns', name: 'DNS resolution', types: ['domain'], ttl: 1 * D, daily: 5000, gap: 200, minPriority: 2, enabled: () => true,
      run: async v => {
        const ips = [];
        try { ips.push(...await dns.resolve4(v)); } catch (e) { /* no A */ }
        try { ips.push(...await dns.resolve6(v)); } catch (e) { /* no AAAA */ }
        ips.forEach(ip => self.observe(ip, 'ip', 'resolved', `resolved from ${v}`));
        return { verdict: 'info', summary: ips.length ? ips.slice(0, 8).join(', ') : 'does not resolve', data: { ips } };
      } },
    { id: 'crtsh', name: 'crt.sh certificates', types: ['domain'], ttl: 7 * D, daily: 200, gap: 3000, minPriority: 99, manualOnly: true, enabled: () => true,
      run: async v => {
        const base = engine.baseDomain(v);
        const r = await fetchJson(`https://crt.sh/?q=${encodeURIComponent(base)}&output=json`, { timeout: 60000 });
        if (!r.ok || !Array.isArray(r.json)) throw new Error(`HTTP ${r.status}`);
        const certs = r.json;
        const first = certs.map(c => Date.parse(c.not_before)).filter(Boolean).sort((a, b) => a - b)[0];
        const age = first ? Math.round((Date.now() - first) / D) : null;
        const issuers = [...new Set(certs.map(c => String(c.issuer_name || '').replace(/^.*O=([^,]+).*$/, '$1')))].slice(0, 4);
        return { verdict: age !== null && age < 30 ? 'suspicious' : 'info', score: age !== null && age < 30 ? 40 : 0,
          summary: `${certs.length} certificates for ${base}; first issued ${age === null ? '?' : age + ' d ago'}; issuers ${issuers.join(', ')}`, link: `https://crt.sh/?q=${encodeURIComponent(base)}` };
      } },
    { id: 'intelowl', name: 'IntelOwl', types: ['ip', 'domain'], ttl: 3 * D, daily: cfg.intelowl.dailyLimit, gap: 3000, minPriority: cfg.intelowl.auto ? 3 : 99, enabled: () => !!(cfg.intelowl.url && cfg.intelowl.token),
      run: (v, t) => self.intelowl(v, t) },
  ];
  return P;
}

class Intel {
  constructor(store, feeds, crowdsec) {
    this.store = store; this.feeds = feeds; this.cs = crowdsec;
    this.providers = providers(this);
    this.busy = new Set();
    this.feedVersion = -1; this.csVersion = -1;
    this.lastError = {};
  }

  // ---------------------------------------------------------------- observe
  observe(raw, type, source, context = '', hits = 1, now = Date.now()) {
    const c = classifyValue(raw);
    if (!c || (type && c.type !== type)) return null;
    const { value } = c; type = c.type;
    if (type === 'ip' && engine.ipScope(value) !== 'public') return null;
    if (type === 'domain' && engine.SKIP_DNS.test(value)) return null;
    const s = this.store;
    const row = s.get('SELECT sources, priority FROM observables WHERE value = ? AND type = ?', value, type);
    const prio = srcPrio(source);
    if (!row) {
      s.run('INSERT INTO observables(value, type, first_seen, last_seen, hits, sources, context, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        value, type, now, now, hits, JSON.stringify([source]), String(context).slice(0, 300), prio);
      this.matchOne(value, type, now);
      return { value, type, created: true };
    }
    const sources = JSON.parse(row.sources);
    if (!sources.includes(source)) { sources.push(source); if (sources.length > 20) sources.shift(); }
    s.run('UPDATE observables SET last_seen = ?, hits = hits + ?, sources = ?, priority = MAX(priority, ?), context = CASE WHEN ? = \'\' THEN context ELSE ? END WHERE value = ? AND type = ?',
      now, hits, JSON.stringify(sources), prio, source === 'dns' ? '' : String(context), String(context).slice(0, 300), value, type);
    return { value, type, created: false };
  }
  observeMany(items) { // [{value,type,source,context,hits}]
    if (!items.length) return;
    this.store.tx(() => { for (const i of items) this.observe(i.value, i.type, i.source, i.context, i.hits || 1, i.now); });
  }
  addFromEngine(iocs) {
    const items = [];
    for (const i of iocs || []) for (const src of String(i.sources).split(', ')) items.push({ value: i.value, type: i.type, source: src === 'dns' ? 'dns-heuristic' : src, context: i.context, hits: 0 });
    this.observeMany(items);
  }

  // --------------------------------------------------------------- matching
  matchOne(value, type, now = Date.now()) {
    const hits = this.feeds.match(value, type);
    for (const h of hits) {
      this.store.run(`INSERT INTO feed_hits(value, type, feed, matched, label, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(value, type, feed) DO UPDATE SET last_seen = excluded.last_seen, matched = excluded.matched, label = excluded.label`, value, type, h.feed, h.matched, h.label || '', now, now);
    }
    if (hits.length || (type === 'ip' && this.cs.match(value))) this.recompute(value, type);
  }
  rematchIfNeeded() {
    if (this.feeds.version !== this.feedVersion) {
      const rows = this.store.all('SELECT value, type FROM observables');
      this.store.tx(() => { for (const r of rows) this.matchOne(r.value, r.type); });
      this.feedVersion = this.feeds.version;
      log.info(`re-matched ${rows.length} observables against feeds`);
    }
    if (this.cs.version !== this.csVersion) {
      const rows = this.store.all("SELECT value FROM observables WHERE type = 'ip'");
      this.store.tx(() => { for (const r of rows) this.recompute(r.value, 'ip'); });
      this.csVersion = this.cs.version;
    }
  }

  recompute(value, type) {
    const reasons = []; let score = 0, enriched = false, anyClean = false;
    const name = id => (this.providers.find(p => p.id === id) || {}).name || id;
    for (const h of this.store.all('SELECT f.feed, f.matched, f.label FROM feed_hits f WHERE f.value = ? AND f.type = ?', value, type)) {
      const def = this.feeds.defs.find(d => d.id === h.feed) || {};
      const sc = def.severity === 'high' ? 90 : def.severity === 'low' ? 45 : 65;
      score = Math.max(score, sc);
      reasons.push(`feed: ${def.name || h.feed}${h.matched && h.matched !== value && h.matched !== 'range' ? ` (via ${h.matched})` : ''}${h.label ? ` — ${h.label}` : ''}`);
    }
    if (type === 'ip') {
      const d = this.cs.match(value);
      if (d) {
        const local = /^(crowdsec|cscli)$/i.test(d.origin);
        score = Math.max(score, local ? 90 : 70);
        reasons.push(`CrowdSec ${local ? 'local detection' : (d.origin === 'CAPI' ? 'community blocklist' : d.origin)}: ${d.scenario}`);
      }
    }
    for (const e of this.store.all('SELECT provider, verdict, score, summary FROM enrichments WHERE value = ? AND type = ? AND error IS NULL', value, type)) {
      enriched = true;
      if (e.verdict === 'clean') anyClean = true;
      if (e.verdict === 'malicious' || e.verdict === 'suspicious') {
        score = Math.max(score, e.score || verdictScore[e.verdict]);
        reasons.push(`${name(e.provider)}: ${e.summary}`);
      }
    }
    const risk = score >= 75 ? 'malicious' : score >= 40 ? 'suspicious' : (enriched && anyClean) ? 'clean' : 'unknown';
    this.store.run('UPDATE observables SET risk = ?, risk_score = ?, reasons = ?, priority = CASE WHEN ? >= 40 THEN MAX(priority, 3) ELSE priority END, enriched_at = CASE WHEN ? THEN ? ELSE enriched_at END WHERE value = ? AND type = ?',
      risk, score, JSON.stringify(reasons), score, enriched ? 1 : 0, Date.now(), value, type);
  }

  // ------------------------------------------------------------- enrichment
  usage(p) { const r = this.store.get('SELECT calls FROM provider_usage WHERE day = ? AND provider = ?', dayKey(), p.id); return r ? r.calls : 0; }
  bumpUsage(p) { this.store.run('INSERT INTO provider_usage(day, provider, calls) VALUES (?, ?, 1) ON CONFLICT(day, provider) DO UPDATE SET calls = calls + 1', dayKey(), p.id); }

  async runProvider(p, value, type) {
    let res = null;
    try {
      res = await p.run(value, type);
      if (!res.cached) this.bumpUsage(p);
      this.store.run(`INSERT INTO enrichments(value, type, provider, fetched_at, verdict, score, summary, link, data, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(value, type, provider) DO UPDATE SET fetched_at = excluded.fetched_at, verdict = excluded.verdict, score = excluded.score, summary = excluded.summary, link = excluded.link, data = excluded.data, error = NULL`,
        value, type, p.id, Date.now(), res.verdict || 'unknown', res.score || 0, String(res.summary || '').slice(0, 500), res.link || '', res.data ? JSON.stringify(res.data).slice(0, 20000) : null);
      if (!res.cached) delete this.lastError[p.id];
    } catch (e) {
      this.bumpUsage(p);
      this.lastError[p.id] = { msg: e.message, at: Date.now() };
      this.store.run(`INSERT INTO enrichments(value, type, provider, fetched_at, verdict, score, summary, error) VALUES (?, ?, ?, ?, 'error', 0, '', ?)
        ON CONFLICT(value, type, provider) DO UPDATE SET fetched_at = excluded.fetched_at, verdict = 'error', error = excluded.error`, value, type, p.id, Date.now(), e.message.slice(0, 300));
    }
    this.recompute(value, type);
    return res;
  }

  // Background queue: each provider works through its own candidate list.
  async tick() {
    this.rematchIfNeeded();
    await Promise.all(this.providers.map(async p => {
      if (this.busy.has(p.id) || p.manualOnly || !p.enabled()) return;
      const left = p.daily - this.usage(p);
      if (left <= 0) return;
      const n = Math.min(left, Math.max(1, Math.floor(cfg.osint.autoEvery / p.gap)), 10);
      const types = p.types.map(t => `'${t}'`).join(',');
      const rows = this.store.all(`SELECT o.value, o.type FROM observables o
        LEFT JOIN enrichments e ON e.value = o.value AND e.type = o.type AND e.provider = ?
        WHERE o.type IN (${types}) AND o.priority >= ? AND (e.fetched_at IS NULL OR e.fetched_at < ?)
        ORDER BY o.priority DESC, o.last_seen DESC LIMIT ?`, p.id, p.minPriority, Date.now() - p.ttl, n);
      if (!rows.length) return;
      this.busy.add(p.id);
      try {
        for (const r of rows) {
          const res = await this.runProvider(p, r.value, r.type);
          if (!res || !res.cached) await sleep(p.gap);
        }
      }
      finally { this.busy.delete(p.id); }
    }));
  }

  async lookup(raw) {
    const c = classifyValue(raw);
    if (!c) throw new Error('not an IP address, domain or URL');
    const isPublic = c.type !== 'ip' || engine.ipScope(c.value) === 'public';
    if (!isPublic) throw new Error('private or reserved address: nothing to look up');
    this.observe(c.value, c.type, 'manual', 'manual lookup');
    const ps = this.providers.filter(p => p.types.includes(c.type) && p.enabled() && this.usage(p) < p.daily);
    const quick = ps.filter(p => p.id !== 'intelowl');
    await Promise.allSettled(quick.map(p => this.runProvider(p, c.value, c.type)));
    const io = ps.find(p => p.id === 'intelowl');
    if (io) this.runProvider(io, c.value, c.type).catch(() => {});
    return this.detail(c.value, c.type);
  }

  detail(value, type) {
    const o = this.store.get('SELECT * FROM observables WHERE value = ? AND type = ?', value, type);
    if (!o) return null;
    const enrich = this.store.all('SELECT provider, fetched_at, verdict, score, summary, link, error FROM enrichments WHERE value = ? AND type = ? ORDER BY score DESC, provider', value, type)
      .map(e => ({ ...e, name: (this.providers.find(p => p.id === e.provider) || {}).name || e.provider }));
    const feeds = this.store.all('SELECT feed, matched, label, first_seen, last_seen FROM feed_hits WHERE value = ? AND type = ?', value, type)
      .map(f => ({ ...f, name: (this.feeds.defs.find(d => d.id === f.feed) || {}).name || f.feed }));
    const pending = this.providers.filter(p => p.types.includes(type) && p.enabled() && !enrich.some(e => e.provider === p.id)).map(p => p.name);
    return { ...rowOut(o), enrichments: enrich, feedHits: feeds, crowdsec: type === 'ip' ? this.cs.match(value) : null, pending };
  }

  list({ q = '', type = '', risk = '', source = '', limit = 200, offset = 0 } = {}) {
    const where = [], p = [];
    if (q) { where.push('value LIKE ?'); p.push(`%${q.toLowerCase()}%`); }
    if (type) { where.push('type = ?'); p.push(type); }
    if (risk === 'flagged') where.push('risk_score >= 40');
    else if (risk) { where.push('risk = ?'); p.push(risk); }
    if (source) { where.push('sources LIKE ?'); p.push(`%"${source}%`); }
    const w = where.length ? 'WHERE ' + where.join(' AND ') : '';
    const total = this.store.db.prepare(`SELECT COUNT(*) AS n FROM observables ${w}`).get(...p).n;
    const rows = this.store.db.prepare(`SELECT * FROM observables ${w} ORDER BY risk_score DESC, last_seen DESC LIMIT ? OFFSET ?`).all(...p, Math.min(+limit || 200, 5000), +offset || 0);
    return { total, rows: rows.map(rowOut) };
  }

  counts() {
    const r = this.store.get(`SELECT COUNT(*) AS total, SUM(risk = 'malicious') AS malicious, SUM(risk = 'suspicious') AS suspicious,
      SUM(type = 'ip') AS ips, SUM(type = 'domain') AS domains, SUM(enriched_at IS NOT NULL) AS enriched FROM observables`);
    const fh = this.store.get('SELECT COUNT(DISTINCT value) AS n FROM feed_hits').n;
    return { ...r, feedHits: fh };
  }

  // Reputation hits on the big clouds' shared addresses are mostly noise: earlier
  // tenants' abuse reports and crowd-sourced pulses stick to the IP. An outbound IP
  // owned by one of these, flagged only by reputation (no high-severity feed, no
  // CrowdSec local detection) and contacted only by Apple-signed programs or a
  // browser, is shown as low instead of medium/high. ARGUS_TRUSTED_CLOUDS=off disables.
  cloudOwner(o) {
    const list = String(process.env.ARGUS_TRUSTED_CLOUDS ?? 'Apple,Google,Amazon,Microsoft,Cloudflare').split(',').map(x => x.trim()).filter(Boolean);
    if (!list.length || /^(off|0|no|none)$/i.test(list[0])) return '';
    if (/^17\./.test(o.value) && list.some(x => /^apple$/i.test(x))) return 'Apple';
    const text = o.reasons.join(' ') + ' ' + this.store.all("SELECT summary FROM enrichments WHERE value = ? AND type = 'ip' AND error IS NULL", o.value).map(e => e.summary).join(' ');
    const alias = { amazon: 'amazon|aws', microsoft: 'microsoft|azure' };
    return list.find(x => new RegExp(`\\b(${alias[x.toLowerCase()] || x.toLowerCase().replace(/[^a-z0-9 ]/g, '')})\\b`, 'i').test(text)) || '';
  }
  reputationOnly(o) {
    if (o.reasons.some(r => /^CrowdSec local detection/.test(r))) return false;
    const high = this.store.all("SELECT feed FROM feed_hits WHERE value = ? AND type = 'ip'", o.value)
      .some(h => (this.feeds.defs.find(d => d.id === h.feed) || {}).severity === 'high');
    return !high && o.sources.every(x => x === 'connection' || x === 'resolved' || x === 'dns');
  }
  // Who connected: signed paths from net_seen when known, else the process names in the context.
  trustedCallers(o, hs) {
    const BROWSER = /\/(Firefox|Firefox Developer Edition|Safari|Google Chrome|Google Chrome Beta|Brave Browser|Microsoft Edge|Arc|Chromium|Vivaldi|Opera|Orion|Zen Browser|Zen)\.app\//;
    const paths = hs ? hs.store.all('SELECT DISTINCT path FROM net_seen WHERE remote = ?', o.value).map(r => r.path) : [];
    if (paths.length) {
      const who = paths.map(p => { const c = hs.signer(p).cls; return c === 'apple' ? `${p.split('/').pop()} (Apple)` : BROWSER.test(p) && /^(devid|appstore|apple)$/.test(c) ? `${p.split('/').pop()} (signed browser)` : null; });
      return who.every(Boolean) ? [...new Set(who)].sort().join(', ') : '';
    }
    const procs = String(o.context || '').split(' → ')[0].split(', ').map(x => x.trim()).filter(Boolean);
    const ok = n => /^com\.apple\./.test(n) || /^(firefox|safari|google chrome( helper.*)?|brave browser( helper.*)?|microsoft edge( helper.*)?|arc|chromium|vivaldi|opera|orion|zen)$/i.test(n);
    return procs.length && procs.every(ok) ? [...new Set(procs)].sort().join(', ') + ' (by name)' : '';
  }

  findings(hs) {
    const rows = this.store.all('SELECT * FROM observables WHERE risk_score >= 40 ORDER BY risk_score DESC, last_seen DESC LIMIT 300');
    return rows.map(r => {
      const o = rowOut(r);
      const src = o.sources;
      const what = o.type === 'domain'
        ? (src.includes('download') ? 'downloaded from' : src.includes('dns') || src.includes('dns-heuristic') ? 'queried' : src.includes('manual') ? 'looked up' : 'seen')
        : src.includes('download') ? 'downloaded from' : src.includes('connection') ? 'in active connections' : src.includes('ssh') ? 'tried SSH' : src.includes('screensharing') ? 'tried Screen Sharing'
          : src.includes('firewall') ? 'probed the firewall' : src.some(s => s.startsWith('syslog:')) ? `in syslog from ${src.find(s => s.startsWith('syslog:')).slice(7)}` : src.includes('resolved') ? 'resolved from a domain' : 'seen';
      let toned = '';
      if (o.type === 'ip' && this.reputationOnly(o)) {
        const owner = this.cloudOwner(o), callers = owner && this.trustedCallers(o, hs);
        if (owner && callers) toned = `toned down to low: ${owner} address, reputation reports only, contacted by ${callers}`;
      }
      return { sev: toned ? 'low' : o.risk_score >= 75 ? 'high' : 'medium', area: 'Threat intel', source: 'feeds / CrowdSec / OSINT',
        title: `${o.risk === 'malicious' ? 'Malicious' : 'Suspicious'} ${o.type === 'ip' ? 'IP' : 'domain'} ${what}: ${o.value}`,
        detail: 'Matched a threat feed, CrowdSec, or an OSINT source. Open it in Indicators for full results.',
        evidence: [toned, ...o.reasons, `sources: ${src.join(', ')}`, o.context ? `context: ${o.context}` : '', `first seen ${new Date(o.first_seen).toLocaleString()}, last ${new Date(o.last_seen).toLocaleString()}, ${o.hits} hits`].filter(Boolean),
        count: o.hits, indicator: { value: o.value, type: o.type } };
    });
  }

  providerStatus() {
    return this.providers.map(p => {
      let err = this.lastError[p.id];
      if (!err) {   // after a restart, fall back to the newest stored result
        const r = this.store.get('SELECT error, fetched_at FROM enrichments WHERE provider = ? ORDER BY fetched_at DESC LIMIT 1', p.id);
        if (r && r.error) err = { msg: r.error, at: r.fetched_at };
      }
      return { id: p.id, name: p.name, types: p.types, enabled: p.enabled(), auto: !p.manualOnly && p.minPriority < 99,
        minPriority: p.minPriority, callsToday: this.usage(p), daily: p.daily, error: err ? err.msg : '', errorAt: err ? err.at : null };
    });
  }

  prune(days) {
    const cut = Date.now() - days * D;
    this.store.run("DELETE FROM observables WHERE last_seen < ? AND risk_score < 40 AND sources NOT LIKE '%manual%'", cut);
    this.store.run('DELETE FROM enrichments WHERE NOT EXISTS (SELECT 1 FROM observables o WHERE o.value = enrichments.value AND o.type = enrichments.type) AND type != \'rdapbase\'');
    this.store.run('DELETE FROM feed_hits WHERE NOT EXISTS (SELECT 1 FROM observables o WHERE o.value = feed_hits.value AND o.type = feed_hits.type)');
    this.store.run("DELETE FROM enrichments WHERE type = 'rdapbase' AND fetched_at < ?", Date.now() - 60 * D);
  }

  // ------------------------------------------------------- provider helpers
  async rdap(domain) {
    const base = engine.baseDomain(domain);
    if (engine.CDN_BASES.has(base)) return { verdict: 'n/a', summary: 'well-known service; skipped', cached: true };
    const cached = this.store.get("SELECT verdict, score, summary, link FROM enrichments WHERE value = ? AND type = 'rdapbase' AND provider = 'rdap' AND fetched_at > ?", base, Date.now() - 30 * D);
    if (cached) return { ...cached, cached: true };
    const r = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(base)}`, { headers: { Accept: 'application/rdap+json, application/json' }, timeout: 20000 });
    let res;
    if (r.status === 404) res = { verdict: 'unknown', summary: `${base}: no RDAP record (unregistered, or TLD has no RDAP)` };
    else if (!r.ok || !r.json) throw new Error(`RDAP HTTP ${r.status}`);
    else {
      const ev = r.json.events || [];
      const reg = ev.find(e => /registration/i.test(e.eventAction || ''));
      const when = reg ? Date.parse(reg.eventDate) : NaN;
      const age = isNaN(when) ? null : Math.floor((Date.now() - when) / D);
      const registrar = ((r.json.entities || []).find(e => (e.roles || []).includes('registrar')) || {});
      const rname = ((registrar.vcardArray || [])[1] || []).find(x => x[0] === 'fn');
      res = { verdict: age === null ? 'unknown' : age < 30 ? 'suspicious' : 'clean', score: age === null ? 0 : age < 7 ? 60 : age < 30 ? 45 : 0,
        summary: `${base} registered ${age === null ? 'on an unknown date' : `${new Date(when).toISOString().slice(0, 10)} (${age} d ago)`}${rname ? ' via ' + rname[3] : ''}`,
        link: `https://rdap.org/domain/${base}` };
    }
    this.store.run(`INSERT INTO enrichments(value, type, provider, fetched_at, verdict, score, summary, link) VALUES (?, 'rdapbase', 'rdap', ?, ?, ?, ?, ?)
      ON CONFLICT(value, type, provider) DO UPDATE SET fetched_at = excluded.fetched_at, verdict = excluded.verdict, score = excluded.score, summary = excluded.summary, link = excluded.link`,
      base, Date.now(), res.verdict, res.score || 0, res.summary, res.link || '');
    return res;
  }

  async intelowl(value, type) {
    const io = cfg.intelowl;
    const headers = { Authorization: `Token ${io.token}`, 'Content-Type': 'application/json' };
    const r = await fetchJson(`${io.url}/api/playbook/analyze_multiple_observables`, { method: 'POST', headers, timeout: 30000,
      body: JSON.stringify({ observables: [[type, value]], playbook_requested: io.playbook, tlp: 'AMBER', tags_labels: ['argus'] }) });
    if (!r.ok || !r.json) throw new Error(`IntelOwl HTTP ${r.status}${r.text ? ': ' + r.text.slice(0, 120) : ''}`);
    const first = (r.json.results || [r.json])[0] || {};
    const id = first.job_id || first.id;
    if (!id) throw new Error(`IntelOwl: no job id (${JSON.stringify(r.json).slice(0, 120)})`);
    const link = `${io.publicUrl || io.url}/jobs/${id}`;
    let job = null;
    for (let i = 0; i < 36; i++) {
      await sleep(5000);
      const j = await fetchJson(`${io.url}/api/jobs/${id}`, { headers, timeout: 20000 });
      if (j.ok && j.json && !/pending|running/i.test(j.json.status || '')) { job = j.json; break; }
    }
    if (!job) return { verdict: 'info', summary: `job ${id} still running; open it in IntelOwl`, link };
    const reports = job.analyzer_reports || job.analyzers_reports || [];
    const ok = reports.filter(x => /success/i.test(x.status || '')).length;
    const evals = reports.map(x => (x.data_model && (x.data_model.evaluation || x.data_model.verdict)) || '').filter(Boolean);
    const mal = evals.filter(e => /malicious/i.test(e)).length;
    const sus = evals.filter(e => /suspicious/i.test(e)).length;
    return { verdict: mal >= 2 ? 'malicious' : (mal || sus) ? 'suspicious' : ok ? 'clean' : 'info', score: mal >= 2 ? 80 : (mal || sus) ? 55 : 0,
      summary: `${ok}/${reports.length} analyzers succeeded${evals.length ? `; ${mal} malicious, ${sus} suspicious` : ''} (job ${id}, ${job.status})`, link };
  }
}

function rowOut(r) {
  return { ...r, sources: safe(r.sources, []), reasons: safe(r.reasons, []) };
}
function safe(s, d) { try { return JSON.parse(s); } catch (e) { return d; } }

module.exports = { Intel };
