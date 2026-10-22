'use strict';
// Argus service: ingest loops, threat intel, report builder and dashboard API.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const engine = require('./lib/engine');
const { cfg, logger, every, toCsv, writeFileAtomic, dayKey } = require('./lib/util');
const { Store } = require('./lib/store');
const { Feeds } = require('./lib/feeds');
const { CrowdSec } = require('./lib/crowdsec');
const { Intel } = require('./lib/intel');
const { Throughput } = require('./lib/throughput');
const { MacIngest, SyslogTail, PiHole } = require('./lib/ingest');
const { FindingState } = require('./lib/findings');
const { Health } = require('./lib/health');
const { Alerts } = require('./lib/alerts');
const { dossier, searchPrograms } = require('./lib/dossier');
const { Trends } = require('./lib/trends');
const { weeklyDue, weeklyHtml, writeWeekly } = require('./lib/weekly');

const log = logger('argus');
const store = new Store(cfg.state);
const tp = new Throughput(store);
const feeds = new Feeds(store);
const cs = new CrowdSec();
const intel = new Intel(store, feeds, cs);
const mac = new MacIngest(store, intel, tp);
const syslog = new SyslogTail(store, intel, tp);
const pihole = new PiHole(mac, intel, store, tp);
const fstate = new FindingState(store);
const health = new Health();
const alerts = new Alerts(store);
const trends = new Trends(store);

let report = null, reportAt = 0;
const started = Date.now();

function buildReport() {
  const m = mac.report || engine.finalize(engine.newState());
  const dnsFindings = mac.dnsReport ? mac.dnsReport.findings.filter(f => f.area === 'DNS' || f.area === 'Ollama') : [];
  const findings = [...m.findings, ...dnsFindings, ...intel.findings(mac.hostsec), ...cs.findings()]
    .sort((a, b) => engine.SEV_ORDER[a.sev] - engine.SEV_ORDER[b.sev] || (b.count || 0) - (a.count || 0));
  // Stable, content-derived id instead of array position: buildReport() reruns every
  // 60s (server timer) and the dashboard polls /api/report every 60s too, replacing
  // the whole report object. A positional id (i + 1) gets reshuffled on every rebuild
  // whenever same-severity findings aren't in a guaranteed-stable order, which silently
  // orphans whatever id the UI had open — the expanded row then stops matching
  // openFinding and the evidence panel goes blank even though the data is still there.
  // Digits are collapsed so a finding keeps its id across minor count changes in the
  // title (e.g. "5 services" -> "6 services"); a counter breaks ties on real collisions.
  const seen = new Map();
  findings.forEach(f => {
    const slug = `${f.area}|${f.source || ''}|${f.title}`.replace(/\d+/g, '#');
    const n = (seen.get(slug) || 0) + 1;
    seen.set(slug, n);
    f.id = n > 1 ? `${slug}#${n}` : slug;
  });
  // acknowledged findings stay in the list (flagged) but don't count
  const acked = fstate.annotate(findings);
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { if (!f.acked) counts[f.sev]++; });
  fstate.snapshot(findings);
  const changes = fstate.changes(findings);
  try { trends.record(m.timeline); } catch (e) { log.warn(`trends: ${e.message}`); }
  let hc = null;
  try { hc = health.check({ mac, feeds, cs }); } catch (e) { log.error(`health: ${e.stack}`); }
  report = {
    generated: new Date(), version: cfg.version, uptime: Date.now() - started,
    host: { name: mac.meta.host || m.meta.host || cfg.macHost || '', os: mac.meta.os || m.meta.os || '', build: m.meta.build || '', tz: process.env.TZ || '' },
    counts, findings, posture: m.posture, timeline: m.timeline, changes, findingState: { acked, acks: fstate.acks().length },
    window: { from: m.meta.minTs, to: m.meta.maxTs, events: m.meta.events, hours: cfg.windowHours },
    macos: { access: m.access, protect: m.protect, persistence: m.persistence, network: m.network, crashes: m.crashes, system: m.system, containers: m.containers, ollama: m.ollama, files: m.files.slice(-200) },
    dns: mac.dnsReport ? mac.dnsReport.dns : null,
    intel: intel.counts(),
    crowdsec: cs.status(),
    feeds: feeds.status(), providers: intel.providerStatus(),
    syslog: syslog.status(),
    inputs: { collector: mac.status(), pihole: pihole.status(), intelowl: { configured: !!(cfg.intelowl.url && cfg.intelowl.token), url: cfg.intelowl.publicUrl || cfg.intelowl.url, playbook: cfg.intelowl.playbook } },
    throughput: tp.summary(24, 10),
    hostsec: m.hostsec || null, vulns: m.vulns || null,
    health: hc, alerts: alerts.status(), history: trends.view(),
  };
  reportAt = Date.now();
  return report;
}

function exportFiles() {
  const r = report || buildReport();
  const dir = path.join(cfg.data, 'reports');
  writeFileAtomic(path.join(dir, 'latest.json'), JSON.stringify(r));
  writeFileAtomic(path.join(dir, `report-${dayKey()}.json`), JSON.stringify(r));
  writeFileAtomic(path.join(dir, 'findings.csv'), findingsCsv(r.findings));
  writeFileAtomic(path.join(dir, 'indicators.csv'), indicatorsCsv());
  const cut = Date.now() - cfg.retainDays * 2 * 86400e3;
  for (const n of fs.readdirSync(dir)) if (/^report-\d{8}\.json$/.test(n) && fs.statSync(path.join(dir, n)).mtimeMs < cut) fs.unlinkSync(path.join(dir, n));
}
const findingsCsv = f => toCsv(f, [['id', 'id'], ['severity', 'sev'], ['area', 'area'], ['title', 'title'], ['count', 'count'], ['source', 'source'], ['detail', 'detail'], ['evidence', r => (r.evidence || []).join(' | ')]]);
function indicatorsCsv(filter = 'flagged') {
  const rows = intel.list({ risk: filter === 'all' ? '' : 'flagged', limit: 5000 }).rows;
  return toCsv(rows, [['value', 'value'], ['type', 'type'], ['risk', 'risk'], ['score', 'risk_score'], ['reasons', r => r.reasons.join(' | ')], ['sources', r => r.sources.join(' ')],
    ['first_seen', r => new Date(r.first_seen).toISOString()], ['last_seen', r => new Date(r.last_seen).toISOString()], ['hits', 'hits'], ['context', 'context']]);
}

// ------------------------------------------------------------------- loops
async function main() {
  feeds.loadCache();
  every('ingest', cfg.ingestEvery, async () => { await mac.cycle(); syslog.cycle(); tp.flush(); }, log);
  every('pihole', cfg.pihole.every, () => pihole.poll(), log);
  every('crowdsec', 60e3, () => cs.poll(), log);
  every('feeds', 10 * 60e3, () => feeds.refresh(false), log);
  every('intel', cfg.osint.autoEvery, () => intel.tick(), log);
  every('report', 60e3, async () => { buildReport(); await alerts.process(report); }, log);
  every('export', 5 * 60e3, async () => { exportFiles(); }, log);
  every('digest', 10 * 60e3, async () => { if (fstate.digestDue()) fstate.writeDigest(report || buildReport()); }, log);
  every('weekly', 10 * 60e3, async () => { if (weeklyDue()) writeWeekly(report || buildReport(), { fstate, trends }); }, log);
  every('housekeeping', 3600e3, async () => { mac.prune(); intel.prune(cfg.retainDays * 2); store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); }, log);

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    // nothing about Argus needs to be framed; refuse it so another page can't overlay the dashboard
    res.set('X-Frame-Options', 'DENY');
    res.set('Content-Security-Policy', "frame-ancestors 'none'");
    next();
  });

  // ---- access control -----------------------------------------------------
  // 1. Host check. Only localhost names are answered, which defeats DNS rebinding: a web
  //    page can point its own domain at 127.0.0.1, but the browser still sends that
  //    domain as the Host header.
  // 2. Origin check on anything but GET/HEAD, so another site can't trigger lookups,
  //    rescans or feed refreshes through your browser.
  // 3. Token. Other containers and other accounts on the Mac can forge a Host header,
  //    so when ARGUS_TOKEN is set (argus.sh init generates one) every route except
  //    /api/health needs it: once as ?token= (swapped for an HttpOnly cookie and
  //    redirected away), or as "Authorization: Bearer <token>" for scripts.
  const allowedHosts = new Set(['127.0.0.1', 'localhost', '::1', ...cfg.http.allowedHosts]);
  const hostOnly = h => {
    h = String(h || '').toLowerCase().trim();
    if (h.startsWith('[')) return h.slice(1, h.indexOf(']') > 0 ? h.indexOf(']') : undefined);
    return h.replace(/:\d+$/, '');
  };
  const tokenOk = t => {
    if (!cfg.http.token) return true;
    const a = Buffer.from(String(t || '')), b = Buffer.from(cfg.http.token);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  };
  const cookieVal = (req, name) => {
    for (const part of String(req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0 && part.slice(0, i).trim() === name) { try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return ''; } }
    }
    return '';
  };
  const UNAUTH = `<!doctype html><meta charset="utf-8"><title>Argus</title>
<body style="font:15px/1.5 -apple-system,system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem">
<h1 style="font-size:1.4rem">Argus needs its access token</h1>
<p>Run <code>./argus.sh open</code> on this Mac. It opens the dashboard and signs you in.</p>
<p>Or open <code>http://127.0.0.1:${cfg.httpPort}/?token=&lt;ARGUS_TOKEN&gt;</code> with the value of <code>ARGUS_TOKEN</code> from your <code>argus.env</code>.</p></body>`;

  app.use((req, res, next) => {
    if (!allowedHosts.has(hostOnly(req.headers.host))) {
      return res.status(403).type('text').send('Argus only answers on localhost. Add other names to ARGUS_ALLOWED_HOSTS if you really need them.\n');
    }
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.headers.origin) {
      let o = '';
      try { o = new URL(req.headers.origin).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { o = ''; }
      if (!allowedHosts.has(o)) return res.status(403).json({ error: 'cross-origin request refused' });
    }
    next();
  });

  app.get('/api/health', (req, res) => res.json({ ok: true, version: cfg.version, uptime: Date.now() - started }));

  app.use((req, res, next) => {
    if (!cfg.http.token) return next();
    const q = typeof req.query.token === 'string' ? req.query.token : '';
    if (q) {
      if (!tokenOk(q)) return res.status(401).type('html').send(UNAUTH);
      res.set('Set-Cookie', `argus_token=${encodeURIComponent(q)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7776000`);
      // Always land on the dashboard home: echoing req.path back allowed //host and /\host,
      // which browsers follow off-site (an open redirect for anyone holding the token).
      return res.redirect(302, '/');
    }
    const auth = String(req.headers.authorization || '');
    if (tokenOk(auth.startsWith('Bearer ') ? auth.slice(7).trim() : cookieVal(req, 'argus_token'))) return next();
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'access token required: run ./argus.sh open' });
    res.status(401).type('html').send(UNAUTH);
  });
  app.get('/api/report', (req, res) => {
    if (!report || Date.now() - reportAt > 20e3 || req.query.fresh) buildReport();
    res.json(report);
  });
  app.get('/api/indicators', (req, res) => res.json(intel.list(req.query)));
  app.get('/api/indicators/:type/:value', (req, res) => {
    const d = intel.detail(String(req.params.value).toLowerCase(), req.params.type);
    if (!d) return res.status(404).json({ error: 'not found' });
    res.json(d);
  });
  app.post('/api/lookup', async (req, res) => {
    try { res.json(await intel.lookup(String((req.body && req.body.value) || ''))); }
    catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.post('/api/feeds/refresh', async (req, res) => {
    feeds.refresh(true).then(() => log.info('manual feed refresh done')).catch(e => log.warn(e.message));
    res.json({ ok: true, message: 'refresh started' });
  });
  app.post('/api/vulns/refresh', async (req, res) => {
    mac.vulns.refresh(true).then(() => { mac.dirty = true; log.info('manual vulnerability-data refresh done'); }).catch(e => log.warn(e.message));
    res.json({ ok: true, message: 'refresh started' });
  });
  app.post('/api/findings/ack', (req, res) => {
    const id = String((req.body && req.body.id) || '');
    const f = (report || buildReport()).findings.find(x => x.id === id);
    if (!f) return res.status(404).json({ error: 'no such finding (the report may have changed; reload)' });
    fstate.ack(f.id, f.fp, f.title, (req.body && req.body.note) || '');
    buildReport(); res.json({ ok: true });
  });
  // Bulk acknowledge: the ids the Findings tab is showing (its filters applied).
  app.post('/api/findings/ack-all', (req, res) => {
    const ids = new Set(Array.isArray(req.body && req.body.ids) ? req.body.ids.map(String) : []);
    if (!ids.size) return res.status(400).json({ error: 'no findings given' });
    const note = String((req.body && req.body.note) || '');
    const list = (report || buildReport()).findings.filter(f => ids.has(f.id) && !f.acked);
    fstate.store.tx(() => { for (const f of list) fstate.ack(f.id, f.fp, f.title, note); });
    log.info(`acknowledged ${list.length} finding(s) in bulk`);
    buildReport(); res.json({ ok: true, acked: list.length, missing: ids.size - list.length });
  });
  app.post('/api/findings/unack', (req, res) => {
    fstate.unack(String((req.body && req.body.id) || '')); buildReport(); res.json({ ok: true });
  });
  app.get('/api/findings/acks', (req, res) => res.json(fstate.acks()));
  app.get('/api/program', (req, res) => {
    try { res.json(dossier(mac.hostsec, report || buildReport(), String(req.query.path || ''))); }
    catch (e) { res.status(400).json({ error: e.message }); }
  });
  app.get('/api/programs', (req, res) => res.json(searchPrograms(mac.hostsec, req.query.q)));
  app.get('/api/health/checks', (req, res) => res.json((report || buildReport()).health));
  app.get('/api/weekly', (req, res) => {
    const r = report || buildReport();
    res.type('html').send(req.query.save ? writeWeekly(r, { fstate, trends }) : weeklyHtml(r, { fstate, trends }));
  });
  app.get('/api/sigma', (req, res) => res.json(mac.hostsec.sigmaPanel()));
  app.post('/api/sigma/mute', (req, res) => {
    const id = String((req.body && req.body.id) || '');
    if (!mac.hostsec.sigma.list().some(r => r.id === id)) return res.status(404).json({ error: 'no such rule' });
    mac.hostsec.sigma.setMuted(id, !!(req.body && req.body.muted));
    mac.dirty = true; buildReport(); res.json({ ok: true });
  });
  app.post('/api/alerts/test', async (req, res) => res.json(await alerts.test()));
  app.get('/api/digest', (req, res) => {
    const r = report || buildReport();
    const html = req.query.fresh ? fstate.writeDigest(r) : (() => { try { return fs.readFileSync(path.join(cfg.data, 'reports', 'digest-latest.html'), 'utf8'); } catch (e) { return fstate.writeDigest(r); } })();
    res.type('html').send(html);
  });
  app.post('/api/rescan', async (req, res) => { mac.lastRebuild = 0; await mac.cycle(); buildReport(); res.json({ ok: true }); });
  app.get('/api/export/findings.csv', (req, res) => res.type('text/csv').attachment('argus-findings.csv').send(findingsCsv((report || buildReport()).findings)));
  app.get('/api/export/indicators.csv', (req, res) => res.type('text/csv').attachment('argus-indicators.csv').send(indicatorsCsv(req.query.all ? 'all' : 'flagged')));
  app.get('/api/throughput', (req, res) => res.json(tp.summary(Math.min(+req.query.hours || 24, 24 * 7), Math.max(1, +req.query.bucket || 10))));

  app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));
  app.listen(cfg.httpPort, '0.0.0.0', () => log.info(`dashboard on :${cfg.httpPort} (inbox ${cfg.inbox}, state ${cfg.state}, data ${cfg.data})`));
}

process.on('unhandledRejection', e => log.error('unhandled', e && e.stack || e));
main().catch(e => { log.error(e.stack || e); process.exit(1); });
