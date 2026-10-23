'use strict';
// Program dossier: everything Argus knows about one executable (or, for an app,
// its whole bundle) in one place. Signature, launches, network, privacy
// permissions, persistence, downloads, Sigma and Endpoint Security events, and
// the findings that mention it. Built on request from data Argus already keeps.
const fs = require('node:fs');
const path = require('node:path');
const engine = require('./engine');
const { cfg } = require('./util');

const D = 86400e3;
const TCC_AUTH = { 0: 'denied', 1: 'unknown', 2: 'allowed', 3: 'limited' };

function readInbox(rel) { try { return fs.readFileSync(path.join(cfg.inbox, rel), 'utf8'); } catch (e) { return ''; } }

// Paths and names the dossier can be opened for, for the search box.
function searchPrograms(hs, q, limit = 40) {
  q = String(q || '').trim();
  if (q.length < 2) return [];
  const like = `%${q.replace(/[%_]/g, m => '\\' + m)}%`;
  const rows = new Map();
  const addRow = (p, src, last) => {
    if (!p || !p.startsWith('/')) return;
    const r = rows.get(p) || { path: p, sources: new Set(), last: 0 };
    r.sources.add(src); r.last = Math.max(r.last, last || 0); rows.set(p, r);
  };
  for (const r of hs.store.all("SELECT path, MAX(last_seen) AS last FROM es_exec WHERE path LIKE ? ESCAPE '\\' GROUP BY path ORDER BY last DESC LIMIT 200", like)) addRow(r.path, 'launches', r.last);
  try { for (const r of hs.store.all("SELECT path, MAX(last_seen) AS last FROM ls_flows WHERE path LIKE ? ESCAPE '\\' GROUP BY path ORDER BY last DESC LIMIT 200", like)) addRow(r.path, 'network', r.last); } catch (e) { /* no LS table */ }
  try { for (const r of hs.store.all("SELECT path, MAX(last_seen) AS last FROM net_seen WHERE path LIKE ? ESCAPE '\\' GROUP BY path ORDER BY last DESC LIMIT 200", like)) addRow(r.path, 'network', r.last); } catch (e) { /* none */ }
  const tsv = readInbox('snapshots/signatures.tsv');
  const ql = q.toLowerCase();
  for (const l of tsv.split('\n')) { const p = l.split('\t')[0]; if (p && p.toLowerCase().includes(ql)) addRow(p, 'running', 0); }
  // Collapse app helpers into their bundle's main program when the bundle matched by name.
  return [...rows.values()].sort((a, b) => b.last - a.last).slice(0, limit)
    .map(r => ({ path: r.path, name: nameOf(r.path), sources: [...r.sources], last: r.last || null }));
}

function nameOf(p) { return (String(p).match(/([^/]+)\.app\/Contents\/MacOS\/[^/]+$/) || [])[1] || (String(p).match(/([^/]+)\.app\//) || [])[1] || path.basename(String(p)); }
function bundleOf(p) { const m = String(p).match(/^(.*?\.app)\//); return m ? m[1] : ''; }

function dossier(hs, report, p) {
  p = String(p || '');
  if (!p.startsWith('/')) throw new Error('path must be absolute');
  const now = Date.now();
  const bundle = bundleOf(p);
  // Scope: the whole outermost .app bundle, so helpers' traffic and launches count toward the app.
  const inScope = x => !!x && (x === p || (bundle && (x === bundle || x.startsWith(bundle + '/'))));
  const scopeSql = bundle ? '(path = ? OR substr(path, 1, ?) = ?)' : 'path = ?';
  const scopeArgs = bundle ? [p, bundle.length + 1, bundle + '/'] : [p];

  const sig = hs.signer(p);
  const execs = hs.store.all(`SELECT path, team, signing_id, platform, adhoc, first_seen, last_seen, count, last_parent, last_args, last_user FROM es_exec WHERE ${scopeSql} ORDER BY last_seen DESC LIMIT 100`, ...scopeArgs);
  const main = execs.find(e => e.path === p) || execs[0] || null;
  const ident = sig.id || (main && main.signing_id) || '';
  const team = sig.team || (main && main.team) || '';
  const parents = [...new Map(execs.filter(e => e.last_parent && !inScope(e.last_parent)).map(e => [e.last_parent, { path: e.last_parent, via: e.path, at: e.last_seen }])).values()].slice(0, 12);
  const children = hs.store.all(`SELECT path, count, first_seen, last_seen, last_args FROM es_exec WHERE ${bundle ? '(last_parent = ? OR substr(last_parent, 1, ?) = ?)' : 'last_parent = ?'} ORDER BY last_seen DESC LIMIT 60`, ...scopeArgs)
    .filter(c => !inScope(c.path)).slice(0, 30);

  // network
  const since = now - 7 * D;
  let flows = [], lsTotals = null;
  try {
    flows = hs.store.all(`SELECT COALESCE(NULLIF(host, ''), ip) AS dest, MIN(ip) AS ip, MAX(dir) AS dir, GROUP_CONCAT(DISTINCT port) AS ports, SUM(connects) AS connects, SUM(denies) AS denies,
        SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
      FROM ls_flows WHERE ${scopeSql} AND last_seen > ? GROUP BY dest ORDER BY bytes_in + bytes_out DESC, connects DESC LIMIT 60`, ...scopeArgs, since);
    lsTotals = hs.store.get(`SELECT COUNT(DISTINCT COALESCE(NULLIF(host, ''), ip)) AS dests, SUM(connects) AS connects, SUM(denies) AS denies, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out FROM ls_flows WHERE ${scopeSql} AND last_seen > ?`, ...scopeArgs, since);
  } catch (e) { /* Little Snitch not in use */ }
  let sockets = [];
  try { sockets = hs.store.all(`SELECT remote, GROUP_CONCAT(DISTINCT port) AS ports, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen, SUM(seen) AS seen FROM net_seen WHERE ${scopeSql} AND last_seen > ? GROUP BY remote ORDER BY last_seen DESC LIMIT 60`, ...scopeArgs, since); } catch (e) { /* none */ }
  const risk = v => v ? hs.store.get("SELECT risk, risk_score, reasons FROM observables WHERE value = ? AND risk_score >= 40", v) : null;
  const typeOf = v => /^[\d.]+$|:/.test(v) ? 'ip' : 'domain';
  // same verdict as the findings: allow list, cloud tone-down and two-source rule applied
  const flagOf = (...vals) => {
    for (const v of vals) {
      if (!v) continue;
      if (hs.intel) { const f = hs.intel.flaggedFor(v, typeOf(v), hs); if (f) return { risk: f.risk, score: f.score, why: f.why }; continue; }
      const r = risk(v); if (r) return { risk: r.risk, score: r.risk_score, why: (JSON.parse(r.reasons || '[]')[0] || '') };
    }
    return null;
  };
  flows.forEach(f => { f.flag = flagOf(f.dest, f.ip); });
  sockets.forEach(s => { s.flag = flagOf(s.remote); });

  // privacy permissions (TCC.db snapshots + live Endpoint Security changes)
  const tccRows = [];
  for (const db of ['system', 'user']) {
    for (const l of readInbox(`snapshots/tcc-${db}.tsv`).split('\n')) {
      const [service, client, ctype, auth, , modified] = l.split('\t');
      if (!service || !client) continue;
      if (client === ident || inScope(client) || (bundle && client === bundle)) {
        const svc = service.replace(/^kTCCService/, '');
        tccRows.push({ db, service: svc, name: (engine.TCC_NAMES && engine.TCC_NAMES[svc]) || svc, auth: TCC_AUTH[+auth] || String(auth), high: !!(engine.TCC_HIGH && engine.TCC_HIGH.has(svc)), modified: +modified ? +modified * 1000 : null });
      }
    }
  }
  const tccEvents = ident ? hs.store.all("SELECT ts, sev, summary FROM es_events WHERE kind LIKE 'tcc%' AND (instr(key, ?) > 0 OR instr(summary, ?) > 0) ORDER BY ts DESC LIMIT 30", '|' + ident, ident) : [];

  // persistence
  const btmText = readInbox('snapshots/background-items.txt');
  const btm = btmText && engine.parseBtmDump ? engine.parseBtmDump(btmText).filter(b => inScope(b.exe) || inScope(b.url) || (ident && (b.ident === ident || b.parent === ident)) || (bundle && String(b.url || '').includes(bundle)))
    .map(b => ({ name: b.name || b.ident, type: b.type, enabled: !!b.enabled, exe: b.exe || b.url || '', team: b.team || '', developer: b.developer || '' })) : [];
  const btmChanges = ((report && report.hostsec && report.hostsec.btmDiff && report.hostsec.btmDiff.changes) || []).filter(c => inScope(c.exe) || (bundle && String(c.exe).includes(bundle)));

  // Endpoint Security events and Sigma matches that name the program
  const key = bundle || p;
  const events = hs.store.all('SELECT ts, kind, sev, key, summary, data FROM es_events WHERE (instr(key, ?) > 0 OR instr(summary, ?) > 0) ORDER BY ts DESC LIMIT 150', key, key)
    .map(e => { let d = null; try { d = e.data ? JSON.parse(e.data) : null; } catch (x) { /* truncated */ } return { ts: e.ts, kind: e.kind, sev: e.sev, summary: e.summary, sigma: e.key.startsWith('sigma:') ? { title: d && d.title, level: d && d.level, link: d && d.link } : null }; });

  // inventory, downloads made by the app
  let app = null;
  if (bundle) {
    try {
      const inv = JSON.parse(readInbox('user/apps.json') || '{}');
      const a = (inv.SPApplicationsDataType || []).find(x => x.path === bundle);
      if (a) app = { name: a._name, version: a.version || '', obtainedFrom: a.obtained_from || '', signedBy: a.signed_by || [], modified: a.lastModified || '', arch: a.arch_kind || '' };
    } catch (e) { /* no inventory */ }
  }
  const dl = ((report && report.hostsec && report.hostsec.downloads && report.hostsec.downloads.recent) || []).filter(d => ident && d.bundle === ident).slice(0, 20);

  // findings that mention it
  const needles = [key, p, ident].filter(x => x && x.length > 3);
  const findings = ((report && report.findings) || []).filter(f => needles.some(n => (f.evidence || []).some(l => String(l).includes(n)) || String(f.title).includes(n)))
    .map(f => ({ id: f.id, sev: f.sev, area: f.area, title: f.title, acked: !!f.acked, lines: (f.evidence || []).filter(l => needles.some(n => String(l).includes(n))).slice(0, 6) }));

  // headline facts
  const notes = [];
  const cls = sig.cls || (main ? (main.platform ? 'apple' : main.adhoc ? 'adhoc' : main.team ? 'devid' : 'unsigned') : '');
  if (cls === 'unsigned' || cls === 'adhoc') notes.push({ sev: 'high', text: cls === 'adhoc' ? 'Ad-hoc signed: no developer identity' : 'Not code signed' });
  const pr = engine.pathRisk ? engine.pathRisk(p) : '';
  if (pr) notes.push({ sev: 'high', text: `Runs from a non-standard path (${pr})` });
  const flagged = [...flows.filter(f => f.flag), ...sockets.filter(s => s.flag)].length;
  if (flagged) notes.push({ sev: 'high', text: `${flagged} flagged ${flagged === 1 ? 'destination' : 'destinations'}` });
  const hiTcc = tccRows.filter(t => t.high && (t.auth === 'allowed' || t.auth === 'limited'));
  if (hiTcc.length) notes.push({ sev: 'medium', text: `Holds ${hiTcc.map(t => t.name).join(', ')}` });
  if (btm.some(b => b.enabled)) notes.push({ sev: 'medium', text: 'Starts automatically (login item or launchd job)' });
  if (events.some(e => e.sigma)) notes.push({ sev: 'high', text: `${new Set(events.filter(e => e.sigma).map(e => e.sigma.title)).size} Sigma rule match(es)` });

  const firstSeen = execs.length ? Math.min(...execs.map(e => e.first_seen)) : null;
  return {
    path: p, bundle, name: (app && app.name) || (bundle ? path.basename(bundle, '.app') : nameOf(p)), ident, team, signer: cls, signerId: sig.id || '',
    firstSeen, lastSeen: execs.length ? Math.max(...execs.map(e => e.last_seen)) : null, launches: execs.reduce((a, e) => a + e.count, 0),
    esSince: hs.store.kvGet('es.since', null),
    binaries: execs.map(e => ({ path: e.path, count: e.count, first: e.first_seen, last: e.last_seen, args: e.last_args, user: e.last_user, team: e.team, platform: !!e.platform, adhoc: !!e.adhoc })),
    parents, children, app, notes,
    network: { littleSnitch: !!lsTotals && !!lsTotals.dests, totals: lsTotals, flows, sockets },
    permissions: tccRows, permissionEvents: tccEvents, persistence: btm, persistenceChanges: btmChanges,
    events, downloads: dl, findings,
  };
}

module.exports = { dossier, searchPrograms, nameOf, bundleOf };
