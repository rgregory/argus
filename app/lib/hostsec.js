'use strict';
// Host telemetry beyond the unified log (dev instance additions):
//   * Endpoint Security events from eslogger   inbox/es/<day>/*.ndjson
//   * TCC.db grants (system + user)            inbox/snapshots/tcc-{system,user}.tsv
//   * Background-item (BTM) persistence diff   inbox/snapshots/background-items.txt
//   * Download provenance (QuarantineEventsV2) inbox/user/quarantine.tsv
// Raw ES data is condensed into SQLite as it arrives (per-binary exec aggregates
// plus a capped log of rare events), so a rebuild never re-reads the raw chunks.
const fs = require('node:fs');
const path = require('node:path');
const engine = require('./engine');
const { cfg, logger, walk } = require('./util');

const log = logger('hostsec');
const H = 3600e3, D = 86400e3;
const MAC_EPOCH = 978307200;   // 2001-01-01 in Unix seconds

const SCHEMA = `
CREATE TABLE IF NOT EXISTS es_files (path TEXT PRIMARY KEY, size INTEGER, done_at INTEGER, events INTEGER);
CREATE TABLE IF NOT EXISTS es_exec (
  path TEXT NOT NULL, team TEXT NOT NULL DEFAULT '', signing_id TEXT NOT NULL DEFAULT '', platform INTEGER NOT NULL DEFAULT 0,
  adhoc INTEGER NOT NULL DEFAULT 0, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 0,
  last_parent TEXT NOT NULL DEFAULT '', last_args TEXT NOT NULL DEFAULT '', last_user INTEGER, cdhash TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (path, team, signing_id)
);
CREATE INDEX IF NOT EXISTS es_exec_seen ON es_exec(last_seen DESC);
CREATE TABLE IF NOT EXISTS es_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, sev TEXT NOT NULL, key TEXT NOT NULL, summary TEXT NOT NULL, data TEXT);
CREATE INDEX IF NOT EXISTS es_events_ts ON es_events(ts DESC);
CREATE INDEX IF NOT EXISTS es_events_kind ON es_events(kind, ts DESC);
`;

// ------------------------------------------------------------ classifiers
const SHELLS = /^\/(bin|usr\/bin)\/(sh|bash|zsh|dash|ksh|tcsh|csh)$/;
const INTERP = /^\/(usr\/bin|bin|opt\/homebrew\/bin|usr\/local\/bin)\/(sh|bash|zsh|dash|python3?(\.\d+)?|perl\d*|ruby|osascript|node|php|curl|wget|nc|ncat|socat|base64|openssl)$/;
// Apps whose children should rarely be shells / downloaders (initial-access pattern).
const RISKY_PARENTS = /\/(Microsoft (Word|Excel|PowerPoint|Outlook)|Pages|Numbers|Keynote|Mail|Messages|Preview|Adobe Acrobat[^/]*|Acrobat Reader|Safari|Google Chrome|Firefox|Microsoft Edge|Brave Browser|Arc|Slack|Discord|zoom\.us|Microsoft Teams[^/]*)\.app\//i;
const RISKY_ARGS = [
  [/\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/, 'pipe-to-shell download', 'high'],
  [/base64\s+(-d|--decode|-D)\b.*\|\s*(ba|z)?sh|echo\s+[A-Za-z0-9+/=]{80,}\s*\|\s*base64/, 'decoded payload piped to a shell', 'high'],
  [/osascript\b.*-e\b.*(do shell script|display dialog.*password|keystroke)/i, 'AppleScript running shell commands / password prompt', 'high'],
  [/\bpython3?\b\s+-c\b.*(socket|subprocess|pty\.spawn|exec\()/, 'inline Python with socket/exec', 'high'],
  [/\b(nc|ncat)\b.*\s-e\s|\/dev\/tcp\/|mkfifo\b.*\bnc\b|\bsocat\b.*exec:/i, 'reverse-shell pattern', 'high'],
  [/\bxattr\b.*(-d|-c|-r).*com\.apple\.quarantine|\bxattr\s+-[a-z]*c[a-z]*\s/, 'quarantine attribute removed', 'medium'],
  [/\bspctl\b.*--(master|global)-disable|\bcsrutil\s+disable/, 'Gatekeeper / SIP disabled', 'high'],
  [/\bsecurity\b\s+(dump-keychain|find-(generic|internet)-password\b.*-w)/, 'keychain secrets read', 'medium'],
  [/\bdscl\b.*-(create|append)\s+\/(Users|Groups\/admin)|\bsysadminctl\b.*-addUser|\bdseditgroup\b.*-a\b.*\badmin\b/, 'account / admin group change', 'medium'],
  [/\blaunchctl\b\s+(load|bootstrap|submit)\b/, 'launchd job loaded', 'low'],
  [/\btccutil\b\s+reset/, 'privacy permissions reset', 'medium'],
  [/\bchmod\b\s+[+0-7]*[ux]?\+?x\b.*\/(tmp|private\/tmp|Users\/Shared)\//, 'made a temp file executable', 'medium'],
];
const OWN = /\/usr\/local\/libexec\/argus(-dev)?\/|\/usr\/bin\/eslogger|com\.argus\.(dev\.)?/;

function procInfo(p) {
  if (!p) return null;
  const exe = (p.executable && p.executable.path) || '';
  const flags = +p.codesigning_flags || 0;
  return {
    path: exe, team: p.team_id || '', signingId: p.signing_id || '', platform: !!p.is_platform_binary,
    adhoc: (flags & 0x2) !== 0, valid: (flags & 0x1) !== 0, cdhash: p.cdhash || '',
    pid: p.audit_token ? p.audit_token.pid : null, euid: p.audit_token ? p.audit_token.euid : null,
  };
}
const unsignedish = t => !t.platform && !t.team;
const fmt = ms => engine.fmtTs(new Date(ms));
const trunc = (s, n = 300) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const plural = (n, w, p) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? w : (p || w + 's')}`;
const AUTH_TYPES = ['Open Directory (password)', 'Touch ID', 'smart card / token', 'Apple Watch unlock'];
const TCC_RIGHT = { 0: 'denied', 1: 'allowed', 2: 'limited', 3: 'added', 4: 'session', 5: 'learn more' };
const BTM_TYPE = { 0: 'user item', 1: 'app', 2: 'login item', 3: 'agent', 4: 'daemon' };
const fileUrl = u => { try { return String(u || '').startsWith('file://') ? decodeURIComponent(String(u).slice(7)) : String(u || ''); } catch (e) { return String(u || ''); } };

class HostSec {
  constructor(store, intel) {
    this.store = store; this.intel = intel;
    store.db.exec(SCHEMA);
    this.mtimes = new Map(); this.cache = new Map();
    this.lastFile = null; this.lastFileAt = null; this.error = '';
    if (!store.kvGet('es.since')) { /* set when the first chunk arrives */ }
  }

  // Read a text/JSON input file only when it changed.
  read(rel, parse = x => x) {
    const p = path.join(cfg.inbox, rel);
    let st; try { st = fs.statSync(p); } catch (e) { this.cache.delete(rel); return null; }
    const key = st.mtimeMs + '|' + st.size;
    if (this.mtimes.get(rel) === key && this.cache.has(rel)) return this.cache.get(rel);
    let v = null;
    try { v = parse(fs.readFileSync(p, 'utf8')); } catch (e) { log.warn(`${rel}: ${e.message}`); }
    this.mtimes.set(rel, key); this.cache.set(rel, v);
    return v;
  }
  mtimeOf(rel) { try { return fs.statSync(path.join(cfg.inbox, rel)).mtimeMs; } catch (e) { return null; } }

  // ------------------------------------------------------------- ES ingest
  cycle() {
    const files = walk(path.join(cfg.inbox, 'es'), (p, n) => n.endsWith('.ndjson')).sort();
    let any = false;
    for (const f of files) {
      if (this.store.get('SELECT 1 FROM es_files WHERE path = ?', f)) continue;
      let st; try { st = fs.statSync(f); } catch (e) { continue; }
      let text; try { text = fs.readFileSync(f, 'utf8'); } catch (e) { continue; }
      const n = this.ingestEs(text);
      this.store.run('INSERT OR REPLACE INTO es_files(path, size, done_at, events) VALUES (?, ?, ?, ?)', f, st.size, Date.now(), n);
      if (!this.store.kvGet('es.since')) this.store.kvSet('es.since', Date.now());
      this.lastFile = f; this.lastFileAt = Date.now(); any = true;
    }
    return any;
  }

  ingestEs(text) {
    const execAgg = new Map(), events = [], iocs = [];
    let n = 0, start = 0;
    const len = text.length;
    while (start < len) {
      let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
      const line = text.slice(start, nl); start = nl + 1;
      if (line.charCodeAt(0) !== 123) continue;
      let o; try { o = JSON.parse(line); } catch (e) { continue; }
      if (!o || !o.event) continue;
      n++;
      const kind = Object.keys(o.event)[0];
      const ev = o.event[kind] || {};
      const ts = Date.parse(o.time) || Date.now();
      const proc = procInfo(o.process) || {};
      try { this.esEvent(kind, ev, ts, proc, execAgg, events, iocs); } catch (e) { /* malformed event */ }
    }
    this.store.tx(() => {
      for (const x of execAgg.values()) {
        this.store.run(`INSERT INTO es_exec(path, team, signing_id, platform, adhoc, first_seen, last_seen, count, last_parent, last_args, last_user, cdhash)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(path, team, signing_id) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen), count = count + excluded.count,
            last_parent = excluded.last_parent, last_args = excluded.last_args, last_user = excluded.last_user, cdhash = excluded.cdhash, adhoc = excluded.adhoc`,
          x.path, x.team, x.signingId, x.platform ? 1 : 0, x.adhoc ? 1 : 0, x.first, x.last, x.count, x.parent, x.args, x.euid, x.cdhash);
      }
      for (const e of events) this.store.run('INSERT INTO es_events(ts, kind, sev, key, summary, data) VALUES (?, ?, ?, ?, ?, ?)', e.ts, e.kind, e.sev, e.key, trunc(e.summary, 600), e.data ? JSON.stringify(e.data).slice(0, 4000) : null);
    });
    if (iocs.length && this.intel) this.intel.observeMany(iocs);
    return n;
  }

  esEvent(kind, ev, ts, proc, execAgg, events, iocs) {
    const push = (sev, key, summary, data) => events.push({ ts, kind, sev, key, summary, data });
    switch (kind) {
      case 'exec': {
        const t = procInfo(ev.target) || {};
        if (!t.path) return;
        const args = (ev.args || []).map(String);
        const cmd = trunc(args.join(' '), 1000);
        const k = t.path + '|' + t.team + '|' + t.signingId;
        let x = execAgg.get(k);
        if (!x) { x = { ...t, first: ts, last: ts, count: 0, parent: '', args: '', euid: null }; execAgg.set(k, x); }
        x.count++; x.last = Math.max(x.last, ts); x.first = Math.min(x.first, ts);
        x.parent = proc.path || ''; x.args = cmd; x.euid = t.euid;
        if (OWN.test(cmd) || OWN.test(proc.path || '')) return;
        // notable single executions are kept individually
        for (const [rx, label, sev] of RISKY_ARGS) {
          if (rx.test(cmd)) { push(sev, 'args:' + label + '|' + t.path, `${label}: ${cmd}`, { path: t.path, parent: proc.path, cmd, team: t.team, euid: t.euid }); break; }
        }
        const pr = engine.pathRisk(t.path);
        if (pr && !t.platform) push(unsignedish(t) || t.adhoc ? 'high' : 'medium', 'path:' + t.path, `${pr}: ${t.path}${t.team ? ` (team ${t.team})` : t.adhoc ? ' (ad-hoc signed)' : ' (no Team ID)'}`, { path: t.path, parent: proc.path, cmd, team: t.team, adhoc: t.adhoc });
        if (RISKY_PARENTS.test(proc.path || '') && INTERP.test(t.path)) push('high', 'parent:' + proc.path + '|' + t.path, `${(proc.path.match(/\/([^/]+)\.app\//) || [])[1] || proc.path} started ${t.path}: ${cmd}`, { path: t.path, parent: proc.path, cmd });
        return;
      }
      case 'btm_launch_item_add': case 'btm_launch_item_remove': {
        const it = ev.item || {};
        const inst = procInfo(ev.instigator) || procInfo(ev.app) || {};
        const exe = ev.executable_path || fileUrl(it.item_url);
        const apple = /^\/System\//.test(exe) || /^com\.apple\./.test(inst.signingId || '');
        const add = kind === 'btm_launch_item_add';
        push(add ? (apple ? 'info' : (engine.pathRisk(exe) ? 'high' : 'medium')) : 'info', 'btm:' + exe,
          `${add ? 'added' : 'removed'} ${BTM_TYPE[it.item_type] || 'item'}${it.legacy ? ' (legacy plist)' : ''}${it.managed ? ' (managed)' : ''}: ${exe || fileUrl(it.item_url)}${inst.path ? ' — by ' + inst.path : ''}`,
          { exe, url: fileUrl(it.item_url), app: fileUrl(it.app_url), type: it.item_type, uid: it.uid, instigator: inst.path, team: inst.team });
        return;
      }
      case 'xp_malware_detected':
        push('high', 'xp:' + ev.malware_identifier + '|' + ev.detected_path, `XProtect detected ${ev.malware_identifier || 'malware'} at ${ev.detected_path || '?'}`, ev); return;
      case 'xp_malware_remediated':
        push('high', 'xpr:' + ev.malware_identifier + '|' + ev.remediated_path, `XProtect ${ev.success ? 'removed' : 'FAILED to remove'} ${ev.malware_identifier || 'malware'} (${ev.action_type || 'action'}) at ${ev.remediated_path || '?'}`, ev); return;
      case 'authentication': {
        if (ev.success) return;
        const d = ev.data || {}, od = d.od || d.touchid || d.token || d.auto_unlock || {};
        const who = od.record_name || od.username || od.uid || '';
        const inst = procInfo(od.instigator) || proc;
        push('low', 'auth:' + ev.type + '|' + who, `${AUTH_TYPES[ev.type] || 'authentication'} failed${who ? ' for ' + who : ''}${inst.path ? ' via ' + inst.path : ''}`, { type: ev.type, who, by: inst.path });
        return;
      }
      case 'sudo': case 'su': {
        if (ev.success) return;
        const r = ev.reject_info || {};
        push('medium', kind + ':' + (ev.from_username || ev.from_uid), `${kind} rejected for ${ev.from_username || ev.from_uid || '?'}${ev.command ? ': ' + ev.command : ''}${r.failure_message ? ' — ' + r.failure_message : ''}`, { from: ev.from_username, to: ev.to_username, command: ev.command });
        return;
      }
      case 'profile_add': case 'profile_remove': {
        const p = ev.profile || {}, inst = procInfo(ev.instigator) || proc;
        push(kind === 'profile_add' ? 'medium' : 'info', 'profile:' + p.identifier, `configuration profile ${kind === 'profile_add' ? (ev.is_update ? 'updated' : 'installed') : 'removed'}: ${p.display_name || p.identifier || '?'}${p.organization ? ' (' + p.organization + ')' : ''} [${p.install_source === 0 ? 'MDM' : 'manual'}]${inst.path ? ' by ' + inst.path : ''}`, { identifier: p.identifier, org: p.organization, source: p.install_source });
        return;
      }
      case 'tcc_modify': {
        const svc = String(ev.service || '').replace(/^kTCCService/, '');
        const resp = procInfo(ev.responsible) || procInfo(ev.instigator) || {};
        const right = TCC_RIGHT[ev.right] || String(ev.right);
        const allowed = ev.right === 1 || ev.right === 2 || ev.right === 3;
        const high = engine.TCC_HIGH ? engine.TCC_HIGH.has(svc) : /SystemPolicyAllFiles|Accessibility|ScreenCapture|ListenEvent|PostEvent|EndpointSecurityClient/.test(svc);
        const apple = /^com\.apple\./.test(ev.identity || '');
        push(allowed && high && !apple ? 'medium' : 'info', 'tcc:' + svc + '|' + ev.identity, `${(engine.TCC_NAMES && engine.TCC_NAMES[svc]) || svc} ${right} for ${ev.identity || '?'}${resp.path ? ' (via ' + resp.path + ')' : ''}`, { service: svc, identity: ev.identity, right: ev.right, update: ev.update_type, reason: ev.reason });
        return;
      }
      case 'openssh_login': case 'screensharing_attach': {
        const ip = ev.source_address || '';
        const what = kind === 'openssh_login' ? 'SSH login' : 'Screen Sharing session';
        const pub = ip && engine.ipScope(ip) === 'public';
        push(ev.success ? (pub ? 'high' : 'medium') : 'low', kind + ':' + ip, `${what} ${ev.success ? 'succeeded' : 'failed'} from ${ip || '?'}${ev.username || ev.authentication_username ? ' as ' + (ev.username || ev.authentication_username) : ''}`, { ip, user: ev.username || ev.authentication_username });
        if (pub) iocs.push({ value: ip, type: 'ip', source: kind === 'openssh_login' ? 'ssh' : 'screensharing', context: `${what} ${ev.success ? 'succeeded' : 'failed'} (Endpoint Security)`, hits: 1, now: ts });
        return;
      }
      case 'login_login':
        if (!ev.success) push('low', 'login:' + ev.username, `login failed for ${ev.username || '?'}${ev.failure_message ? ': ' + ev.failure_message : ''}`, { user: ev.username });
        return;
      default:
    }
  }

  // ------------------------------------------------------------- analysis
  analyze(ctx) {
    const out = { findings: [], views: {} };
    const add = f => out.findings.push({ detail: '', evidence: [], ...f, count: f.count !== undefined ? f.count : (f.evidence || []).length || 1 });
    try { out.views.es = this.analyzeEs(add, ctx); } catch (e) { log.error(`es: ${e.stack}`); }
    try { out.views.tccDb = this.analyzeTccDb(add); } catch (e) { log.error(`tcc: ${e.stack}`); }
    try { out.views.btmDiff = this.analyzeBtmDiff(add); } catch (e) { log.error(`btm: ${e.stack}`); }
    try { out.views.downloads = this.analyzeDownloads(add); } catch (e) { log.error(`downloads: ${e.stack}`); }
    const X = require('./hostsec-extra');
    try { out.views.net = X.analyzeNet(this, add); } catch (e) { log.error(`net: ${e.stack}`); }
    try { out.views.littlesnitch = X.analyzeLs(this, add); } catch (e) { log.error(`littlesnitch: ${e.stack}`); }
    try { out.views.fim = X.analyzeFim(this, add); } catch (e) { log.error(`fim: ${e.stack}`); }
    try { out.views.extensions = X.analyzeExtensions(this, add); } catch (e) { log.error(`extensions: ${e.stack}`); }
    try { out.views.certs = X.analyzeCerts(this, add); } catch (e) { log.error(`certs: ${e.stack}`); }
    const Y = require('./hostsec-extra2');
    try { out.views.dnsAttribution = Y.analyzeDnsAttribution(this, add); } catch (e) { log.error(`dns attribution: ${e.stack}`); }
    try { out.views.network = Y.analyzeNetwork(this, add); } catch (e) { log.error(`network: ${e.stack}`); }
    try { out.views.devices = Y.analyzeDevices(this, add); } catch (e) { log.error(`devices: ${e.stack}`); }
    try { out.views.images = Y.analyzeImages(this, add); } catch (e) { log.error(`images: ${e.stack}`); }
    return out;
  }

  analyzeEs(add, ctx) {
    const since = Date.now() - cfg.windowHours * H;
    const esSince = this.store.kvGet('es.since', null);
    const files = this.store.get('SELECT COUNT(*) AS n, SUM(events) AS ev, MAX(done_at) AS last FROM es_files WHERE done_at > ?', since);
    const view = { active: !!esSince, since: esSince, files: files.n || 0, events: files.ev || 0, lastFileAt: this.lastFileAt || files.last || null };
    if (!esSince) return view;

    const evs = this.store.all('SELECT ts, kind, sev, key, summary, data FROM es_events WHERE ts > ? ORDER BY ts DESC LIMIT 20000', since);
    const group = (rows) => { const m = new Map(); for (const r of rows) { const g = m.get(r.key) || { ...r, n: 0, first: r.ts, last: r.ts }; g.n++; g.first = Math.min(g.first, r.ts); g.last = Math.max(g.last, r.ts); m.set(r.key, g); } return [...m.values()].sort((a, b) => b.last - a.last); };
    const line = g => `${fmt(g.last)}  ${g.summary}${g.n > 1 ? ` (×${g.n})` : ''}`;
    const sevOf = gs => gs.some(g => g.sev === 'high') ? 'high' : gs.some(g => g.sev === 'medium') ? 'medium' : 'low';
    const byKind = k => evs.filter(e => (Array.isArray(k) ? k.includes(e.kind) : e.kind === k));

    const xp = group(byKind(['xp_malware_detected', 'xp_malware_remediated']));
    if (xp.length) add({ sev: 'high', area: 'Endpoint Security', title: `XProtect acted on malware (${plural(xp.length, 'event')})`, source: 'eslogger: xp_malware_*', detail: 'Apple’s anti-malware engine detected or removed something. Find out how it arrived (Downloads, below) and whether it ran.', evidence: xp.map(line) });

    const execRisk = group(byKind('exec').filter(e => e.key.startsWith('args:') || e.key.startsWith('parent:')));
    if (execRisk.length) add({ sev: sevOf(execRisk), area: 'Endpoint Security', title: `${plural(execRisk.length, 'suspicious command line')} executed`, source: 'eslogger: exec',
      detail: 'Process launches matching download-and-run, encoded payload, reverse-shell or security-control tampering patterns, or a document/browser/chat app starting a shell. Confirm each was you.', evidence: execRisk.map(line) });
    const execPath = group(byKind('exec').filter(e => e.key.startsWith('path:')));
    if (execPath.length) add({ sev: sevOf(execPath), area: 'Endpoint Security', title: `${plural(execPath.length, 'program')} launched from unusual locations`, source: 'eslogger: exec',
      detail: 'Non-Apple binaries started from temp folders, Downloads, /Users/Shared, caches or hidden directories. Unsigned or ad-hoc signed ones are rated high.', evidence: execPath.map(line) });

    const btm = group(byKind('btm_launch_item_add').filter(e => e.sev !== 'info'));
    if (btm.length) add({ sev: sevOf(btm), area: 'Persistence', title: `${plural(btm.length, 'new background item')} registered (live)`, source: 'eslogger: btm_launch_item_add',
      detail: 'Something registered a login item, launch agent or daemon. This is the moment persistence is created — check the instigator.', evidence: btm.map(line) });

    const auth = group(byKind(['authentication', 'login_login']));
    const authN = auth.reduce((a, g) => a + g.n, 0);
    if (authN) add({ sev: authN >= 20 ? 'medium' : 'low', area: 'Access', title: `${plural(authN, 'failed authentication')} (Endpoint Security)`, source: 'eslogger: authentication', count: authN,
      detail: 'Password, Touch ID, token or Apple Watch unlock failures. A burst while you were away is worth a look.', evidence: auth.map(line) });
    const su = group(byKind(['sudo', 'su']));
    if (su.length) add({ sev: 'medium', area: 'Access', title: `${plural(su.reduce((a, g) => a + g.n, 0), 'rejected sudo/su attempt')}`, source: 'eslogger: sudo/su', evidence: su.map(line) });
    const remote = group(byKind(['openssh_login', 'screensharing_attach']));
    const remoteOk = remote.filter(g => g.sev !== 'low');
    if (remoteOk.length) add({ sev: sevOf(remoteOk), area: 'Access', title: `${plural(remoteOk.length, 'remote session source')} (Endpoint Security)`, source: 'eslogger: openssh_login / screensharing_attach', evidence: remoteOk.map(line) });
    const prof = group(byKind('profile_add'));
    if (prof.length) add({ sev: 'medium', area: 'Persistence', title: `${plural(prof.length, 'configuration profile')} installed or updated`, source: 'eslogger: profile_add', detail: 'Profiles can install root certificates, proxies, DNS settings and restrictions.', evidence: prof.map(line) });
    const tcc = group(byKind('tcc_modify'));
    const tccGrant = tcc.filter(g => g.sev === 'medium');
    if (tccGrant.length) add({ sev: 'medium', area: 'Permissions', title: `${plural(tccGrant.length, 'high-impact permission')} granted (live)`, source: 'eslogger: tcc_modify', detail: 'Full Disk Access, Accessibility, Screen Recording, Input Monitoring and similar were granted to a third-party app.', evidence: tccGrant.map(line) });

    // first-seen third-party binaries (after a 24 h baseline)
    const baselineDone = Date.now() - esSince > D;
    const newBins = baselineDone ? this.store.all(`SELECT * FROM es_exec WHERE platform = 0 AND first_seen > ? AND first_seen > ? ORDER BY first_seen DESC LIMIT 300`, since, esSince + D) : [];
    const newShow = newBins.filter(b => !OWN.test(b.path));
    if (newShow.length) add({ sev: newShow.some(b => !b.team && engine.pathRisk(b.path)) ? 'medium' : 'low', area: 'Endpoint Security', title: `${plural(newShow.length, 'third-party program')} ran for the first time`, source: 'eslogger: exec',
      detail: 'Binaries never seen before on this Mac (since Endpoint Security collection started). Installs and updates show up here; anything you do not recognize deserves a look.',
      evidence: newShow.map(b => `${fmt(b.first_seen)}  ${b.path}${b.team ? ` (team ${b.team})` : b.adhoc ? ' (ad-hoc signed)' : ' (no Team ID)'}${b.last_parent ? ' ← ' + b.last_parent : ''}`) });

    const top = this.store.all('SELECT path, team, signing_id, platform, adhoc, first_seen, last_seen, count, last_parent, last_args FROM es_exec WHERE last_seen > ? AND platform = 0 ORDER BY count DESC LIMIT 320', since).filter(b => !OWN.test(b.path)).slice(0, 300);
    const totals = this.store.get('SELECT COUNT(*) AS bins, SUM(platform = 0) AS third, SUM(platform = 0 AND team = \'\') AS noteam FROM es_exec WHERE last_seen > ?', since);
    const kinds = this.store.all('SELECT kind, COUNT(*) AS n FROM es_events WHERE ts > ? GROUP BY kind ORDER BY n DESC', since);
    return { ...view, binaries: totals.bins || 0, thirdParty: totals.third || 0, noTeam: totals.noteam || 0, baselineDone,
      newBinaries: newShow.slice(0, 300), topThirdParty: top, eventKinds: kinds, recent: evs.slice(0, 500).map(e => ({ ts: e.ts, kind: e.kind, sev: e.sev, summary: e.summary })) };
  }

  analyzeTccDb(add) {
    const parse = text => text.split('\n').filter(Boolean).map(l => {
      const [service, client, ctype, auth, reason, modified, indirect] = l.split('\t');
      return { service: String(service || '').replace(/^kTCCService/, ''), client, clientType: +ctype, auth: +auth, reason: +reason, modified: +modified ? +modified * 1000 : null, indirect: indirect || '' };
    }).filter(r => r.service && r.client);
    const sys = this.read('snapshots/tcc-system.tsv', parse), usr = this.read('snapshots/tcc-user.tsv', parse);
    if (!sys && !usr) return { available: false };
    const rows = [...(sys || []).map(r => ({ ...r, db: 'system' })), ...(usr || []).map(r => ({ ...r, db: 'user' }))];
    const HIGH = engine.TCC_HIGH || new Set(['SystemPolicyAllFiles', 'Accessibility', 'ScreenCapture', 'ListenEvent', 'PostEvent', 'EndpointSecurityClient']);
    const name = s => (engine.TCC_NAMES && engine.TCC_NAMES[s]) || s;
    const apple = r => /^com\.apple\./.test(r.client) || /^\/(System|usr\/libexec|usr\/sbin)\//.test(r.client);
    const ours = r => /^\/usr\/bin\/(eslogger|sqlite3)$/.test(r.client);
    const granted = rows.filter(r => r.auth === 2 || r.auth === 3);
    const third = granted.filter(r => !apple(r) && HIGH.has(r.service));
    const risky = third.filter(r => r.clientType === 1 && engine.pathRisk(r.client));
    if (risky.length) add({ sev: 'high', area: 'Permissions', title: 'High-impact permission held by a program in an unusual location', source: 'TCC.db', evidence: risky.map(r => `${name(r.service)} → ${r.client} (${engine.pathRisk(r.client)})`) });
    // diff against the previous snapshot
    const keyOf = r => r.db + '|' + r.service + '|' + r.client;
    const prev = this.store.kvGet('tcc.baseline', null);
    const cur = Object.fromEntries(granted.map(r => [keyOf(r), r.modified || 1]));
    let added = [];
    if (prev) added = third.filter(r => !(keyOf(r) in prev.grants) && !ours(r));
    const fresh = Object.fromEntries(Object.entries(prev ? prev.added || {} : {}).filter(([, t]) => Date.now() - t < 7 * D));
    for (const r of added) fresh[keyOf(r)] = Date.now();
    this.store.kvSet('tcc.baseline', { grants: cur, at: Date.now(), added: fresh });
    const recent = third.filter(r => keyOf(r) in fresh);
    if (recent.length) add({ sev: 'medium', area: 'Permissions', title: `${plural(recent.length, 'new high-impact grant')} in TCC.db (last 7 days)`, source: 'TCC.db diff',
      detail: 'Grants that were not in the previous snapshot. Full Disk Access, Accessibility, Screen Recording and Input Monitoring let an app read everything or watch and drive input.',
      evidence: recent.map(r => `${name(r.service)} → ${r.client} [${r.db}]${r.modified ? ' modified ' + fmt(r.modified) : ''}`) });
    const inv = third.filter(r => !ours(r));
    if (inv.length) add({ sev: 'info', area: 'Permissions', title: `${plural(inv.length, 'third-party high-impact grant')} on record`, source: 'TCC.db', detail: 'Full inventory from the permission databases (not just what was used in the window).', evidence: inv.map(r => `${name(r.service)} → ${r.client} [${r.db}]`) });
    return { available: true, system: !!sys, user: !!usr, rows: rows.length, granted: granted.length,
      thirdParty: third.map(r => ({ ...r, serviceName: name(r.service), recent: keyOf(r) in fresh, ours: ours(r) })), baselineAt: prev ? prev.at : null };
  }

  analyzeBtmDiff(add) {
    const text = this.read('snapshots/background-items.txt');
    if (!text || !engine.parseBtmDump) return { available: false };
    const items = engine.parseBtmDump(text).filter(b => !b.apple);
    const keyOf = b => [b.uid, b.type, b.ident || b.name, b.exe || b.url].join('|');
    const prev = this.store.kvGet('btm.baseline', null);
    const cur = Object.fromEntries(items.map(b => [keyOf(b), b.enabled ? 1 : 0]));
    const changes = prev ? (prev.changes || []).filter(c => Date.now() - c.at < 7 * D) : [];
    if (prev) {
      for (const b of items) {
        const k = keyOf(b);
        if (!(k in prev.items)) changes.push({ at: Date.now(), change: 'added', item: b });
        else if (prev.items[k] !== cur[k]) changes.push({ at: Date.now(), change: cur[k] ? 'enabled' : 'disabled', item: b });
      }
      for (const k of Object.keys(prev.items)) if (!(k in cur)) { const p = k.split('|'); changes.push({ at: Date.now(), change: 'removed', item: { type: p[1], name: p[2], exe: p[3] } }); }
    }
    this.store.kvSet('btm.baseline', { items: cur, at: prev ? prev.at : Date.now(), changes: changes.slice(-200) });
    const addedOrEnabled = changes.filter(c => c.change === 'added' || c.change === 'enabled');
    if (addedOrEnabled.length) {
      const risky = addedOrEnabled.some(c => engine.pathRisk(c.item.exe) || (!c.item.team && c.item.enabled));
      add({ sev: risky ? 'high' : 'medium', area: 'Persistence', title: `${plural(addedOrEnabled.length, 'background item')} added or enabled since the previous snapshot`, source: 'sfltool dumpbtm diff',
        detail: 'New login items, launch agents and daemons (last 7 days). Persistence is how most macOS malware survives a reboot.',
        evidence: addedOrEnabled.map(c => `${fmt(c.at)}  ${c.change}: ${c.item.type || 'item'} ${c.item.name || c.item.ident} → ${c.item.exe || c.item.url || '?'}${c.item.team ? ` (team ${c.item.team})` : ' (no Team ID)'}${c.item.developer ? ` — ${c.item.developer}` : ''}`) });
    }
    const removed = changes.filter(c => c.change === 'removed' || c.change === 'disabled');
    if (removed.length) add({ sev: 'info', area: 'Persistence', title: `${plural(removed.length, 'background item')} removed or disabled`, source: 'sfltool dumpbtm diff', evidence: removed.map(c => `${fmt(c.at)}  ${c.change}: ${c.item.name || c.item.ident} → ${c.item.exe || '?'}`) });
    return { available: true, items: items.length, baselineAt: prev ? prev.at : Date.now(), changes: changes.slice().reverse().map(c => ({ at: c.at, change: c.change, name: c.item.name || c.item.ident, exe: c.item.exe || c.item.url || '', type: c.item.type || '', team: c.item.team || '' })) };
  }

  analyzeDownloads(add) {
    const rows = this.read('user/quarantine.tsv', text => text.split('\n').filter(Boolean).map(l => {
      const [ts, agent, bundle, data, origin, sender, type] = l.split('\t');
      const t = (parseFloat(ts) + MAC_EPOCH) * 1000;
      const host = u => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return ''; } };
      return { ts: isFinite(t) ? t : null, agent: agent || bundle || '?', bundle: bundle || '', url: data || '', origin: origin || '', host: host(data), originHost: host(origin), sender: sender || '', type: +type || 0 };
    }));
    if (!rows) return { available: false };
    // feed download hosts to threat intel once per file version
    const ver = this.mtimes.get('user/quarantine.tsv');
    if (this.intel && ver && ver !== this.dlFed) {
      const seen = new Map();
      for (const r of rows) for (const h of [r.host, r.originHost]) {
        if (!h || h === 'localhost') continue;
        const x = seen.get(h) || { value: h, type: /^[\d.]+$|:/.test(h) ? 'ip' : 'domain', source: 'download', context: `download via ${r.agent}: ${trunc(r.url || r.origin, 160)}`, hits: 0, now: r.ts || Date.now() };
        x.hits++; seen.set(h, x);
      }
      this.intel.observeMany([...seen.values()]);
      this.dlFed = ver;
    }
    const isIpHost = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');
    const ipDl = rows.filter(r => isIpHost(r.host) && engine.ipScope(r.host) === 'public');
    if (ipDl.length) add({ sev: 'medium', area: 'Downloads', title: `${plural(ipDl.length, 'download')} straight from an IP address`, source: 'QuarantineEventsV2', detail: 'Legitimate software is rarely served from a bare IP. Check what was downloaded and whether it was opened.', evidence: ipDl.map(r => `${fmt(r.ts)}  ${r.agent}: ${r.url}`) });
    const plain = rows.filter(r => /^http:\/\//i.test(r.url) && /\.(dmg|pkg|mpkg|zip|app|command|sh|scpt|jar|tar\.gz|tgz)(\?|$)/i.test(r.url));
    if (plain.length) add({ sev: 'low', area: 'Downloads', title: `${plural(plain.length, 'installer or script')} downloaded over plain HTTP`, source: 'QuarantineEventsV2', evidence: plain.map(r => `${fmt(r.ts)}  ${r.agent}: ${r.url}`) });
    const viaTerm = rows.filter(r => /terminal|iterm|curl|wget|python|node/i.test(r.agent + ' ' + r.bundle));
    if (viaTerm.length) add({ sev: 'info', area: 'Downloads', title: `${plural(viaTerm.length, 'download')} by command-line tools`, source: 'QuarantineEventsV2', evidence: viaTerm.map(r => `${fmt(r.ts)}  ${r.agent}: ${r.url || r.origin}`) });
    const byHost = new Map();
    for (const r of rows) { if (!r.host) continue; const h = byHost.get(r.host) || { host: r.host, count: 0, last: 0, agents: new Set() }; h.count++; h.last = Math.max(h.last, r.ts || 0); h.agents.add(r.agent); byHost.set(r.host, h); }
    return { available: true, total: rows.length, recent: rows.slice(-500).reverse(), hosts: [...byHost.values()].map(h => ({ ...h, agents: [...h.agents].join(', ') })).sort((a, b) => b.count - a.count).slice(0, 200) };
  }

  prune(days) {
    const cut = Date.now() - days * D;
    this.store.run('DELETE FROM es_events WHERE ts < ?', cut);
    this.store.run('DELETE FROM es_files WHERE done_at < ?', cut);
    this.store.run('DELETE FROM es_exec WHERE last_seen < ?', Date.now() - 90 * D);   // keep 90 d of "seen before" memory
    // hard cap on rare-event rows
    const n = this.store.get('SELECT COUNT(*) AS n FROM es_events').n;
    if (n > 200000) this.store.run('DELETE FROM es_events WHERE id IN (SELECT id FROM es_events ORDER BY ts ASC LIMIT ?)', n - 200000);
  }

  status() {
    const r = this.store.get('SELECT COUNT(*) AS files, SUM(events) AS events, MAX(done_at) AS last FROM es_files');
    return { esSince: this.store.kvGet('es.since', null), esFiles: r.files || 0, esEvents: r.events || 0, lastFileAt: this.lastFileAt || r.last || null,
      tccDb: { system: this.mtimeOf('snapshots/tcc-system.tsv'), user: this.mtimeOf('snapshots/tcc-user.tsv') },
      quarantine: this.mtimeOf('user/quarantine.tsv'), inventory: this.mtimeOf('user/apps.json') };
  }
}

module.exports = { HostSec, RISKY_ARGS };
