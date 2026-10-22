'use strict';
// More host visibility (1.2.0):
//   * process ↔ network join   snapshots/procs.txt + snapshots/established-tcp.txt (+ ES exec data)
//   * file integrity           snapshots/fim.txt
//   * browser extensions       user/browser-extensions.txt
//   * certificate trust store  snapshots/certs-system.txt, user/certs-user.txt
// Each analyzer keeps a baseline in the kv table and reports changes for 7 days.
const engine = require('./engine');

const D = 86400e3;
const KEEP = 7 * D;
const plural = (n, w, p) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? w : (p || w + 's')}`;
const fmt = ms => engine.fmtTs(new Date(ms));
const trunc = (s, n = 200) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
const OWN = /\/usr\/local\/libexec\/argus(-dev)?\/|\/usr\/bin\/eslogger|\/usr\/bin\/sqlite3/;

// keep a rolling, de-duplicated change log in kv
function changeLog(store, key, fresh) {
  const prev = (store.kvGet(key, []) || []).filter(c => Date.now() - c.at < KEEP);
  const all = [...prev, ...fresh].slice(-500);
  store.kvSet(key, all);
  return all;
}

// ------------------------------------------------------- process ↔ network
const LS_SCHEMA = `CREATE TABLE IF NOT EXISTS ls_files (path TEXT PRIMARY KEY, rows INTEGER, done_at INTEGER);
CREATE TABLE IF NOT EXISTS ls_flows (path TEXT NOT NULL, parent TEXT NOT NULL DEFAULT '', dir TEXT NOT NULL, ip TEXT NOT NULL, host TEXT NOT NULL DEFAULT '', proto INTEGER NOT NULL, port TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, connects INTEGER NOT NULL DEFAULT 0, denies INTEGER NOT NULL DEFAULT 0, bytes_in INTEGER NOT NULL DEFAULT 0, bytes_out INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (path, dir, ip, proto, port));
CREATE INDEX IF NOT EXISTS ls_flows_last ON ls_flows(last_seen DESC);`;
function csvRows(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; } else if (c === '\n') { row.push(f); rows.push(row); row = []; f = ''; } else if (c !== '\r') f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows;
}
// Little Snitch log-traffic CSV chunks: inbox/ls/<day>/*.csv
function ingestLs(hs) {
  hs.store.db.exec(LS_SCHEMA);
  const files = require('./util').walk(require('node:path').join(require('./util').cfg.inbox, 'ls'), (p, n) => n.endsWith('.csv')).sort();
  let any = false;
  for (const f of files) {
    if (hs.store.get('SELECT 1 FROM ls_files WHERE path = ?', f)) continue;
    let text; try { text = require('node:fs').readFileSync(f, 'utf8'); } catch (e) { continue; }
    const rows = csvRows(text); const head = rows.shift() || [];
    const ix = Object.fromEntries(head.map((h, i) => [h.trim(), i]));
    const agg = new Map(), iocs = new Map();
    for (const r of rows) {
      if (r.length < 12) continue;
      const g = k => r[ix[k]] ?? '';
      const ts = Date.parse(g('date')) || Date.now();
      const path = g('connectingExecutable') || '(unknown)', dir = g('direction'), ip = g('ipAddress'), port = g('port'), proto = +g('protocol') || 0;
      const k = [path, dir, ip, proto, port].join('|');
      const a = agg.get(k) || { path, parent: g('parentAppExecutable'), dir, ip, host: g('remoteHostname'), proto, port, first: ts, last: ts, connects: 0, denies: 0, bin: 0, bout: 0 };
      a.first = Math.min(a.first, ts); a.last = Math.max(a.last, ts); a.connects += +g('connectCount') || 0; a.denies += +g('denyCount') || 0;
      a.bin += +g('byteCountIn') || 0; a.bout += +g('byteCountOut') || 0; if (!a.host && g('remoteHostname')) a.host = g('remoteHostname');
      agg.set(k, a);
    }
    hs.store.tx(() => {
      for (const a of agg.values()) {
        hs.store.run(`INSERT INTO ls_flows(path, parent, dir, ip, host, proto, port, first_seen, last_seen, connects, denies, bytes_in, bytes_out) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(path, dir, ip, proto, port) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen), connects = connects + excluded.connects, denies = denies + excluded.denies,
          bytes_in = bytes_in + excluded.bytes_in, bytes_out = bytes_out + excluded.bytes_out, host = CASE WHEN excluded.host != '' THEN excluded.host ELSE host END`,
          a.path, a.parent || '', a.dir, a.ip, a.host || '', a.proto, a.port, a.first, a.last, a.connects, a.denies, a.bin, a.bout);
        if (engine.ipScope(a.ip) === 'public') {
          if (a.connects || a.bin || a.bout) hs.store.run(`INSERT INTO net_seen(path, remote, port, first_seen, last_seen, seen) VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(path, remote, port) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen), seen = seen + 1`, a.path, a.ip, a.port, a.first, a.last);
          const prog = a.path.split('/').pop();
          const ctx = `${prog} ${a.dir === 'in' ? '←' : '→'} :${a.port}${a.denies ? ' (denied by Little Snitch)' : ''}`;
          const xi = iocs.get('ip|' + a.ip) || { value: a.ip, type: 'ip', source: a.dir === 'in' ? 'firewall' : 'connection', context: ctx, hits: 0, now: a.last };
          xi.hits += Math.max(1, a.connects); iocs.set('ip|' + a.ip, xi);
          if (a.host) { const xd = iocs.get('d|' + a.host) || { value: a.host, type: 'domain', source: 'connection', context: ctx, hits: 0, now: a.last }; xd.hits += Math.max(1, a.connects); iocs.set('d|' + a.host, xd); }
        }
      }
      hs.store.run('INSERT OR REPLACE INTO ls_files(path, rows, done_at) VALUES (?, ?, ?)', f, rows.length, Date.now());
    });
    if (iocs.size && hs.intel) hs.intel.observeMany([...iocs.values()]);
    hs.lsLast = Date.now(); any = true;
  }
  if (any || !hs.lsPruned || Date.now() - hs.lsPruned > 3600e3) {
    hs.store.run('DELETE FROM ls_flows WHERE last_seen < ?', Date.now() - KEEP);
    hs.store.run('DELETE FROM ls_files WHERE done_at < ?', Date.now() - KEEP);
    hs.lsPruned = Date.now();
  }
  return any;
}
const mb = n => n >= 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(0) + ' KB' : n + ' B';

function analyzeLs(hs, add) {
  hs.store.db.exec(LS_SCHEMA);
  const since = Date.now() - 24 * 3600e3;
  const n = hs.store.get('SELECT COUNT(*) AS n, MAX(last_seen) AS last FROM ls_flows WHERE last_seen > ?', since);
  if (!n.n) return { available: false };
  const flagged = hs.store.all(`SELECT f.path, f.dir, f.ip, f.host, f.port, f.connects, f.denies, f.bytes_out, o.risk, o.reasons FROM ls_flows f
    JOIN observables o ON ((o.value = f.ip AND o.type = 'ip') OR (f.host != '' AND o.value = f.host AND o.type = 'domain')) WHERE f.last_seen > ? AND o.risk_score >= 40 ORDER BY o.risk_score DESC LIMIT 200`, since);
  const allowed = flagged.filter(f => f.connects > 0 || f.bytes_out > 0);
  if (allowed.length) add({ sev: allowed.some(f => f.risk === 'malicious') ? 'high' : 'medium', area: 'Network', title: `${plural(new Set(allowed.map(f => f.path)).size, 'program')} exchanged traffic with flagged destinations (Little Snitch)`, source: 'Little Snitch + threat intel',
    detail: 'Little Snitch allowed these connections; the destination is flagged by a feed, CrowdSec or an OSINT source. Consider a deny rule and check the program.',
    evidence: allowed.map(f => `${f.path} ${f.dir === 'in' ? '←' : '→'} ${f.host || f.ip}:${f.port} [${f.risk}] sent ${mb(f.bytes_out)} — ${(JSON.parse(f.reasons || '[]')[0] || '')}`) });
  const inbound = hs.store.all(`SELECT path, ip, port, SUM(connects) AS c FROM ls_flows WHERE last_seen > ? AND dir = 'in' AND connects > 0 GROUP BY path, ip, port ORDER BY c DESC LIMIT 400`, since).filter(r => engine.ipScope(r.ip) === 'public');
  if (inbound.length) add({ sev: 'medium', area: 'Network', title: `Inbound connections accepted from ${plural(new Set(inbound.map(r => r.ip)).size, 'internet address', 'internet addresses')}`, source: 'Little Snitch',
    detail: 'Little Snitch let these public addresses connect in. Fine for things you host on purpose; otherwise add a deny rule.', evidence: inbound.map(r => `${r.ip} → ${r.path}:${r.port} (${r.c}×)`) });
  const upMB = +(process.env.ARGUS_UPLOAD_MB || 500);
  const up = hs.store.all(`SELECT path, COALESCE(NULLIF(host, ''), ip) AS dest, SUM(bytes_out) AS b FROM ls_flows WHERE last_seen > ? AND dir = 'out' GROUP BY path, dest HAVING b > ? ORDER BY b DESC LIMIT 50`, since, upMB * 1e6)
    .filter(r => !/\/(Backblaze|Arq|Dropbox|Google Drive|OneDrive|iCloud|Synology|Time Machine|bird|cloudd|nsurlsessiond|backupd)/i.test(r.path));
  if (up.length) add({ sev: 'low', area: 'Network', title: `${plural(up.length, 'large upload')} (over ${upMB} MB to one destination in 24 h)`, source: 'Little Snitch',
    detail: 'Big outbound transfers outside known backup/sync apps. Usually uploads you started; worth a glance if the program or destination is unfamiliar.', evidence: up.map(r => `${r.path} → ${r.dest}: ${mb(r.b)}`) });
  const denied = hs.store.all('SELECT path, COALESCE(NULLIF(host, \'\'), ip) AS dest, port, SUM(denies) AS d FROM ls_flows WHERE last_seen > ? AND denies > 0 GROUP BY path, dest, port ORDER BY d DESC LIMIT 300', since);
  const deniedTotal = denied.reduce((a, r) => a + r.d, 0);
  if (deniedTotal) add({ sev: 'info', area: 'Network', title: `Little Snitch denied ${plural(deniedTotal, 'connection attempt')} (24 h)`, source: 'Little Snitch', evidence: denied.slice(0, 100).map(r => `${r.path} → ${r.dest}:${r.port} (${r.d}×)`) });
  const totals = hs.store.get("SELECT SUM(connects) AS c, SUM(denies) AS d, SUM(bytes_in) AS bi, SUM(bytes_out) AS bo, COUNT(DISTINCT path) AS progs FROM ls_flows WHERE last_seen > ?", since);
  const top = hs.store.all(`SELECT path, MAX(parent) AS parent, COUNT(DISTINCT ip) AS remotes, SUM(connects) AS connects, SUM(denies) AS denies, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MAX(last_seen) AS last,
    GROUP_CONCAT(DISTINCT NULLIF(host, '')) AS hosts FROM ls_flows WHERE last_seen > ? GROUP BY path ORDER BY bytes_out + bytes_in DESC LIMIT 300`, since)
    .map(r => ({ ...r, hosts: String(r.hosts || '').split(',').filter(Boolean).slice(0, 6) }));
  return { available: true, lastAt: hs.lsLast || n.last, totals, programs: top, denied: denied.slice(0, 200), inbound: inbound.slice(0, 200) };
}

const SCHEMA = `CREATE TABLE IF NOT EXISTS net_seen (path TEXT NOT NULL, remote TEXT NOT NULL, port TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (path, remote, port));
CREATE INDEX IF NOT EXISTS net_seen_last ON net_seen(last_seen DESC);`;

function parseProcs(text) {
  const m = new Map();
  for (const line of String(text || '').split('\n')) {
    const x = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$/);
    if (x) m.set(+x[1], { pid: +x[1], ppid: +x[2], uid: +x[3], path: x[4] });
  }
  return m;
}
function parseEstablished(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!/\(ESTABLISHED\)/.test(line)) continue;
    const f = line.trim().split(/\s+/);
    const name = (line.match(/(\S+)->(\S+)\s+\(ESTABLISHED\)/) || []);
    if (!name[2]) continue;
    const m = name[2].match(/^\[?([0-9a-f.:]+?)\]?:(\d+)$/i);
    if (!m) continue;
    out.push({ cmd: f[0], pid: +f[1], user: f[2], remote: m[1], port: m[2] });
  }
  return out;
}

function analyzeNet(hs, add) {
  hs.store.db.exec(SCHEMA);
  try { ingestLs(hs); } catch (e) { /* logged by caller on analyze errors */ }
  const est = hs.read('snapshots/established-tcp.txt', parseEstablished);
  const procs = hs.read('snapshots/procs.txt', parseProcs);
  if (!est || !procs) return { available: false };
  const ver = hs.mtimes.get('snapshots/established-tcp.txt');
  const now = Date.now();
  if (ver !== hs.netVer) {   // record each new snapshot once
    hs.store.tx(() => {
      for (const c of est) {
        if (engine.ipScope(c.remote) !== 'public') continue;
        const p = procs.get(c.pid);
        const path = p ? p.path : c.cmd;
        hs.store.run(`INSERT INTO net_seen(path, remote, port, first_seen, last_seen, seen) VALUES (?, ?, ?, ?, ?, 1)
          ON CONFLICT(path, remote, port) DO UPDATE SET last_seen = excluded.last_seen, seen = seen + 1`, path, c.remote, c.port, now, now);
      }
    });
    hs.netVer = ver;
  }
  const since = now - 24 * 3600e3;
  const rows = hs.store.all('SELECT path, remote, port, first_seen, last_seen, seen FROM net_seen WHERE last_seen > ?', since);
  const esSince = hs.store.kvGet('es.since', null);
  const sig = path => hs.store.get('SELECT team, platform, adhoc, MIN(first_seen) AS first_seen FROM es_exec WHERE path = ?', path) || {};
  const flagged = ip => hs.store.get('SELECT risk, risk_score, reasons FROM observables WHERE value = ? AND type = \'ip\' AND risk_score >= 40', ip);
  const byProg = new Map();
  for (const r of rows) {
    let p = byProg.get(r.path);
    if (!p) { const s = sig(r.path); p = { path: r.path, remotes: new Set(), ports: new Set(), last: 0, first: r.first_seen, team: s.team || '', platform: !!s.platform, adhoc: !!s.adhoc, known: s.first_seen !== null && s.first_seen !== undefined, binFirst: s.first_seen || null, flagged: [] }; byProg.set(r.path, p); }
    p.remotes.add(r.remote); p.ports.add(r.port); p.last = Math.max(p.last, r.last_seen); p.first = Math.min(p.first, r.first_seen);
    const f = flagged(r.remote);
    if (f && !p.flagged.some(x => x.ip === r.remote)) p.flagged.push({ ip: r.remote, port: r.port, risk: f.risk, why: (JSON.parse(f.reasons || '[]')[0] || '') });
  }
  const progs = [...byProg.values()].filter(p => !OWN.test(p.path));
  const line = p => `${p.path} → ${plural(p.remotes.size, 'address', 'addresses')} on port ${[...p.ports].slice(0, 6).join(', ')}${p.team ? ` (team ${p.team})` : p.platform ? ' (Apple)' : p.known ? (p.adhoc ? ' (ad-hoc signed)' : ' (no Team ID)') : ''}`;

  const lsOn = !!hs.store.get('SELECT 1 FROM ls_flows WHERE last_seen > ? LIMIT 1', since);   // Little Snitch reports these with more detail
  const bad = lsOn ? [] : progs.filter(p => p.flagged.length);
  if (bad.length) add({ sev: bad.some(p => p.flagged.some(f => f.risk === 'malicious')) ? 'high' : 'medium', area: 'Network', title: `${plural(bad.length, 'program')} connected to flagged addresses`, source: 'lsof + threat intel',
    detail: 'Which program on this Mac talked to an IP that a threat feed, CrowdSec or an OSINT source flagged. Open the address in Indicators for the reasons.',
    evidence: bad.flatMap(p => [p.path, ...p.flagged.slice(0, 8).map(f => `    ${f.ip}:${f.port} [${f.risk}] ${f.why}`)]) });
  const odd = progs.filter(p => !p.platform && (engine.pathRisk(p.path) || (p.known && !p.team)));
  if (odd.length) add({ sev: odd.some(p => engine.pathRisk(p.path)) ? 'high' : 'medium', area: 'Network', title: `${plural(odd.length, 'unsigned or oddly located program')} with internet connections`, source: 'lsof + Endpoint Security',
    detail: 'Programs without a Developer Team ID, or running from temp, Downloads or hidden folders, that held connections to public addresses in the last 24 h. Homebrew tools and self-built binaries land here too.',
    evidence: odd.map(p => `${line(p)}${engine.pathRisk(p.path) ? ' — ' + engine.pathRisk(p.path) : ''}`) });
  const baselineDone = esSince && now - esSince > D;
  const fresh = baselineDone ? progs.filter(p => !p.platform && p.binFirst && p.binFirst > esSince + D && now - p.binFirst < KEEP) : [];
  if (fresh.length) add({ sev: 'low', area: 'Network', title: `${plural(fresh.length, 'newly seen program')} talking to the internet`, source: 'lsof + Endpoint Security',
    detail: 'Third-party programs first seen in the last 7 days that opened outbound connections.', evidence: fresh.map(p => `${fmt(p.binFirst)} first run · ${line(p)}`) });
  return { available: true, programs: progs.sort((a, b) => b.remotes.size - a.remotes.size).slice(0, 300)
    .map(p => ({ path: p.path, remotes: p.remotes.size, sample: [...p.remotes].slice(0, 5), ports: [...p.ports].slice(0, 10), last: p.last, team: p.team, platform: p.platform, adhoc: p.adhoc, known: p.known, flagged: p.flagged.length })) };
}

// ------------------------------------------------------------ file integrity
const FIM_CLASS = [
  [/\/\.ssh\/authorized_keys2?$/, 'high', 'SSH authorized keys'],
  [/^\/etc\/sudoers(\.d\/|$)/, 'high', 'sudo rules'],
  [/^\/etc\/pam\.d\//, 'high', 'PAM authentication'],
  [/^\/Library\/Security\/SecurityAgentPlugins\//, 'high', 'authorization plugin'],
  [/^\/etc\/ssh\/sshd_config/, 'high', 'SSH server config'],
  [/^\/Library\/DirectoryServices\/PlugIns\/|^\/Library\/InputManagers\/|^\/Library\/ScriptingAdditions\//, 'medium', 'system plug-in'],
  [/^\/etc\/hosts$/, 'medium', 'hosts file'],
  [/^\/etc\/(periodic|emond\.d)\/|^\/private\/var\/at\/tabs\/|^\/etc\/crontab$|^\/etc\/launchd\.conf$|^\/etc\/rc\.common$/, 'medium', 'scheduled / boot script'],
  [/\/\.ssh\/(rc|environment|config)$|^\/etc\/ssh\/ssh_config/, 'medium', 'SSH client/session config'],
  [/\/\.(zshrc|zshenv|zprofile|zlogin|zlogout|bashrc|bash_profile|bash_login|profile|tmux\.conf)$|\/config\.fish$|^\/etc\/(profile|zshrc|zprofile|zshenv|bashrc)$/, 'low', 'shell startup file'],
  [/^\/etc\/(paths|paths\.d\/)|^\/etc\/(pf\.conf|auto_master)$/, 'low', 'system config'],
];
const classOf = p => (FIM_CLASS.find(([rx]) => rx.test(p)) || [null, 'low', 'watched file']).slice(1);

function parseFim(text) {
  const files = {}, keys = {}, hooks = {};
  for (const line of String(text || '').split('\n')) {
    const f = line.split('\t');
    if (f[0] === 'F' && f.length >= 7) files[f[6]] = { hash: f[1], perm: f[2], owner: f[3], mtime: +f[4] * 1000, size: +f[5] };
    else if (f[0] === 'K' && f.length >= 3) (keys[f[1]] = keys[f[1]] || []).push(f.slice(2).join('\t'));
    else if (f[0] === 'H' && f.length >= 4) hooks[`${f[1]} (${f[2]})`] = f.slice(3).join('\t');
  }
  return { files, keys, hooks };
}

function analyzeFim(hs, add) {
  const cur = hs.read('snapshots/fim.txt', parseFim);
  if (!cur) return { available: false };
  const prev = hs.store.kvGet('fim.baseline', null);
  const fresh = [];
  if (prev && hs.mtimes.get('snapshots/fim.txt') !== prev.ver) {
    for (const [p, f] of Object.entries(cur.files)) {
      const o = prev.files[p];
      if (!o) fresh.push({ at: Date.now(), path: p, change: 'created', detail: `${f.perm} ${f.owner} ${f.size} B` });
      else if (o.hash !== f.hash) fresh.push({ at: Date.now(), path: p, change: 'modified', detail: `modified ${fmt(f.mtime)}, ${o.size} → ${f.size} B` });
      else if (o.perm !== f.perm || o.owner !== f.owner) fresh.push({ at: Date.now(), path: p, change: 'permissions', detail: `${o.perm} ${o.owner} → ${f.perm} ${f.owner}` });
    }
    for (const p of Object.keys(prev.files)) if (!cur.files[p]) fresh.push({ at: Date.now(), path: p, change: 'deleted', detail: '' });
    for (const [p, ks] of Object.entries(cur.keys)) for (const k of ks) if (!(prev.keys[p] || []).includes(k)) fresh.push({ at: Date.now(), path: p, change: 'key added', detail: k });
    for (const [p, ks] of Object.entries(prev.keys)) for (const k of ks) if (!(cur.keys[p] || []).includes(k)) fresh.push({ at: Date.now(), path: p, change: 'key removed', detail: k });
    for (const [h, v] of Object.entries(cur.hooks)) if (prev.hooks[h] !== v) fresh.push({ at: Date.now(), path: h, change: 'hook set', detail: v });
  }
  if (!prev || hs.mtimes.get('snapshots/fim.txt') !== prev.ver) hs.store.kvSet('fim.baseline', { ...cur, ver: hs.mtimes.get('snapshots/fim.txt'), at: prev ? prev.at : Date.now() });
  const changes = changeLog(hs.store, 'fim.changes', fresh).map(c => { const [sev, kind] = c.change === 'hook set' ? ['high', 'login/logout hook'] : classOf(c.path); return { ...c, sev: c.change === 'key removed' ? 'low' : sev, kind }; });
  for (const sev of ['high', 'medium', 'low']) {
    const cs = changes.filter(c => c.sev === sev);
    if (cs.length) add({ sev, area: 'File integrity', title: `${plural(cs.length, sev === 'high' ? 'security-critical file change' : sev === 'medium' ? 'sensitive file change' : 'startup/config file change')} (last 7 days)`, source: 'file integrity snapshot',
      detail: sev === 'high' ? 'SSH keys, sudo rules, PAM, sshd config, authorization plugins or login hooks changed. These grant access or run code with privileges — confirm each change was yours.'
        : sev === 'medium' ? 'hosts file, scheduled/boot scripts, SSH session config or system plug-in folders changed.' : 'Shell startup files and path configuration changed (usually you, an installer or a package manager).',
      evidence: cs.slice().reverse().map(c => `${fmt(c.at)}  ${c.change}: ${c.path}${c.detail ? ' — ' + trunc(c.detail, 160) : ''} [${c.kind}]`) });
  }
  const hooks = Object.entries(cur.hooks);
  if (hooks.length) add({ sev: 'medium', area: 'File integrity', title: 'Login/logout hooks are set', source: 'file integrity snapshot', detail: 'Deprecated mechanism that runs a script as root at every login; rarely legitimate today.', evidence: hooks.map(([h, v]) => `${h}: ${v}`) });
  const plugins = Object.keys(cur.files).filter(p => /^\/Library\/Security\/SecurityAgentPlugins\//.test(p) && /\/Contents\/MacOS\//.test(p));
  if (plugins.length) add({ sev: 'info', area: 'File integrity', title: `${plural(plugins.length, 'third-party authorization plugin')} installed`, source: 'file integrity snapshot', detail: 'Authorization plugins run inside the login and unlock flow. Expected for MDM / SSO agents; otherwise verify.', evidence: plugins });
  const keyCount = Object.values(cur.keys).reduce((a, k) => a + k.length, 0);
  return { available: true, watched: Object.keys(cur.files).length, keys: Object.entries(cur.keys).map(([p, ks]) => ({ path: p, keys: ks })), keyCount, hooks: cur.hooks,
    baselineAt: prev ? prev.at : Date.now(), changes: changes.slice().reverse().slice(0, 300) };
}

// -------------------------------------------------------- browser extensions
const CHROME_LOC = { 1: 'store/installed', 2: 'external pref', 3: 'external registry', 4: 'unpacked (developer mode)', 5: 'component', 6: 'external pref download', 7: 'policy download', 8: 'command line', 9: 'policy', 10: 'external component' };
const RISKY_PERMS = ['debugger', 'nativeMessaging', 'proxy', 'webRequestBlocking', 'management', 'privacy', 'declarativeNetRequestWithHostAccess', 'cookies', 'history', 'clipboardRead', 'desktopCapture', 'tabCapture', 'scripting', 'webRequest'];
const BROAD = /^(<all_urls>|\*:\/\/\*\/\*|https?:\/\/\*\/\*|\*:\/\/\*\/|file:\/\/\/\*)$/;

function parseExtensions(text) {
  const sections = []; let cur = null;
  for (const line of String(text || '').split('\n')) {
    if (line.startsWith('=== ')) { cur = { head: line.slice(4).split('\t'), body: [] }; sections.push(cur); continue; }
    if (cur) cur.body.push(line);
  }
  const prefs = new Map(), msgs = new Map(), list = [];
  const J = s => { try { return JSON.parse(s); } catch (e) { return null; } };
  for (const s of sections) {
    const [kind, browser, profile, id] = s.head;
    if (kind === 'chromium-prefs') { const j = J(s.body.join('\n')) || {}; for (const [k, v] of Object.entries(j)) prefs.set(`${browser}|${profile}|${k}`, { ...(prefs.get(`${browser}|${profile}|${k}`) || {}), ...v }); }
    if (kind === 'chromium-messages') msgs.set(`${browser}|${profile}|${id}`, J(s.body.join('\n')) || {});
  }
  for (const s of sections) {
    const [kind, browser, profile, id, version] = s.head;
    if (kind === 'chromium-manifest') {
      const m = J(s.body.join('\n')); if (!m) continue;
      const msg = msgs.get(`${browser}|${profile}|${id}`) || {};
      const loc = v => { const x = String(v || '').match(/^__MSG_(.+)__$/); if (!x) return v; const e = Object.entries(msg).find(([k]) => k.toLowerCase() === x[1].toLowerCase()); return e ? e[1].message : v; };
      const p = prefs.get(`${browser}|${profile}|${id}`) || {};
      const perms = [...(m.permissions || []), ...(m.optional_permissions || [])].filter(x => typeof x === 'string');
      const hosts = [...(m.host_permissions || []), ...perms.filter(x => x.includes('://') || x === '<all_urls>'), ...((m.content_scripts || []).flatMap(c => c.matches || []))];
      list.push({ browser: browser.replace(/\/User Data$/, '').replace(/^.*\//, ''), profile, id, name: loc(m.name) || id, version: m.version || version, mv: m.manifest_version, location: p.location, locationName: CHROME_LOC[p.location] || (p.location === undefined ? 'unknown' : String(p.location)),
        fromStore: p.from_webstore, enabled: p.state === undefined ? true : p.state === 1 && !(p.disable_reasons > 0), installed: p.install_time ? chromeTime(p.install_time) : null, byDefault: !!(p.by_default || p.by_oem),
        perms: perms.filter(x => !x.includes('://')), broad: [...new Set(hosts)].some(h => BROAD.test(h)), hosts: [...new Set(hosts)].slice(0, 20), update: m.update_url || '' });
    } else if (kind === 'firefox') {
      const j = J(s.body.join('\n')) || {};
      for (const a of j.addons || []) {
        if (a.type !== 'extension' || /^app-(builtin|system)/.test(a.location || '')) continue;
        const perms = ((a.userPermissions || {}).permissions || []), origins = ((a.userPermissions || {}).origins || []);
        list.push({ browser: 'Firefox', profile: browser, id: a.id, name: (a.defaultLocale || {}).name || a.id, version: a.version, location: a.location, locationName: a.location,
          fromStore: /addons\.mozilla\.org/.test(a.sourceURI || '') || a.signedState === 2, signedState: a.signedState, enabled: !!a.active && !a.userDisabled, installed: a.installDate || null,
          perms, broad: origins.some(o => BROAD.test(o)), hosts: origins.slice(0, 20), source: a.sourceURI || '' });
      }
    } else if (kind === 'safari') {
      // pluginkit -mAvvv: "+    com.x.ext(1.2)" then indented "Key = value" lines
      let cur = null;
      for (const line of s.body) {
        const m = line.match(/^([+\-!=]?)\s*([A-Za-z0-9._-]+)\(([^)]*)\)\s*$/);
        if (m) { cur = { browser: 'Safari', profile: '', id: m[2], name: m[2], version: m[3], location: 'app extension', locationName: 'app extension', fromStore: null, enabled: m[1] !== '-', installed: null, perms: [], broad: false, hosts: [], path: '' }; list.push(cur); continue; }
        const kv = line.match(/^\s+([A-Za-z ]+?)\s*=\s*(.*)$/);
        if (!cur || !kv) continue;
        if (kv[1] === 'Path') cur.path = kv[2];
        else if (kv[1] === 'Display Name' && kv[2] && kv[2] !== '(null)') cur.name = kv[2];
        else if (kv[1] === 'Parent Name' && kv[2] && kv[2] !== '(null)') cur.parent = kv[2];
        else if (kv[1] === 'Timestamp') cur.installed = Date.parse(kv[2]) || null;
      }
    }
  }
  return list;
}
// Chrome stores install_time as microseconds since 1601-01-01
function chromeTime(v) { const n = Number(v); if (!n) return null; return n > 1e16 ? Math.round(n / 1000 - 11644473600000) : n; }

function analyzeExtensions(hs, add) {
  const list = hs.read('user/browser-extensions.txt', parseExtensions);
  if (!list) return { available: false };
  const exts = list.filter(e => e.location !== 5 && e.location !== 10 && !e.byDefault);
  const key = e => `${e.browser}|${e.profile}|${e.id}`;
  const prev = hs.store.kvGet('ext.baseline', null);
  const ver = hs.mtimes.get('user/browser-extensions.txt');
  const fresh = [];
  if (prev && prev.ver !== ver) for (const e of exts) if (!prev.keys.includes(key(e))) fresh.push({ at: Date.now(), key: key(e), name: e.name, browser: e.browser, profile: e.profile, version: e.version });
  if (!prev || prev.ver !== ver) hs.store.kvSet('ext.baseline', { keys: exts.map(key), ver, at: prev ? prev.at : Date.now() });
  const added = changeLog(hs.store, 'ext.changes', fresh);
  const newKeys = new Set(added.map(a => a.key));
  for (const e of exts) {
    e.risky = e.perms.filter(p => RISKY_PERMS.includes(p));
    e.sideloaded = e.location === 4 || e.location === 8 || (e.browser !== 'Firefox' && e.browser !== 'Safari' && e.fromStore === false && [1, 2, 3, 6].includes(e.location)) || (e.browser === 'Firefox' && e.signedState !== undefined && e.signedState <= 0);
    e.managed = e.location === 7 || e.location === 9;
    e.isNew = newKeys.has(key(e));
  }
  const name = e => `${e.name} ${e.version || ''} [${e.browser}${e.profile ? ' / ' + e.profile : ''}] ${e.id}`;
  const side = exts.filter(e => e.sideloaded && e.enabled);
  if (side.length) add({ sev: side.some(e => e.broad || e.risky.length) ? 'high' : 'medium', area: 'Browser', title: `${plural(side.length, 'sideloaded or unsigned browser extension')} enabled`, source: 'browser extensions',
    detail: 'Installed outside the browser’s store (developer mode, external install, command line) or unsigned. A common way info-stealers and ad-injectors get in; keep only ones you built or deliberately installed.',
    evidence: side.map(e => `${name(e)} — ${e.locationName}${e.broad ? ', access to all sites' : ''}${e.risky.length ? ', ' + e.risky.join(' ') : ''}`) });
  const nw = exts.filter(e => e.isNew);
  if (nw.length) add({ sev: nw.some(e => e.broad && e.risky.length) ? 'medium' : 'low', area: 'Browser', title: `${plural(nw.length, 'browser extension')} added (last 7 days)`, source: 'browser extensions', evidence: nw.map(e => `${name(e)}${e.broad ? ' — access to all sites' : ''}${e.risky.length ? ' — ' + e.risky.join(' ') : ''}`) });
  const powerful = exts.filter(e => e.enabled && e.broad && e.risky.some(p => ['debugger', 'nativeMessaging', 'proxy', 'webRequestBlocking', 'cookies', 'management', 'scripting', 'webRequest'].includes(p)));
  if (powerful.length) add({ sev: 'info', area: 'Browser', title: `${plural(powerful.length, 'extension')} can read and change data on every site`, source: 'browser extensions',
    detail: 'All-sites access plus request/cookie/scripting powers. Fine for ad blockers and password managers you trust; each one is a high-value target if its developer account is compromised.', evidence: powerful.map(e => `${name(e)} — ${e.risky.join(' ')}`) });
  return { available: true, total: exts.length, baselineAt: prev ? prev.at : Date.now(),
    extensions: exts.sort((a, b) => (b.sideloaded - a.sideloaded) || (b.isNew - a.isNew) || (b.broad - a.broad) || String(a.name).localeCompare(String(b.name))).slice(0, 500) };
}

// ----------------------------------------------------------- certificates
function parseCerts(text) {
  const out = { keychains: {}, trust: {} };
  let sec = '', cur = null;
  for (const line of String(text || '').split('\n')) {
    const h = line.match(/^== (.+)$/);
    if (h) { sec = h[1]; cur = null; continue; }
    if (/keychain$/.test(sec)) {
      const k = out.keychains[sec] = out.keychains[sec] || [];
      let m;
      if ((m = line.match(/^SHA-256 hash:\s*([0-9A-F]+)/i))) { cur = { sha256: m[1].toUpperCase(), name: '' }; k.push(cur); continue; }
      if ((m = line.match(/^SHA-1 hash:\s*([0-9A-F]+)/i))) { if (!cur || cur.sha1) { cur = { sha256: '', name: '' }; k.push(cur); } cur.sha1 = m[1].toUpperCase(); continue; }
      if (cur && (m = line.match(/"labl"<blob>="(.*)"\s*$/))) cur.name = m[1];
      else if (cur && !cur.name && (m = line.match(/"alis"<blob>="(.*)"\s*$/))) cur.name = m[1];
    } else if (/trust$/.test(sec)) {
      const t = out.trust[sec] = out.trust[sec] || [];
      let m;
      if ((m = line.match(/^Cert \d+:\s*(.*)$/))) { cur = { name: m[1].trim(), results: [] }; t.push(cur); }
      else if (cur && (m = line.match(/Result Type\s*:\s*(\S+)/))) cur.results.push(m[1].replace(/^kSecTrustSettingsResult/, ''));
    }
  }
  return out;
}

function analyzeCerts(hs, add) {
  const sys = hs.read('snapshots/certs-system.txt', parseCerts);
  const usr = hs.read('user/certs-user.txt', parseCerts);
  if (!sys && !usr) return { available: false };
  const sysCerts = (sys && sys.keychains['system.keychain']) || [];
  const trust = [...(((sys && sys.trust['admin trust']) || []).map(t => ({ ...t, domain: 'admin' }))), ...(((usr && usr.trust['user trust']) || []).map(t => ({ ...t, domain: 'user' })))];
  const roots = trust.filter(t => !t.results.length || t.results.some(r => /TrustRoot|TrustAsRoot/.test(r)));
  const certKey = c => c.sha256 || c.sha1 || c.name;
  const trustKey = t => `${t.domain}|${t.name}|${t.results.join(',')}`;
  const ver = `${hs.mtimes.get('snapshots/certs-system.txt')}|${hs.mtimes.get('user/certs-user.txt')}`;
  const prev = hs.store.kvGet('certs.baseline', null);
  const fresh = [];
  if (prev && prev.ver !== ver) {
    for (const c of sysCerts) if (!prev.certs.includes(certKey(c))) fresh.push({ at: Date.now(), kind: 'System keychain certificate', name: c.name || '(unnamed)', id: (c.sha256 || c.sha1 || '').slice(0, 16) });
    for (const t of trust) if (!prev.trust.includes(trustKey(t))) fresh.push({ at: Date.now(), kind: `${t.domain} trust setting`, name: t.name, id: t.results.join(', ') || 'trusted (default)', root: roots.includes(t) });
  }
  if (!prev || prev.ver !== ver) hs.store.kvSet('certs.baseline', { certs: sysCerts.map(certKey), trust: trust.map(trustKey), ver, at: prev ? prev.at : Date.now() });
  const changes = changeLog(hs.store, 'certs.changes', fresh);
  const newRoots = changes.filter(c => c.root);
  if (newRoots.length) add({ sev: 'high', area: 'Certificates', title: `${plural(newRoots.length, 'certificate')} newly trusted as a root`, source: 'security dump-trust-settings',
    detail: 'A newly trusted root can intercept HTTPS for every app on this Mac. Expected only for tools you set up on purpose (proxy debuggers, corporate inspection).', evidence: newRoots.map(c => `${fmt(c.at)}  ${c.kind}: ${c.name} (${c.id})`) });
  const newCerts = changes.filter(c => !c.root);
  if (newCerts.length) add({ sev: 'medium', area: 'Certificates', title: `${plural(newCerts.length, 'certificate change')} in the System keychain / trust settings (last 7 days)`, source: 'security find-certificate', evidence: newCerts.map(c => `${fmt(c.at)}  ${c.kind}: ${c.name} (${c.id})`) });
  if (roots.length) add({ sev: 'info', area: 'Certificates', title: `${plural(roots.length, 'custom-trusted certificate')} (admin / user trust settings)`, source: 'security dump-trust-settings',
    detail: 'Certificates someone explicitly marked as trusted, on top of Apple’s built-in roots.', evidence: roots.map(t => `${t.domain}: ${t.name} — ${t.results.join(', ') || 'trusted'}`) });
  return { available: true, systemCerts: sysCerts.map(c => ({ name: c.name, sha256: c.sha256, sha1: c.sha1 })), trust, changes: changes.slice().reverse(), baselineAt: prev ? prev.at : Date.now() };
}

module.exports = { analyzeLs, ingestLs, csvRows, analyzeNet, analyzeFim, analyzeExtensions, analyzeCerts, parseEstablished, parseProcs, parseFim, parseExtensions, parseCerts };
