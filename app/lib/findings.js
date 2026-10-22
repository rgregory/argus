'use strict';
// Finding state: acknowledgements, 24-hour change tracking and the daily digest.
//
// A finding's fingerprint is a hash of its evidence with timestamps and repeat
// counters removed, so an acknowledged finding stays hidden while the same items
// keep recurring, and comes back as soon as a new item appears in its evidence.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { cfg, logger, writeFileAtomic, dayKey } = require('./util');

const log = logger('findings');
const H = 3600e3, D = 86400e3;
const SCHEMA = `
CREATE TABLE IF NOT EXISTS finding_acks (id TEXT PRIMARY KEY, fp TEXT NOT NULL, title TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS finding_snap (ts INTEGER NOT NULL, id TEXT NOT NULL, sev TEXT NOT NULL, area TEXT NOT NULL, title TEXT NOT NULL, fp TEXT NOT NULL, PRIMARY KEY (ts, id));
CREATE INDEX IF NOT EXISTS finding_snap_ts ON finding_snap(ts);
`;

const TS = /^\s*\d{4}-\d\d-\d\d[ T]\d\d:\d\d(:\d\d)?(\.\d+)?Z?\s*/;
function normLine(l) {
  return String(l).replace(TS, '').replace(/\s*\(×\d+\)|\s*\(\d+×\)|\b\d+×/g, '')
    .replace(/\b(last|first seen|updated|modified)\s+\d{4}-\d\d-\d\d[ T][\d:]+/gi, '$1').trim();
}
function fingerprint(f) {
  const lines = [...new Set((f.evidence || []).map(normLine).filter(Boolean))].sort();
  return crypto.createHash('sha1').update(lines.join('\n')).digest('hex').slice(0, 16);
}

class FindingState {
  constructor(store) {
    this.store = store;
    store.db.exec(SCHEMA);
    this.lastSnap = (store.get('SELECT MAX(ts) AS t FROM finding_snap') || {}).t || 0;
  }

  // Adds fp / acked / ackChanged to each finding. Returns the number hidden.
  annotate(findings) {
    const acks = new Map(this.store.all('SELECT id, fp, note, at FROM finding_acks').map(a => [a.id, a]));
    let hidden = 0;
    for (const f of findings) {
      f.fp = fingerprint(f);
      const a = acks.get(f.id);
      if (!a) continue;
      if (a.fp === f.fp) { f.acked = { at: a.at, note: a.note }; hidden++; }
      else f.ackChanged = { at: a.at, note: a.note };   // acknowledged earlier, but something new appeared
    }
    return hidden;
  }

  ack(id, fp, title, note) {
    this.store.run(`INSERT INTO finding_acks(id, fp, title, note, at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET fp = excluded.fp, title = excluded.title, note = excluded.note, at = excluded.at`, id, fp, String(title).slice(0, 300), String(note || '').slice(0, 500), Date.now());
  }
  unack(id) { this.store.run('DELETE FROM finding_acks WHERE id = ?', id); }
  acks() { return this.store.all('SELECT id, title, note, at FROM finding_acks ORDER BY at DESC'); }

  // Hourly snapshot of the visible findings, kept 8 days.
  snapshot(findings, force = false) {
    const now = Date.now();
    if (!force && now - this.lastSnap < H - 60e3) return;
    this.store.tx(() => {
      for (const f of findings) this.store.run('INSERT OR REPLACE INTO finding_snap(ts, id, sev, area, title, fp) VALUES (?, ?, ?, ?, ?, ?)', now, f.id, f.sev, f.area, f.title, f.fp || fingerprint(f));
      if (!findings.length) this.store.run("INSERT OR REPLACE INTO finding_snap(ts, id, sev, area, title, fp) VALUES (?, '', '', '', '', '')", now);
      this.store.run('DELETE FROM finding_snap WHERE ts < ?', now - 8 * D);
    });
    this.lastSnap = now;
  }

  // New, changed and resolved compared with the snapshot closest to `hours` ago.
  changes(findings, hours = 24) {
    const target = Date.now() - hours * H;
    const row = this.store.get('SELECT ts FROM finding_snap WHERE ts <= ? ORDER BY ts DESC LIMIT 1', target)
      || this.store.get('SELECT ts FROM finding_snap ORDER BY ts ASC LIMIT 1');
    if (!row) return { since: null, new: [], changed: [], resolved: [] };
    const then = new Map(this.store.all("SELECT id, sev, area, title, fp FROM finding_snap WHERE ts = ? AND id != ''", row.ts).map(r => [r.id, r]));
    const now = new Map(findings.map(f => [f.id, f]));
    const pick = f => ({ id: f.id, sev: f.sev, area: f.area, title: f.title, acked: !!f.acked });
    const out = { since: row.ts, new: [], changed: [], resolved: [] };
    for (const f of findings) {
      const t = then.get(f.id);
      if (!t) out.new.push(pick(f));
      else if (t.fp !== f.fp && !f.acked) out.changed.push({ ...pick(f), was: t.sev !== f.sev ? t.sev : undefined });
    }
    for (const [id, t] of then) if (!now.has(id)) out.resolved.push({ id, sev: t.sev, area: t.area, title: t.title });
    return out;
  }

  // ---------------------------------------------------------- daily digest
  digestDue() {
    const hour = +(process.env.ARGUS_DIGEST_HOUR ?? 7);
    if (!(hour >= 0 && hour <= 23)) return false;
    const now = new Date();
    if (now.getHours() < hour) return false;
    return !fs.existsSync(path.join(cfg.data, 'reports', `digest-${dayKey()}.html`));
  }

  writeDigest(report) {
    const ch = report.changes || this.changes(report.findings);
    const live = report.findings.filter(f => !f.acked);
    const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
    const badge = s => `<span class="badge ${({ high: 'bg-red-lt', medium: 'bg-orange-lt', low: 'bg-yellow-lt', info: 'bg-azure-lt' })[s] || 'bg-secondary-lt'}">${esc(s)}</span>`;
    const rows = list => list.length ? list.map(f => `<tr><td>${badge(f.sev)}</td><td class="text-secondary">${esc(f.area)}</td><td>${esc(f.title)}${f.was ? ` <span class="text-secondary">(was ${esc(f.was)})</span>` : ''}</td></tr>`).join('') : '<tr><td colspan="3" class="text-secondary">None.</td></tr>';
    const evid = list => list.map(f => `<details class="mb-2"><summary>${badge(f.sev)} ${esc(f.title)}</summary><pre>${esc((f.evidence || []).slice(0, 40).join('\n'))}</pre></details>`).join('') || '<p class="text-secondary">None.</p>';
    const top = live.filter(f => f.sev === 'high' || f.sev === 'medium');
    const p = report.posture.filter(x => x.status === 'fail' || x.status === 'warn');
    const date = new Date();
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus digest ${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1/dist/css/tabler.min.css">
<script>(function(){var d=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.setAttribute('data-bs-theme',d?'dark':'light');})();</script>
<style>body{background:var(--tblr-bg-surface-secondary)} .wrap{max-width:960px;margin:1.5rem auto;padding:0 16px} pre{white-space:pre-wrap;font-size:.78rem;background:var(--tblr-bg-surface-tertiary);color:var(--tblr-body-color);padding:.6rem;border-radius:4px}</style></head>
<body><div class="wrap">
<h1 class="mb-1">Argus daily digest</h1>
<p class="text-secondary">${esc(report.host.name)} · macOS ${esc(report.host.os)} · ${esc(date.toLocaleString())} · changes since ${ch.since ? esc(new Date(ch.since).toLocaleString()) : 'the first snapshot'}</p>
<div class="row row-cards mb-3">
${['high', 'medium', 'low', 'info'].map(s => `<div class="col-6 col-md-3"><div class="card card-sm"><div class="card-body"><div class="subheader">${s}</div><div class="h2 m-0">${live.filter(f => f.sev === s).length}</div></div></div></div>`).join('')}
</div>
<div class="card mb-3"><div class="card-header"><h3 class="card-title">New (${ch.new.length})</h3></div><table class="table table-sm card-table">${rows(ch.new)}</table></div>
<div class="card mb-3"><div class="card-header"><h3 class="card-title">Changed (${ch.changed.length})</h3></div><table class="table table-sm card-table">${rows(ch.changed)}</table></div>
<div class="card mb-3"><div class="card-header"><h3 class="card-title">Resolved (${ch.resolved.length})</h3></div><table class="table table-sm card-table">${rows(ch.resolved)}</table></div>
<div class="card mb-3"><div class="card-header"><h3 class="card-title">Open high and medium findings (${top.length})</h3></div><div class="card-body">${evid(top)}</div></div>
<div class="card mb-3"><div class="card-header"><h3 class="card-title">Posture needing attention (${p.length})</h3></div><table class="table table-sm card-table">${p.map(x => `<tr><td>${x.status === 'fail' ? badge('high') : badge('low')}</td><td>${esc(x.control)}</td><td class="text-secondary">${esc(x.value)}</td></tr>`).join('') || '<tr><td class="text-secondary">All checks pass.</td></tr>'}</table></div>
<p class="text-secondary small">${report.findingState ? `${report.findingState.acked} acknowledged finding(s) hidden.` : ''} Generated by Argus ${esc(report.version)}.</p>
</div></body></html>`;
    const dir = path.join(cfg.data, 'reports');
    writeFileAtomic(path.join(dir, `digest-${dayKey()}.html`), html);
    writeFileAtomic(path.join(dir, 'digest-latest.html'), html);
    for (const n of fs.readdirSync(dir)) if (/^digest-\d{8}\.html$/.test(n) && fs.statSync(path.join(dir, n)).mtimeMs < Date.now() - 30 * D) fs.unlinkSync(path.join(dir, n));
    log.info(`digest written: ${ch.new.length} new, ${ch.changed.length} changed, ${ch.resolved.length} resolved`);
    return html;
  }
}

module.exports = { FindingState, fingerprint, normLine };
