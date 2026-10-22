'use strict';
// Sigma detection rules (SigmaHQ, macOS process_creation) evaluated against
// Endpoint Security exec events. Rules are fetched weekly from GitHub into the
// state volume and compiled into matcher functions.
//
// Field mapping (Sigma → eslogger exec): Image → target executable path,
// CommandLine → joined argv, ParentImage → the process that called exec.
// Rules that need any other field (OriginalFileName, ParentCommandLine, ...)
// are skipped, and listed as unsupported in the status.
//
// Your own rules: put .yml files in $ARGUS_HOME/data/sigma/ (the container's
// /data/sigma). They load within a minute and replace a SigmaHQ rule with the same id.
// Rules can be muted from the dashboard; the list lives in the state volume.
//
// Sigma rules are licensed under the Detection Rule License (DRL) 1.1; each
// match carries the rule's title, id, author and a link to the rule.
const fs = require('node:fs');
const path = require('node:path');
const YAML = require('yaml');
const { cfg, logger, fetchText, fetchJson, writeFileAtomic } = require('./util');

const log = logger('sigma');
const D = 86400e3;
const REPO = 'SigmaHQ/sigma', BRANCH = 'master';
const FIELDS = new Set(['Image', 'CommandLine', 'ParentImage']);

// ------------------------------------------------------------- matching
const escRe = s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
function globRe(v, mode) {   // Sigma wildcards: * and ?, \* \? are literal
  let out = '';
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if (c === '\\' && (v[i + 1] === '*' || v[i + 1] === '?' || v[i + 1] === '\\')) { out += escRe(v[i + 1]); i++; }
    else if (c === '*') out += '.*';
    else if (c === '?') out += '.';
    else out += escRe(c);
  }
  if (mode === 'contains') out = '.*' + out + '.*';
  else if (mode === 'startswith') out = out + '.*';
  else if (mode === 'endswith') out = '.*' + out;
  return new RegExp('^' + out + '$', 'is');
}
function fieldMatcher(key, value) {
  const [field, ...mods] = key.split('|');
  if (!FIELDS.has(field)) throw new Error(`unsupported field ${field}`);
  const all = mods.includes('all');
  const mode = mods.find(m => ['contains', 'startswith', 'endswith', 're'].includes(m)) || 'equals';
  const bad = mods.filter(m => !['contains', 'startswith', 'endswith', 're', 'all'].includes(m));
  if (bad.length) throw new Error(`unsupported modifier ${bad.join(',')}`);
  const vals = (Array.isArray(value) ? value : [value]);
  const tests = vals.map(v => {
    if (v === null) return s => !s;
    const sv = String(v);
    if (mode === 're') { const re = new RegExp(sv); return s => re.test(s || ''); }
    const re = globRe(sv, mode);
    return s => re.test(s || '');
  });
  return ev => { const s = ev[field]; return all ? tests.every(t => t(s)) : tests.some(t => t(s)); };
}
function selectionMatcher(sel) {
  if (Array.isArray(sel)) {
    if (sel.every(x => typeof x !== 'object' || x === null)) throw new Error('keyword selections unsupported');
    const ms = sel.map(selectionMatcher);
    return ev => ms.some(m => m(ev));
  }
  if (typeof sel !== 'object' || sel === null) throw new Error('keyword selections unsupported');
  const ms = Object.entries(sel).map(([k, v]) => fieldMatcher(k, v));
  return ev => ms.every(m => m(ev));
}
// condition grammar: or / and / not / ( ) / "1 of x*" / "all of x*" / "1 of them"
function conditionMatcher(cond, sels) {
  const toks = String(cond).match(/\(|\)|[^\s()]+/g) || [];
  let i = 0;
  const peek = () => toks[i], next = () => toks[i++];
  const group = (pat) => {
    const names = pat === 'them' ? Object.keys(sels) : Object.keys(sels).filter(n => new RegExp('^' + pat.split('*').map(escRe).join('.*') + '$').test(n));
    if (!names.length) throw new Error(`condition refers to nothing: ${pat}`);
    return names.map(n => sels[n]);
  };
  const primary = () => {
    const t = next();
    if (t === '(') { const e = orExpr(); if (next() !== ')') throw new Error('unbalanced condition'); return e; }
    if (t === 'not') { const e = primary(); return ev => !e(ev); }
    if ((t === '1' || t === 'all' || t === 'any') && peek() === 'of') { next(); const ms = group(next()); return t === 'all' ? ev => ms.every(m => m(ev)) : ev => ms.some(m => m(ev)); }
    if (!sels[t]) throw new Error(`unknown selection ${t}`);
    return sels[t];
  };
  const andExpr = () => { let l = primary(); while (peek() === 'and') { next(); const r = primary(), a = l; l = ev => a(ev) && r(ev); } return l; };
  const orExpr = () => { let l = andExpr(); while (peek() === 'or') { next(); const r = andExpr(), a = l; l = ev => a(ev) || r(ev); } return l; };
  const e = orExpr();
  if (i < toks.length) throw new Error(`unexpected "${toks[i]}" in condition`);
  return e;
}
function compile(text, file) {
  const r = YAML.parse(text);
  if (!r || !r.detection || !r.logsource) throw new Error('not a rule');
  if (r.logsource.category !== 'process_creation' || r.logsource.product !== 'macos') throw new Error('not a macOS process_creation rule');
  if (r.status === 'deprecated' || r.status === 'unsupported') throw new Error(`status ${r.status}`);
  const conds = Array.isArray(r.detection.condition) ? r.detection.condition : [r.detection.condition];
  if (r.detection.timeframe || conds.some(c => /\|/.test(String(c)))) throw new Error('aggregations unsupported');
  const sels = {};
  for (const [k, v] of Object.entries(r.detection)) if (k !== 'condition') sels[k] = selectionMatcher(v);
  const ms = conds.map(c => conditionMatcher(c, sels));
  return { id: r.id || file, title: r.title || file, level: r.level || 'medium', author: r.author || '', file,
    tags: (r.tags || []).filter(t => /^attack\./.test(t)), falsepositives: r.falsepositives || [],
    link: `https://github.com/${REPO}/blob/${BRANCH}/rules/macos/process_creation/${file}`, test: ev => ms.some(m => m(ev)) };
}

class Sigma {
  constructor() {
    this.dir = path.join(cfg.state, 'sigma');
    this.localDir = path.join(cfg.data, 'sigma');
    fs.mkdirSync(this.dir, { recursive: true });
    try { fs.mkdirSync(this.localDir, { recursive: true }); } catch (e) { /* read-only data dir */ }
    this.rules = []; this.skipped = []; this.meta = {}; this.localSig = '';
    this.muted = new Set();
    try { this.muted = new Set(JSON.parse(fs.readFileSync(path.join(this.dir, 'muted.json'), 'utf8'))); } catch (e) { /* none */ }
    this.disabled = String(process.env.ARGUS_SIGMA || '1') === '0';
    try { this.meta = JSON.parse(fs.readFileSync(path.join(this.dir, 'meta.json'), 'utf8')); } catch (e) { /* none */ }
    this.load();
  }
  listLocal() { try { return fs.readdirSync(this.localDir).filter(n => /\.ya?ml$/.test(n)); } catch (e) { return []; } }
  localSignature() { return this.listLocal().map(n => { try { return n + ':' + fs.statSync(path.join(this.localDir, n)).mtimeMs; } catch (e) { return n; } }).join('|'); }
  // Called every ingest cycle: reload when a local rule is added, changed or removed.
  maybeReload() { const s = this.localSignature(); if (s !== this.localSig) { this.load(); } }
  load() {
    const all = [], skipped = [];
    const take = (dir, f, local) => {
      try {
        const r = compile(fs.readFileSync(path.join(dir, f), 'utf8'), f);
        r.local = local;
        if (local) r.link = '';
        all.push(r);
      } catch (e) { skipped.push({ file: f, why: e.message, local }); }
    };
    let files = [];
    try { files = fs.readdirSync(this.dir).filter(n => n.endsWith('.yml')); } catch (e) { /* none */ }
    files.forEach(f => take(this.dir, f, false));
    const local = this.listLocal();
    local.forEach(f => take(this.localDir, f, true));
    this.localSig = this.localSignature();
    // a local rule replaces a SigmaHQ rule with the same id
    const byId = new Map();
    for (const r of all) if (!byId.has(r.id) || r.local) byId.set(r.id, r);
    const off = new Set(String(process.env.ARGUS_SIGMA_DISABLE || '').split(/[,\s]+/).filter(Boolean));
    const rules = [];
    for (const r of byId.values()) {
      if (off.has(r.id) || off.has(r.file)) { skipped.push({ file: r.file, id: r.id, title: r.title, why: 'disabled in ARGUS_SIGMA_DISABLE', local: r.local }); continue; }
      rules.push(r);
    }
    this.all = rules;
    this.rules = rules.filter(r => !this.muted.has(r.id));
    this.skipped = skipped;
    if (files.length || local.length) log.info(`${this.rules.length} Sigma rules active (${local.length} local), ${this.muted.size} muted, ${skipped.length} skipped`);
  }
  isMuted(id) { return this.muted.has(id); }
  setMuted(id, on) {
    if (on) this.muted.add(id); else this.muted.delete(id);
    writeFileAtomic(path.join(this.dir, 'muted.json'), JSON.stringify([...this.muted]));
    this.rules = (this.all || []).filter(r => !this.muted.has(r.id));
  }
  // Full rule list for the dashboard panel.
  list() {
    return (this.all || []).map(r => ({ id: r.id, title: r.title, level: r.level, author: r.author, file: r.file, local: !!r.local, link: r.link, tags: r.tags,
      falsepositives: r.falsepositives, muted: this.muted.has(r.id) }));
  }
  async refresh(force = false) {
    if (this.disabled) return;
    if (!force && this.meta.updated && Date.now() - this.meta.updated < 7 * D) return;
    if (!force && this.meta.failed && Date.now() - this.meta.failed < 6 * 3600e3) return;
    try {
      const t = await fetchJson(`https://api.github.com/repos/${REPO}/git/trees/${BRANCH}?recursive=1`, { headers: { Accept: 'application/vnd.github+json' }, timeout: 60000 });
      if (!t.ok || !t.json || !Array.isArray(t.json.tree)) throw new Error(`GitHub tree HTTP ${t.status}`);
      const paths = t.json.tree.map(x => x.path).filter(p => /^rules\/macos\/process_creation\/[^/]+\.yml$/.test(p));
      if (!paths.length) throw new Error('no macOS process_creation rules in the tree');
      let n = 0;
      for (const p of paths) {
        const r = await fetchText(`https://raw.githubusercontent.com/${REPO}/${BRANCH}/${p}`, { timeout: 30000, maxBytes: 200000 });
        if (r.ok) { writeFileAtomic(path.join(this.dir, path.basename(p)), r.text); n++; }
      }
      const keep = new Set(paths.map(p => path.basename(p)));
      for (const f of fs.readdirSync(this.dir)) if (f.endsWith('.yml') && !keep.has(f)) fs.unlinkSync(path.join(this.dir, f));
      this.meta = { updated: Date.now(), files: n, error: '' };
      this.load();
    } catch (e) {
      this.meta = { ...this.meta, failed: Date.now(), error: e.message };
      log.warn(`refresh failed: ${e.message}`);
    }
    writeFileAtomic(path.join(this.dir, 'meta.json'), JSON.stringify(this.meta));
  }
  match(ev) {
    const hits = [];
    for (const r of this.rules) { try { if (r.test(ev)) hits.push(r); } catch (e) { /* bad regex at runtime */ } }
    return hits;
  }
  status() {
    return { enabled: !this.disabled, rules: this.rules.length, local: (this.all || []).filter(r => r.local).length, muted: this.muted.size, skipped: this.skipped.length, skippedList: this.skipped.slice(0, 200),
      updated: this.meta.updated || null, error: this.meta.error || '', localDir: '$ARGUS_HOME/data/sigma' };
  }
}

module.exports = { Sigma, compile };
