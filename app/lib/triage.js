'use strict';
// Your triage (acknowledgements and the allow list) lives in the database volume,
// so it would be lost with ./argus.sh destroy or a damaged volume. Argus writes it
// nightly to $ARGUS_HOME/data/backups/triage-YYYYMMDD.json (14 kept), and can merge
// a backup back in: ./argus.sh backup / ./argus.sh restore <file>.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, env, logger, writeFileAtomic, dayKey } = require('./util');

const log = logger('triage');
const dir = () => path.join(cfg.data, 'backups');
const KEEP = () => Math.max(1, +env('ARGUS_BACKUP_KEEP', 14) || 14);

function snapshot(store) {
  return {
    kind: 'argus-triage', version: 1, written: new Date().toISOString(), argus: cfg.version,
    acks: store.all('SELECT id, fp, title, note, at, until FROM finding_acks ORDER BY at'),
    allow: store.all('SELECT entry, note, at FROM allowlist ORDER BY at'),
  };
}

function write(store, name = `triage-${dayKey()}.json`) {
  const file = path.join(dir(), name);
  writeFileAtomic(file, JSON.stringify(snapshot(store), null, 1));
  const old = list().filter(f => /^triage-\d{8}(-\d{6})?\.json$/.test(f)).slice(KEEP());
  for (const f of old) { try { fs.unlinkSync(path.join(dir(), f)); } catch (e) { /* leave it */ } }
  return file;
}

function due(store) { return store.kvGet('triage.backup', '') !== dayKey(); }
function nightly(store) {
  if (!due(store)) return;
  const f = write(store); store.kvSet('triage.backup', dayKey());
  log.info(`wrote ${path.basename(f)}`);
}

// Merges a backup: an acknowledgement or allow entry is added when missing and
// replaced when the backup's copy is newer. Nothing already here is removed.
function restore(store, intel, name) {
  const base = path.basename(String(name || ''));
  if (!/^[\w.-]+\.json$/.test(base)) throw new Error('give the name of a .json file in data/backups');
  const j = JSON.parse(fs.readFileSync(path.join(dir(), base), 'utf8'));
  if (j.kind !== 'argus-triage') throw new Error('not an Argus triage backup');
  let acks = 0, allow = 0;
  store.tx(() => {
    for (const a of j.acks || []) {
      if (!a.id || !a.fp) continue;
      const cur = store.get('SELECT at FROM finding_acks WHERE id = ?', a.id);
      if (cur && cur.at >= a.at) continue;
      store.run(`INSERT INTO finding_acks(id, fp, title, note, at, until) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET fp = excluded.fp, title = excluded.title, note = excluded.note, at = excluded.at, until = excluded.until`,
        String(a.id), String(a.fp), String(a.title || ''), String(a.note || ''), +a.at || Date.now(), a.until ? +a.until : null);
      acks++;
    }
    for (const e of j.allow || []) {
      const cur = store.get('SELECT at FROM allowlist WHERE entry = ?', e.entry);
      if (cur && cur.at >= e.at) continue;
      if (intel.allowAdd(e.entry, e.note || '')) { store.run('UPDATE allowlist SET at = ? WHERE entry = ?', +e.at || Date.now(), e.entry); allow++; }
    }
  });
  intel.allowRules = null;
  log.info(`restored ${base}: ${acks} acknowledgement(s), ${allow} allow entries`);
  return { acks, allow, written: j.written };
}

function list() {
  try {   // newest first, by when it was written
    return fs.readdirSync(dir()).filter(f => /^triage-.*\.json$/.test(f))
      .map(f => [f, fs.statSync(path.join(dir(), f)).mtimeMs]).sort((a, b) => b[1] - a[1]).map(x => x[0]);
  } catch (e) { return []; }
}

module.exports = { snapshot, write, nightly, restore, list };
