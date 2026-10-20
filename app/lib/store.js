'use strict';
// SQLite state (node:sqlite, built into Node >= 22.13). Lives in the argus-state volume.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS observables (
  value TEXT NOT NULL, type TEXT NOT NULL,
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, hits INTEGER NOT NULL DEFAULT 0,
  sources TEXT NOT NULL DEFAULT '[]', context TEXT NOT NULL DEFAULT '',
  priority INTEGER NOT NULL DEFAULT 0,
  risk TEXT NOT NULL DEFAULT 'unknown', risk_score INTEGER NOT NULL DEFAULT 0, reasons TEXT NOT NULL DEFAULT '[]',
  enriched_at INTEGER,
  PRIMARY KEY (value, type)
);
CREATE INDEX IF NOT EXISTS obs_risk ON observables(risk_score DESC);
CREATE INDEX IF NOT EXISTS obs_seen ON observables(last_seen DESC);
CREATE INDEX IF NOT EXISTS obs_enrich ON observables(priority DESC, enriched_at);
CREATE TABLE IF NOT EXISTS enrichments (
  value TEXT NOT NULL, type TEXT NOT NULL, provider TEXT NOT NULL,
  fetched_at INTEGER NOT NULL, verdict TEXT NOT NULL, score INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '', data TEXT, error TEXT,
  PRIMARY KEY (value, type, provider)
);
CREATE TABLE IF NOT EXISTS feed_hits (
  value TEXT NOT NULL, type TEXT NOT NULL, feed TEXT NOT NULL, matched TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  PRIMARY KEY (value, type, feed)
);
CREATE TABLE IF NOT EXISTS processed (path TEXT PRIMARY KEY, size INTEGER, done_at INTEGER);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS throughput (minute INTEGER NOT NULL, source TEXT NOT NULL, events INTEGER NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (minute, source));
CREATE TABLE IF NOT EXISTS provider_usage (day TEXT NOT NULL, provider TEXT NOT NULL, calls INTEGER NOT NULL, PRIMARY KEY (day, provider));
`;

class Store {
  constructor(dir) {
    fs.mkdirSync(dir, { recursive: true });
    this.db = new DatabaseSync(path.join(dir, 'argus.db'));
    this.db.exec(SCHEMA);
    this.cache = new Map();
  }
  q(sql) {
    let s = this.cache.get(sql);
    if (!s) { s = this.db.prepare(sql); this.cache.set(sql, s); }
    return s;
  }
  run(sql, ...p) { return this.q(sql).run(...p); }
  get(sql, ...p) { return this.q(sql).get(...p); }
  all(sql, ...p) { return this.q(sql).all(...p); }
  tx(fn) {
    this.db.exec('BEGIN');
    try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  kvGet(key, d = null) { const r = this.get('SELECT value FROM kv WHERE key = ?', key); return r ? JSON.parse(r.value) : d; }
  kvSet(key, v) { this.run('INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, JSON.stringify(v)); }
}

module.exports = { Store };
