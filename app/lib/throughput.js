'use strict';
// Per-minute event/byte counters per input, persisted to SQLite for the
// Throughput view (live answer to "how much log data is flowing?").
class Throughput {
  constructor(store) { this.store = store; this.cur = new Map(); }
  add(source, events, bytes) {
    const minute = Math.floor(Date.now() / 60000);
    const k = minute + '|' + source;
    const c = this.cur.get(k) || { minute, source, events: 0, bytes: 0 };
    c.events += events; c.bytes += bytes; this.cur.set(k, c);
  }
  flush() {
    if (!this.cur.size) return;
    const rows = [...this.cur.values()]; this.cur.clear();
    this.store.tx(() => {
      for (const r of rows) this.store.run(`INSERT INTO throughput(minute, source, events, bytes) VALUES (?, ?, ?, ?)
        ON CONFLICT(minute, source) DO UPDATE SET events = events + excluded.events, bytes = bytes + excluded.bytes`, r.minute, r.source, r.events, r.bytes);
    });
    this.store.run('DELETE FROM throughput WHERE minute < ?', Math.floor(Date.now() / 60000) - 8 * 1440);
  }
  summary(hours = 24, bucketMin = 10) {
    this.flush();
    const now = Math.floor(Date.now() / 60000), from = now - hours * 60;
    const rows = this.store.all('SELECT minute, source, events, bytes FROM throughput WHERE minute >= ? ORDER BY minute', from);
    const first = rows.length ? rows[0].minute : now;
    const spanMin = Math.max(1, now - first + 1);
    const sources = new Map(), buckets = new Map();
    for (const r of rows) {
      const s = sources.get(r.source) || { source: r.source, events: 0, bytes: 0, last15e: 0, last15b: 0 };
      s.events += r.events; s.bytes += r.bytes;
      if (r.minute > now - 15) { s.last15e += r.events; s.last15b += r.bytes; }
      sources.set(r.source, s);
      const b = Math.floor(r.minute / bucketMin) * bucketMin;
      const row = buckets.get(b) || { t: new Date(b * 60000) };
      row[r.source + ':e'] = (row[r.source + ':e'] || 0) + r.events;
      row[r.source + ':b'] = (row[r.source + ':b'] || 0) + r.bytes;
      buckets.set(b, row);
    }
    const out = [...sources.values()].map(s => ({
      ...s,
      eps: s.events / (spanMin * 60), bps: s.bytes / (spanMin * 60),
      eps15: s.last15e / 900, bps15: s.last15b / 900,
      perDayEvents: Math.round(s.events / spanMin * 1440), perDayBytes: Math.round(s.bytes / spanMin * 1440),
    })).sort((a, b) => b.bytes - a.bytes);
    const series = [];
    for (let b = Math.floor(from / bucketMin) * bucketMin; b <= now; b += bucketMin) series.push(buckets.get(b) || { t: new Date(b * 60000) });
    return { hours, bucketMin, spanMinutes: spanMin, sources: out, series };
  }
}
module.exports = { Throughput };
