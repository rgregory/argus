'use strict';
// History for the Overview: hourly security-event counts (31 days) for the clock's
// "normal" outline and the events-per-day bars, and the open findings at the end of
// each day (from the hourly finding snapshots) for the trend charts.
const H = 3600e3, D = 86400e3;
const CATS = ['auth', 'gatekeeper', 'tcc', 'firewall', 'background'];
const SCHEMA = `CREATE TABLE IF NOT EXISTS tl_hourly (hour INTEGER PRIMARY KEY, ${CATS.map(c => c + ' INTEGER NOT NULL DEFAULT 0').join(', ')}, total INTEGER NOT NULL DEFAULT 0);`;

class Trends {
  constructor(store) { this.store = store; store.db.exec(SCHEMA); }

  // The 24-hour window is rebuilt every few minutes; the oldest hour in it can be
  // partial (cut by the window), so a stored hour only ever grows.
  record(timeline) {
    if (!Array.isArray(timeline) || !timeline.length) return;
    const cur = Math.floor(Date.now() / H) * H;
    this.store.tx(() => {
      for (const x of timeline) {
        const hour = Math.floor(+new Date(x.t) / H) * H;
        if (!isFinite(hour) || hour > cur) continue;
        const v = CATS.map(c => +x[c] || 0), total = v.reduce((a, b) => a + b, 0);
        this.store.run(`INSERT INTO tl_hourly(hour, ${CATS.join(', ')}, total) VALUES (?, ${CATS.map(() => '?').join(', ')}, ?)
          ON CONFLICT(hour) DO UPDATE SET ${CATS.map(c => `${c} = MAX(${c}, excluded.${c})`).join(', ')}, total = MAX(total, excluded.total)`, hour, ...v, total);
      }
      this.store.run('DELETE FROM tl_hourly WHERE hour < ?', Date.now() - 32 * D);
    });
  }

  // [hourStartMs, total] for the last 31 days; the browser groups by its own local hour.
  hourly() { return this.store.all('SELECT hour, total FROM tl_hourly WHERE hour > ? ORDER BY hour', Date.now() - 31 * D).map(r => [r.hour, r.total]); }

  // Open (not acknowledged) findings at the last snapshot of each day.
  findings(days = 30) {
    let rows = [];
    try {
      rows = this.store.all(`WITH d AS (SELECT MAX(ts) AS ts FROM finding_snap WHERE ts > ? GROUP BY date(ts / 1000, 'unixepoch', 'localtime'))
        SELECT s.ts, s.sev, s.area, COUNT(*) AS n FROM finding_snap s JOIN d ON s.ts = d.ts WHERE s.id != '' AND s.acked = 0 GROUP BY s.ts, s.sev, s.area ORDER BY s.ts`, Date.now() - days * D);
    } catch (e) { return null; }
    const empty = this.store.all(`SELECT MAX(ts) AS ts FROM finding_snap WHERE ts > ? GROUP BY date(ts / 1000, 'unixepoch', 'localtime') ORDER BY ts`, Date.now() - days * D).map(r => r.ts);
    const days_ = [...new Set([...empty, ...rows.map(r => r.ts)])].sort((a, b) => a - b);
    const idx = new Map(days_.map((t, i) => [t, i]));
    const zero = () => days_.map(() => 0);
    const total = { high: zero(), medium: zero(), low: zero() }, areas = {};
    for (const r of rows) {
      const i = idx.get(r.ts);
      if (total[r.sev]) total[r.sev][i] += r.n;
      if (r.sev === 'high' || r.sev === 'medium') {
        const a = areas[r.area] || (areas[r.area] = { high: zero(), medium: zero() });
        a[r.sev][i] += r.n;
      }
    }
    return { days: days_, total, areas };
  }

  view() { return { hourly: this.hourly(), findings: this.findings(30) }; }
}

module.exports = { Trends };
