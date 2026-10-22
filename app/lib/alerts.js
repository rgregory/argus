'use strict';
// Alerts: tell someone when a new high finding appears or an input stops.
//
// Channels (any combination):
//   * macOS notification  data/alerts/outbox.tsv, shown by the com.argus.notify
//                         LaunchAgent the moment the file changes (on by default)
//   * ntfy                ARGUS_NTFY_URL (https://ntfy.sh/<topic> or self-hosted), ARGUS_NTFY_TOKEN
//   * Pushover            PUSHOVER_TOKEN + PUSHOVER_USER
//   * webhook             ARGUS_ALERT_WEBHOOK (JSON POST with title/text; Slack-compatible)
//
// A finding alerts once per fingerprint: it alerts again only when new evidence
// appears. Acknowledged findings never alert. On the very first run everything
// already open is recorded silently, so installing Argus doesn't page you for
// the backlog.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, logger, fetchText } = require('./util');

const log = logger('alerts');
const H = 3600e3;
const RANK = { high: 0, medium: 1, low: 2, info: 3 };
const SCHEMA = 'CREATE TABLE IF NOT EXISTS alert_sent (key TEXT PRIMARY KEY, fp TEXT NOT NULL, at INTEGER NOT NULL);';
const clean = s => String(s ?? '').replace(/[\t\r\n]+/g, ' ').trim();

class Alerts {
  constructor(store) {
    this.store = store;
    store.db.exec(SCHEMA);
    const env = process.env;
    this.minSev = RANK[String(env.ARGUS_ALERT_SEV || 'high').toLowerCase()] ?? 0;
    this.health = String(env.ARGUS_ALERT_HEALTH || 'fail').toLowerCase();   // fail | warn | off
    this.mac = !/^(0|false|no|off)$/i.test(env.ARGUS_ALERT_MAC || '1');
    this.ntfy = { url: (env.ARGUS_NTFY_URL || '').trim(), token: (env.ARGUS_NTFY_TOKEN || '').trim() };
    this.pushover = { token: (env.PUSHOVER_TOKEN || '').trim(), user: (env.PUSHOVER_USER || '').trim() };
    this.webhook = (env.ARGUS_ALERT_WEBHOOK || '').trim();
    this.publicUrl = (env.ARGUS_PUBLIC_URL || '').trim().replace(/\/+$/, '');
    this.maxPerHour = +(env.ARGUS_ALERT_MAX_PER_HOUR || 6);
    this.sentTimes = [];
    this.last = null; this.lastError = ''; this.sent = 0;
    this.outbox = path.join(cfg.data, 'alerts', 'outbox.tsv');
  }

  channels() { return { mac: this.mac, ntfy: !!this.ntfy.url, pushover: !!(this.pushover.token && this.pushover.user), webhook: !!this.webhook }; }

  // Collect what should alert now, send it, remember it.
  async process(report) {
    const items = [];
    for (const f of report.findings || []) {
      if (f.acked || (RANK[f.sev] ?? 9) > this.minSev) continue;
      items.push({ key: 'f:' + f.id, fp: f.fp || f.title, kind: 'finding', sev: f.sev, title: f.title, area: f.area, line: (f.evidence || [])[0] || '' });
    }
    const hc = (report.health && report.health.checks) || [];
    if (this.health !== 'off' && !(report.health && report.health.grace)) {
      for (const c of hc) {
        if (c.status === 'fail' || (this.health === 'warn' && c.status === 'warn')) items.push({ key: 'h:' + c.id, fp: c.status, kind: 'health', sev: c.status === 'fail' ? 'high' : 'medium', title: c.title, area: 'Argus', line: c.fix || c.detail });
      }
    }
    const sent = new Map(this.store.all('SELECT key, fp FROM alert_sent').map(r => [r.key, r.fp]));
    const now = Date.now();
    if (!this.store.kvGet('alerts.init', null)) {
      this.store.tx(() => { for (const it of items) this.store.run('INSERT OR REPLACE INTO alert_sent(key, fp, at) VALUES (?, ?, ?)', it.key, it.fp, now); });
      this.store.kvSet('alerts.init', now);
      log.info(`alerts armed; ${items.length} open item(s) recorded without notifying`);
      return;
    }
    const fresh = items.filter(it => sent.get(it.key) !== it.fp);
    // health checks that were alerted and have recovered
    const live = new Set(items.map(i => i.key));
    const recovered = report.health && report.health.grace ? [] : [...sent.keys()].filter(k => k.startsWith('h:') && !live.has(k) && hc.some(c => 'h:' + c.id === k && c.status === 'ok'));
    // findings that went away are forgotten, so they alert again if they come back
    const gone = [...sent.keys()].filter(k => k.startsWith('f:') && !live.has(k));
    if (gone.length) this.store.tx(() => gone.forEach(k => this.store.run('DELETE FROM alert_sent WHERE key = ?', k)));
    if (!fresh.length && !recovered.length) return;

    const msgs = [];
    const host = (report.host && report.host.name) || 'Mac';
    const findings = fresh.filter(i => i.kind === 'finding'), health = fresh.filter(i => i.kind === 'health');
    if (health.length) msgs.push({ sev: 'high', title: `Argus on ${host}: ${health.length === 1 ? health[0].title : health.length + ' inputs need attention'}`, body: health.map(h => `${h.title}${h.line ? ' — ' + h.line : ''}`).join('\n'), tags: 'warning' });
    if (findings.length === 1) {
      const f = findings[0];
      msgs.push({ sev: f.sev, title: `Argus ${f.sev} on ${host}: ${f.area}`, body: `${f.title}${f.line ? '\n' + clean(f.line).slice(0, 200) : ''}`, tags: 'rotating_light' });
    } else if (findings.length) {
      msgs.push({ sev: findings.some(f => f.sev === 'high') ? 'high' : 'medium', title: `Argus on ${host}: ${findings.length} new findings`, body: findings.slice(0, 8).map(f => `• [${f.sev}] ${f.title}`).join('\n') + (findings.length > 8 ? `\n…and ${findings.length - 8} more` : ''), tags: 'rotating_light' });
    }
    if (recovered.length) msgs.push({ sev: 'low', title: `Argus on ${host}: recovered`, body: recovered.map(k => (hc.find(c => 'h:' + c.id === k) || {}).title || k).join('\n'), tags: 'white_check_mark' });

    // rate limit: beyond the hourly cap, fold everything into one summary
    this.sentTimes = this.sentTimes.filter(t => now - t < H);
    let out = msgs;
    if (this.sentTimes.length + msgs.length > this.maxPerHour) {
      if (this.sentTimes.length >= this.maxPerHour) { log.warn(`rate limit reached; holding ${msgs.length} alert(s)`); return; }
      out = [{ sev: 'high', title: `Argus on ${host}: ${fresh.length} new alerts`, body: msgs.map(m => m.title.replace(/^Argus[^:]*: /, '')).join('\n'), tags: 'rotating_light' }];
    }
    for (const m of out) await this.send(m);
    this.sentTimes.push(...out.map(() => now));
    this.store.tx(() => {
      for (const it of fresh) this.store.run('INSERT OR REPLACE INTO alert_sent(key, fp, at) VALUES (?, ?, ?)', it.key, it.fp, now);
      for (const k of recovered) this.store.run('DELETE FROM alert_sent WHERE key = ?', k);
    });
  }

  async send(m) {
    const errs = [];
    const url = this.publicUrl || '';
    if (this.mac) {
      try {
        fs.mkdirSync(path.dirname(this.outbox), { recursive: true });
        fs.appendFileSync(this.outbox, `${Date.now()}\t${clean(m.sev)}\t${clean(m.title)}\t${clean(m.body).slice(0, 400)}\n`);
        const st = fs.statSync(this.outbox);
        if (st.size > 512 * 1024) fs.writeFileSync(this.outbox, '');   // the notifier tracks its offset and restarts from 0
      } catch (e) { errs.push('mac: ' + e.message); }
    }
    if (this.ntfy.url) {
      try {
        const h = { Title: m.title.replace(/[^\x20-\x7e]/g, ''), Priority: m.sev === 'high' ? '5' : m.sev === 'medium' ? '4' : '3', Tags: m.tags || '' };
        if (url) h.Click = url;
        if (this.ntfy.token) h.Authorization = `Bearer ${this.ntfy.token}`;
        const r = await fetchText(this.ntfy.url, { method: 'POST', headers: h, body: m.body, timeout: 15000 });
        if (!r.ok) errs.push(`ntfy: HTTP ${r.status}`);
      } catch (e) { errs.push('ntfy: ' + e.message); }
    }
    if (this.pushover.token && this.pushover.user) {
      try {
        const body = new URLSearchParams({ token: this.pushover.token, user: this.pushover.user, title: m.title, message: m.body, priority: m.sev === 'high' ? '1' : '0', ...(url ? { url, url_title: 'Open Argus' } : {}) });
        const r = await fetchText('https://api.pushover.net/1/messages.json', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(), timeout: 15000 });
        if (!r.ok) errs.push(`pushover: HTTP ${r.status}`);
      } catch (e) { errs.push('pushover: ' + e.message); }
    }
    if (this.webhook) {
      try {
        const r = await fetchText(this.webhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: m.title, text: `*${m.title}*\n${m.body}`, severity: m.sev, url: url || undefined }), timeout: 15000 });
        if (!r.ok) errs.push(`webhook: HTTP ${r.status}`);
      } catch (e) { errs.push('webhook: ' + e.message); }
    }
    this.sent++; this.last = { at: Date.now(), title: m.title };
    this.lastError = errs.join('; ');
    if (errs.length) log.warn(`alert "${m.title}": ${this.lastError}`); else log.info(`alert sent: ${m.title}`);
  }

  async test() {
    await this.send({ sev: 'low', title: 'Argus test alert', body: 'Alerts are working. This is a test from the dashboard.', tags: 'white_check_mark' });
    return { ok: !this.lastError, error: this.lastError, channels: this.channels() };
  }

  status() {
    const sevName = Object.keys(RANK).find(k => RANK[k] === this.minSev);
    return { channels: this.channels(), minSev: sevName, health: this.health, armed: !!this.store.kvGet('alerts.init', null), sent: this.sent, last: this.last, error: this.lastError, maxPerHour: this.maxPerHour };
  }
}

module.exports = { Alerts };
