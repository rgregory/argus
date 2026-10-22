'use strict';
// The Argus Weekly: a one-page, printable front page for the week. Written on
// ARGUS_WEEKLY_DAY (default 1 = Monday) after ARGUS_DIGEST_HOUR, kept 26 weeks,
// and available any time from /api/weekly. Print it or save it as a PDF from the browser.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, logger, writeFileAtomic } = require('./util');

const log = logger('weekly');
const D = 86400e3;
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const num = n => Number(n || 0).toLocaleString('en-US');
const ymd = d => `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
const day = ms => new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
const SEV = { high: '#b3261e', medium: '#d77a1f', low: '#a98c1c', info: '#5f7a94' };

function weekStart(now = new Date()) {
  const want = +(process.env.ARGUS_WEEKLY_DAY ?? 1);
  const d = new Date(now); d.setHours(0, 0, 0, 0);
  while (d.getDay() !== ((want % 7) + 7) % 7) d.setDate(d.getDate() - 1);
  return d;
}
function weeklyDue() {
  const want = +(process.env.ARGUS_WEEKLY_DAY ?? 1), hour = +(process.env.ARGUS_DIGEST_HOUR ?? 7);
  if (!(want >= 0 && want <= 6) || !(hour >= 0 && hour <= 23)) return false;
  const now = new Date();
  if (now.getDay() !== want || now.getHours() < hour) return false;
  return !fs.existsSync(path.join(cfg.data, 'reports', `weekly-${ymd(weekStart(now))}.html`));
}

// Open high + medium per day, as a small line chart.
function trendSvg(tr) {
  if (!tr || !tr.days || tr.days.length < 2) return '<p class="note">The trend line appears once Argus has two days of snapshots.</p>';
  const W = 380, H = 150, l = 26, r = 8, t = 10, b = 22, n = tr.days.length;
  const hi = tr.total.high, me = tr.total.medium, max = Math.max(1, ...hi.map((v, i) => v + me[i]));
  const x = i => l + (W - l - r) * (n === 1 ? 0 : i / (n - 1)), y = v => t + (H - t - b) * (1 - v / max);
  const line = (arr, c, w) => `<polyline fill="none" stroke="${c}" stroke-width="${w}" points="${arr.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')}"/>`;
  const both = hi.map((v, i) => v + me[i]);
  const area = `<polygon fill="${SEV.medium}" opacity=".12" points="${x(0)},${y(0)} ${both.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')} ${x(n - 1)},${y(0)}"/>`;
  const ticks = [0, Math.floor((n - 1) / 2), n - 1].map((i, k) => `<text x="${x(i)}" y="${H - 5}" text-anchor="${['start', 'middle', 'end'][k]}">${esc(day(tr.days[i]))}</text>`).join('');
  return `<svg viewBox="0 0 ${W} ${H}" class="chart">${area}<line x1="${l}" x2="${W - r}" y1="${y(0)}" y2="${y(0)}" stroke="#ddd3c1"/>`
    + `<text x="${l - 6}" y="${y(max) + 4}" text-anchor="end">${max}</text>${line(both, SEV.medium, 1.5)}${line(hi, SEV.high, 2.5)}${ticks}</svg>`
    + `<div class="key"><span style="--c:${SEV.high}">high</span><span style="--c:${SEV.medium}">high + medium</span></div>`;
}

function weeklyHtml(report, ctx) {
  const { fstate, trends } = ctx;
  const now = new Date(), start = weekStart(now), live = report.findings.filter(f => !f.acked);
  const week = fstate.changes(report.findings, 168);
  const tr = trends ? trends.findings(30) : null;
  const top = live.filter(f => f.sev === 'high' || f.sev === 'medium');
  const posture = (report.posture || []).filter(p => p.status === 'fail' || p.status === 'warn');
  const health = report.health ? report.health.checks.filter(c => c.status !== 'ok') : [];
  const hostName = report.host.name || 'this Mac';
  // last week's open count from the trend series
  let lastWeek = null;
  if (tr && tr.days.length) {
    const i = tr.days.findIndex(t => t >= Date.now() - 7 * D);
    if (i > 0) lastWeek = tr.total.high[i - 1] + tr.total.medium[i - 1];
  }
  const openHM = (report.counts.high || 0) + (report.counts.medium || 0);
  const evWeek = trends ? trends.hourly().filter(([t]) => t >= Date.now() - 7 * D).reduce((a, [, v]) => a + v, 0) : 0;
  const newBins = ((report.hostsec && report.hostsec.es && report.hostsec.es.newBinaries) || []).filter(b => b.first_seen >= Date.now() - 7 * D);
  const flagged = (report.intel.malicious || 0) + (report.intel.suspicious || 0);

  const lede = [
    `${week.new.length ? `<b>${week.new.length}</b> new ${week.new.length === 1 ? 'finding' : 'findings'} this week` : 'No new findings this week'}, <b>${week.resolved.length}</b> resolved.`,
    `<b style="color:${SEV.high}">${report.counts.high || 0}</b> high and <b style="color:${SEV.medium}">${report.counts.medium || 0}</b> medium open${lastWeek !== null ? `, ${openHM > lastWeek ? 'up' : openHM < lastWeek ? 'down' : 'level'} from <b>${lastWeek}</b> a week ago` : ''}.`,
    report.vulns && report.vulns.macos && report.vulns.macos.installed ? (report.vulns.macos.behind && report.vulns.macos.behind.length ? `macOS ${esc(report.vulns.macos.installed)} is <b style="color:${SEV.high}">${report.vulns.macos.behind.length}</b> security ${report.vulns.macos.behind.length === 1 ? 'release' : 'releases'} behind.` : `macOS ${esc(report.vulns.macos.installed)} is current.`) : '',
    health.length ? `<b style="color:${SEV.high}">${health.length}</b> ${health.length === 1 ? 'input needs' : 'inputs need'} attention.` : 'Every input is reporting.',
  ].filter(Boolean).join(' ');

  const stat = (v, l, c) => `<div class="stat"><div class="v"${c ? ` style="color:${c}"` : ''}>${v}</div><div class="l">${l}</div></div>`;
  const item = f => `<li><i style="background:${SEV[f.sev] || '#888'}"></i><span><b class="area">${esc(f.area)}</b> ${esc(f.title)}</span></li>`;
  const list = (arr, empty, n = 12) => arr.length ? `<ul class="items">${arr.slice(0, n).map(item).join('')}${arr.length > n ? `<li class="more">and ${arr.length - n} more</li>` : ''}</ul>` : `<p class="note">${empty}</p>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Argus Weekly · ${esc(hostName)} · week of ${esc(day(start))}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT@9..144,400..700,0..100&family=Source+Serif+4:ital,opsz,wght@0,8..60,400..700;1,8..60,400&display=swap">
<style>
  @page { size: letter; margin: 14mm; }
  :root { --paper: #f3eee3; --ink: #2a2521; --ink2: #5d544b; --muted: #8b8073; --rule: #ddd3c1; }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--paper); color: var(--ink); font: 15px/1.5 'Source Serif 4', Georgia, serif; }
  .sheet { max-width: 1000px; margin: 0 auto; padding: 28px 32px 40px; }
  .flag { text-align: center; border-bottom: 4px double var(--ink); padding-bottom: 10px; }
  .flag .kick { font: 600 13px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .14em; color: var(--muted); display: flex; justify-content: space-between; border-bottom: 1px solid var(--ink); padding-bottom: 6px; }
  .flag h1 { font: 500 64px/1 Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .02em; margin: 14px 0 4px; font-variation-settings: "opsz" 144; }
  .lede { font-size: 18px; text-align: center; max-width: 46rem; margin: 18px auto 6px; color: var(--ink2); }
  .lede b { color: var(--ink); }
  .stats { display: grid; grid-template-columns: repeat(6, 1fr); border-top: 2px solid var(--ink); border-bottom: 1px solid var(--rule); margin: 18px 0; }
  .stat { text-align: center; padding: 10px 4px; border-left: 1px solid var(--rule); } .stat:first-child { border-left: 0; }
  .stat .v { font: 500 34px/1 Fraunces, Georgia, serif; } .stat .l { font: 13px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .07em; color: var(--muted); margin-top: 4px; }
  .cols { display: grid; grid-template-columns: 1.45fr 1fr; gap: 28px; }
  .cols3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; margin-top: 18px; }
  h2 { font: 600 21px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .03em; border-bottom: 2px solid var(--ink); padding-bottom: 3px; margin: 18px 0 8px; }
  .items { list-style: none; margin: 0; padding: 0; } .items li { display: flex; gap: 8px; align-items: baseline; padding: 4px 0; border-bottom: 1px dotted var(--rule); font-size: 14px; }
  .items i { width: 8px; height: 8px; border-radius: 50%; flex: none; transform: translateY(-1px); }
  .items .area { font: 600 12.5px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .04em; color: var(--ink2); margin-right: 4px; }
  .items .more, .note { color: var(--muted); font-style: italic; font-size: 14px; }
  .resolved li span { text-decoration: line-through; color: var(--muted); }
  .chart { width: 100%; height: auto; } .chart text { font: 11px 'Source Serif 4', Georgia, serif; fill: var(--muted); }
  .key { display: flex; gap: 16px; font: 12.5px Fraunces, Georgia, serif; font-variant: small-caps; color: var(--muted); } .key span::before { content: ''; display: inline-block; width: 16px; height: 3px; background: var(--c); margin-right: 6px; vertical-align: middle; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 12px; word-break: break-all; }
  .foot { margin-top: 26px; border-top: 1px solid var(--rule); padding-top: 8px; text-align: center; font: 13px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .06em; color: var(--muted); }
  .print { position: fixed; right: 18px; bottom: 18px; font: 600 14px Fraunces, Georgia, serif; font-variant: small-caps; letter-spacing: .05em; background: var(--ink); color: var(--paper); border: 0; padding: 8px 14px; border-radius: 3px; cursor: pointer; }
  @media print { .print { display: none; } body { background: #fff; } .sheet { padding: 0; } }
  @media (max-width: 760px) { .cols, .cols3 { grid-template-columns: 1fr; } .stats { grid-template-columns: repeat(3, 1fr); } .flag h1 { font-size: 40px; } }
</style></head><body><div class="sheet">
<header class="flag">
  <div class="kick"><span>Vol. ${now.getFullYear()} · No. ${Math.ceil(((now - new Date(now.getFullYear(), 0, 1)) / D + 1) / 7)}</span><span>${esc(hostName)} · macOS ${esc(report.host.os)}</span><span>Week of ${esc(start.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' }))}</span></div>
  <h1>The Argus Weekly</h1>
</header>
<p class="lede">${lede}</p>
<div class="stats">
  ${stat(num(week.new.length), 'New this week')}${stat(num(week.resolved.length), 'Resolved')}${stat(num(report.counts.high || 0), 'High open', report.counts.high ? SEV.high : '')}${stat(num(report.counts.medium || 0), 'Medium open', report.counts.medium ? SEV.medium : '')}${stat(evWeek >= 1e5 ? Math.round(evWeek / 1e3) + 'k' : num(evWeek), 'Security events')}${stat(num(flagged), 'Indicators flagged', flagged ? SEV.high : '')}
</div>
<div class="cols">
  <section><h2>Still open, worst first</h2>${list(top, 'No high or medium findings are open.', 14)}</section>
  <section><h2>The month in findings</h2>${trendSvg(tr)}
    <h2>New this week</h2>${list(week.new, 'Nothing new.', 8)}</section>
</div>
<div class="cols3">
  <section><h2>Fixed or gone</h2>${week.resolved.length ? `<ul class="items resolved">${week.resolved.slice(0, 10).map(item).join('')}</ul>` : '<p class="note">Nothing resolved this week.</p>'}</section>
  <section><h2>Set-up problems</h2>${posture.length ? `<ul class="items">${posture.slice(0, 10).map(p => `<li><i style="background:${p.status === 'fail' ? SEV.high : SEV.medium}"></i><span><b class="area">${esc(p.control)}</b> ${esc(p.value)}</span></li>`).join('')}</ul>` : '<p class="note">Every setting checked looks right.</p>'}</section>
  <section><h2>New programs</h2>${newBins.length ? `<ul class="items">${newBins.slice(0, 10).map(b => `<li><i style="background:#8b8073"></i><span class="mono">${esc(b.path)}</span></li>`).join('')}${newBins.length > 10 ? `<li class="more">and ${newBins.length - 10} more</li>` : ''}</ul>` : '<p class="note">No third-party program ran for the first time.</p>'}</section>
</div>
${health.length ? `<h2>Argus itself</h2><ul class="items">${health.map(c => `<li><i style="background:${c.status === 'fail' ? SEV.high : SEV.medium}"></i><span>${esc(c.title)}${c.fix ? ` <span class="mono">${esc(c.fix)}</span>` : ''}</span></li>`).join('')}</ul>` : ''}
<div class="foot">Argus ${esc(report.version)} · compared with ${week.since ? esc(new Date(week.since).toLocaleString('en-US', { weekday: 'long', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })) : 'the first snapshot'} · ${report.findingState ? `${report.findingState.acked} acknowledged finding(s) left out · ` : ''}printed ${esc(now.toLocaleString('en-US'))}</div>
</div><button class="print" onclick="window.print()">Print or save as PDF</button></body></html>`;
}

function writeWeekly(report, ctx) {
  const html = weeklyHtml(report, ctx);
  const dir = path.join(cfg.data, 'reports');
  writeFileAtomic(path.join(dir, `weekly-${ymd(weekStart())}.html`), html);
  writeFileAtomic(path.join(dir, 'weekly-latest.html'), html);
  for (const n of fs.readdirSync(dir)) if (/^weekly-\d{8}\.html$/.test(n) && fs.statSync(path.join(dir, n)).mtimeMs < Date.now() - 26 * 7 * D) fs.unlinkSync(path.join(dir, n));
  log.info('weekly edition written');
  return html;
}

module.exports = { weeklyDue, weeklyHtml, writeWeekly };
