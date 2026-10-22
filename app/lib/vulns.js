'use strict';
// Vulnerability correlation for this Mac (dev instance addition):
//   * macOS / Safari version vs Apple's security-release index
//   * CISA KEV (known exploited vulnerabilities) vs macOS and installed apps
//   * Homebrew: `brew vulns` output from the collector, or an OSV.dev (GIT
//     ecosystem) lookup per formula when `brew vulns` is not available
// Inputs from the collector: snapshots/posture.txt (macOS version),
// snapshots/software-updates.txt, user/apps.json, user/brew-*.{txt,json}.
const fs = require('node:fs');
const path = require('node:path');
const { cfg, logger, fetchText, fetchJson, writeFileAtomic } = require('./util');

const log = logger('vulns');
const H = 3600e3, D = 86400e3;
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const APPLE_URL = 'https://support.apple.com/en-us/100100';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

const fmtDay = t => t ? new Date(t).toISOString().slice(0, 10) : '?';
const plural = (n, w, p) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? w : (p || w + 's')}`;
const vparts = v => String(v || '').split(/[^\d]+/).filter(Boolean).map(Number);
function vcmp(a, b) {
  const x = vparts(a), y = vparts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}
const decode = s => String(s).replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&rsquo;/g, "'").replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim();

// Apple's index: one <tr> per release: name (linked when it has CVEs), "available for", date.
function parseAppleReleases(html) {
  const out = [];
  for (const m of String(html).matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...m[1].matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi)].map(c => c[1]);
    if (cells.length < 3) continue;
    const name = decode(cells[0]); const date = Date.parse(decode(cells[cells.length - 1]));
    if (!name || isNaN(date)) continue;
    const link = (cells[0].match(/href="([^"]+)"/) || [])[1] || '';
    const os = name.match(/^macOS\s+(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+)?(\d+(?:\.\d+)*)\b/);
    const saf = name.match(/^Safari\s+(\d+(?:\.\d+)*)\b/);
    out.push({ name, date, link, product: os ? 'macOS' : saf ? 'Safari' : 'other', version: os ? os[1] : saf ? saf[1] : '', noCves: !link });
  }
  return out;
}

// Installed-app name → which KEV vendor/product rows apply to it.
const CHROMIUM = { vendor: /^google$/i, product: /chrom/i };
const APP_KEV = [
  [/^Google Chrome\b/i, [CHROMIUM]],
  [/^(Microsoft Edge|Brave Browser|Arc|Vivaldi|Opera|Chromium)\b/i, [CHROMIUM, { vendor: /^microsoft$/i, product: /edge/i }]],
  [/^Firefox\b/i, [{ vendor: /^mozilla$/i, product: /firefox/i }]],
  [/^Thunderbird\b/i, [{ vendor: /^mozilla$/i, product: /thunderbird/i }]],
  [/^Microsoft (Word|Excel|PowerPoint|Outlook|OneNote)\b/i, [{ vendor: /^microsoft$/i, product: /^office|^(word|excel|powerpoint|outlook)/i }]],
  [/^Microsoft Teams\b/i, [{ vendor: /^microsoft$/i, product: /teams/i }]],
  [/^Visual Studio Code\b/i, [{ vendor: /^microsoft$/i, product: /visual studio code/i }]],
  [/^zoom\.us$|^Zoom\b/i, [{ vendor: /^zoom/i, product: /./ }]],
  [/^Adobe Acrobat|^Acrobat Reader/i, [{ vendor: /^adobe$/i, product: /acrobat|reader/i }]],
  [/^Adobe (Photoshop|Illustrator|InDesign|Premiere)/i, [{ vendor: /^adobe$/i, product: /photoshop|illustrator|indesign|premiere|creative cloud/i }]],
  [/^VMware Fusion\b/i, [{ vendor: /^vmware$/i, product: /fusion/i }]],
  [/^Parallels Desktop\b/i, [{ vendor: /^parallels$/i, product: /desktop/i }]],
  [/^Docker\b/i, [{ vendor: /^docker$/i, product: /desktop|docker/i }]],
  [/^Citrix Workspace\b/i, [{ vendor: /^citrix$/i, product: /workspace/i }]],
  [/^Cisco (Secure Client|AnyConnect)/i, [{ vendor: /^cisco$/i, product: /anyconnect|secure client/i }]],
  [/^FortiClient\b/i, [{ vendor: /^fortinet$/i, product: /forticlient/i }]],
  [/^Java|^JDK|Oracle/i, [{ vendor: /^oracle$/i, product: /^java/i }]],
  [/^Telegram\b/i, [{ vendor: /^telegram$/i, product: /./ }]],
  [/^WhatsApp\b/i, [{ vendor: /^whatsapp|^meta$/i, product: /whatsapp/i }]],
  [/^Plex Media Server\b/i, [{ vendor: /^plex$/i, product: /media server/i }]],
  [/^WinRAR|^7-Zip|^Keka|^The Unarchiver/i, [{ vendor: /^(rarlab|7-zip)$/i, product: /./ }]],
  [/^TeamViewer\b/i, [{ vendor: /^teamviewer$/i, product: /./ }]],
  [/^AnyDesk\b/i, [{ vendor: /^anydesk$/i, product: /./ }]],
  [/^ScreenConnect|ConnectWise/i, [{ vendor: /^connectwise$/i, product: /screenconnect/i }]],
];
const APPLE_KEV_PRODUCT = /macOS|Multiple Products|WebKit|Safari|Kernel/i;

class Vulns {
  constructor(store) {
    this.store = store;
    this.dir = path.join(cfg.state, 'feeds');
    fs.mkdirSync(this.dir, { recursive: true });
    this.kev = null; this.apple = null; this.osv = null;
    this.meta = { kev: {}, apple: {}, osv: {} };
    this.loadCache();
  }
  file(n) { return path.join(this.dir, n); }
  loadCache() {
    try { this.meta = { ...this.meta, ...JSON.parse(fs.readFileSync(this.file('vulns-meta.json'), 'utf8')) }; } catch (e) { /* none yet */ }
    try { this.kev = JSON.parse(fs.readFileSync(this.file('kev.json'), 'utf8')); } catch (e) { /* none */ }
    try { this.apple = parseAppleReleases(fs.readFileSync(this.file('apple-security-releases.html'), 'utf8')); } catch (e) { /* none */ }
    try { this.osv = JSON.parse(fs.readFileSync(this.file('osv-brew.json'), 'utf8')); } catch (e) { /* none */ }
  }
  saveMeta() { writeFileAtomic(this.file('vulns-meta.json'), JSON.stringify(this.meta)); }

  inbox(rel, json = false) {
    try { const t = fs.readFileSync(path.join(cfg.inbox, rel), 'utf8'); return json ? JSON.parse(t) : t; } catch (e) { return null; }
  }

  async refresh(force = false) {
    const due = (k, ttl) => force || !this.meta[k].updated || Date.now() - this.meta[k].updated > ttl;
    const fail = (k, e) => { const c = e.cause ? ` (${e.cause.code || e.cause.message})` : ''; this.meta[k] = { ...this.meta[k], error: e.message + c, failed: Date.now() }; log.warn(`${k}: ${e.message}${c}`); };
    const backoff = k => this.meta[k].failed && Date.now() - this.meta[k].failed < 30 * 60e3 && !force;
    if (due('kev', 12 * H) && !backoff('kev')) {
      try {
        const r = await fetchText(KEV_URL, { timeout: 60000, maxBytes: 50e6 });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j = JSON.parse(r.text);
        if (!Array.isArray(j.vulnerabilities) || !j.vulnerabilities.length) throw new Error('KEV: no vulnerabilities array');
        writeFileAtomic(this.file('kev.json'), r.text); this.kev = j;
        this.meta.kev = { updated: Date.now(), count: j.vulnerabilities.length, catalog: j.catalogVersion, error: '' };
        log.info(`KEV: ${j.vulnerabilities.length} entries (catalog ${j.catalogVersion})`);
      } catch (e) { fail('kev', e); }
    }
    if (due('apple', 12 * H) && !backoff('apple')) {
      try {
        const r = await fetchText(APPLE_URL, { timeout: 60000, maxBytes: 20e6, headers: { 'Accept-Language': 'en-US' } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const rel = parseAppleReleases(r.text);
        if (rel.filter(x => x.product === 'macOS').length < 5) throw new Error('Apple security releases: page format not recognized');
        writeFileAtomic(this.file('apple-security-releases.html'), r.text); this.apple = rel;
        this.meta.apple = { updated: Date.now(), count: rel.length, error: '' };
        log.info(`Apple security releases: ${rel.length} rows`);
      } catch (e) { fail('apple', e); }
    }
    // OSV only when `brew vulns` is unavailable and Homebrew is present
    const brewInfo = this.inbox('user/brew-info.json', true);
    const haveBrewVulns = !!(this.inbox('user/brew-vulns.json') || /vulnerabilit|Scanning/i.test(this.inbox('user/brew-vulns.txt') || ''));
    if (brewInfo && !haveBrewVulns && (due('osv', 24 * H) || (this.osv && this.osv.inputHash !== hashBrew(brewInfo))) && !backoff('osv')) {
      try { await this.osvBrew(brewInfo); } catch (e) { fail('osv', e); }
    }
    this.saveMeta();
  }

  async osvBrew(info) {
    const pkgs = [];
    for (const f of info.formulae || []) {
      const ver = ((f.installed || [])[0] || {}).version || (f.versions || {}).stable;
      const urls = [(f.urls && f.urls.stable && f.urls.stable.url) || '', (f.urls && f.urls.head && f.urls.head.url) || '', f.homepage || ''];
      let repo = '';
      for (const u of urls) { const m = String(u).match(/^https?:\/\/(github\.com|gitlab\.com|codeberg\.org)\/([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?]|$)/i); if (m) { repo = `https://${m[1].toLowerCase()}/${m[2]}/${m[3]}`; break; } }
      if (!ver || !repo) continue;
      const v = String(ver).replace(/_\d+$/, '');   // drop Homebrew revision suffix
      pkgs.push({ name: f.name, version: v, repo });
    }
    const queries = [];
    for (const p of pkgs) for (const tag of [p.version, 'v' + p.version]) queries.push({ pkg: p, tag, q: { package: { name: p.repo, ecosystem: 'GIT' }, version: tag } });
    const hits = new Map();   // name -> Set(id)
    for (let i = 0; i < queries.length; i += 500) {
      const chunk = queries.slice(i, i + 500);
      const r = await fetchJson(OSV_BATCH, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: chunk.map(c => c.q) }), timeout: 90000 });
      if (!r.ok || !r.json || !Array.isArray(r.json.results)) throw new Error(`OSV querybatch HTTP ${r.status}`);
      r.json.results.forEach((res, j) => { for (const v of res.vulns || []) { const n = chunk[j].pkg.name; if (!hits.has(n)) hits.set(n, new Set()); hits.get(n).add(v.id); } });
    }
    const prev = (this.osv && this.osv.details) || {};
    const details = {};
    let fetched = 0;
    for (const id of new Set([...hits.values()].flatMap(s => [...s]))) {
      if (prev[id]) { details[id] = prev[id]; continue; }
      if (fetched >= 300) { details[id] = { id, summary: '', severity: '', aliases: [] }; continue; }
      const r = await fetchJson(OSV_VULN + encodeURIComponent(id), { timeout: 20000 }); fetched++;
      const j = r.json || {};
      const sev = ((j.database_specific || {}).severity || '') || ((j.affected || [])[0] && ((j.affected[0].ecosystem_specific || {}).severity || '')) || '';
      details[id] = { id, summary: String(j.summary || j.details || '').slice(0, 200), severity: String(sev).toUpperCase(), aliases: j.aliases || [], published: j.published || '' };
    }
    const results = [...hits.entries()].map(([name, ids]) => {
      const p = pkgs.find(x => x.name === name);
      return { name, version: p.version, repo: p.repo, vulns: [...ids].map(id => details[id] || { id }) };
    });
    this.osv = { updated: Date.now(), scanned: pkgs.length, skipped: (info.formulae || []).length - pkgs.length, results, details, inputHash: hashBrew(info) };
    writeFileAtomic(this.file('osv-brew.json'), JSON.stringify(this.osv));
    this.meta.osv = { updated: Date.now(), count: results.length, error: '' };
    log.info(`OSV: ${pkgs.length} formulae checked, ${results.length} with advisories`);
  }

  // ------------------------------------------------------------- analysis
  analyze(osVersion) {
    const findings = [];
    const add = f => findings.push({ detail: '', evidence: [], ...f, count: f.count !== undefined ? f.count : (f.evidence || []).length || 1 });
    const view = { os: osVersion || '', kev: this.meta.kev, apple: this.meta.apple, osv: this.meta.osv };
    const kev = (this.kev && this.kev.vulnerabilities) || [];
    const kevIds = new Map(kev.map(k => [k.cveID, k]));
    const recentDays = 365;

    // ---- macOS
    const apple = this.apple || [];
    if (osVersion && apple.length) {
      const major = vparts(osVersion)[0];
      const line = apple.filter(r => r.product === 'macOS' && vparts(r.version)[0] === major).sort((a, b) => vcmp(b.version, a.version));
      const latest = line[0];
      const newer = line.filter(r => vcmp(r.version, osVersion) > 0).sort((a, b) => a.date - b.date);
      view.macos = { installed: osVersion, latest: latest ? latest.version : '', latestDate: latest ? latest.date : null, behind: newer.map(r => ({ version: r.version, date: r.date, link: r.link, noCves: r.noCves })) };
      if (newer.length) {
        const since = newer[0].date - 3 * D;
        const exploited = kev.filter(k => /^apple$/i.test(k.vendorProject) && APPLE_KEV_PRODUCT.test(k.product) && Date.parse(k.dateAdded) >= since);
        view.macos.kev = exploited.map(k => ({ cve: k.cveID, name: k.vulnerabilityName, added: k.dateAdded, product: k.product }));
        add({ sev: exploited.length ? 'high' : 'medium', area: 'Vulnerabilities',
          title: exploited.length ? `macOS ${osVersion} is missing fixes for ${plural(exploited.length, 'actively exploited vulnerability', 'actively exploited vulnerabilities')}` : `macOS ${osVersion} is behind the latest security release (${latest.version})`,
          source: 'Apple security releases' + (exploited.length ? ' + CISA KEV' : ''),
          detail: `Apple has shipped ${plural(newer.length, 'newer security release')} for this macOS line since your version. ${exploited.length ? 'CISA lists Apple vulnerabilities as exploited in the wild since the first of them; ' : ''}Install the update (System Settings → General → Software Update).`,
          evidence: [...newer.map(r => `${r.name || 'macOS ' + r.version} — released ${fmtDay(r.date)}${r.noCves ? ' (no published CVEs)' : ''}${r.link ? ' ' + r.link : ''}`), ...exploited.map(k => `KEV ${k.cveID} (${k.product}, added ${k.dateAdded}): ${k.vulnerabilityName}`)] });
      } else if (latest) {
        view.macos.current = true;
      } else {
        add({ sev: 'info', area: 'Vulnerabilities', title: `macOS ${osVersion}: not yet in Apple's security-release index`, source: 'Apple security releases', detail: 'Usually a beta or a release from the last few days.', evidence: [] });
      }
    } else if (osVersion && !apple.length) {
      view.macos = { installed: osVersion, pending: true };
    }

    // ---- pending updates (softwareupdate --list)
    const su = this.inbox('snapshots/software-updates.txt');
    if (su) {
      const pend = [...su.matchAll(/^\s*\*\s*Label:\s*(.+)\n\s*Title:\s*([^,\n]+),\s*Version:\s*([^,\n]+)(.*)$/gm)].map(m => ({ label: m[1].trim(), title: m[2].trim(), version: m[3].trim(), recommended: /Recommended:\s*YES/i.test(m[4]), restart: /Action:\s*restart/i.test(m[4]) }));
      view.pendingUpdates = pend;
      if (pend.length) {
        const sec = pend.filter(p => /security|macOS|Safari|XProtect|Background Security|Rapid Security/i.test(p.title + ' ' + p.label));
        add({ sev: sec.length ? 'medium' : 'low', area: 'Vulnerabilities', title: `${plural(pend.length, 'software update')} waiting to be installed`, source: 'softwareupdate --list',
          detail: 'Downloaded or available Apple updates that are not installed yet.', evidence: pend.map(p => `${p.title} ${p.version}${p.recommended ? ' (recommended)' : ''}${p.restart ? ' — needs restart' : ''}`) });
      }
    }

    // ---- apps vs KEV
    const appsJson = this.inbox('user/apps.json', true);
    const apps = ((appsJson && appsJson.SPApplicationsDataType) || []).filter(a => a.obtained_from !== 'apple' && !/^\/System\//.test(a.path || ''));
    view.apps = { total: apps.length, scanned: !!appsJson };
    // Safari (ships with macOS but is versioned separately)
    const safari = ((appsJson && appsJson.SPApplicationsDataType) || []).find(a => a._name === 'Safari' && /^\/Applications\/Safari\.app/.test(a.path || ''));
    if (safari && apple.length) {
      const maj = vparts(safari.version)[0];
      const sl = apple.filter(r => r.product === 'Safari' && vparts(r.version)[0] === maj).sort((a, b) => vcmp(b.version, a.version));
      if (sl.length && vcmp(sl[0].version, safari.version) > 0) {
        view.safari = { installed: safari.version, latest: sl[0].version };
        add({ sev: 'medium', area: 'Vulnerabilities', title: `Safari ${safari.version} is behind ${sl[0].version}`, source: 'Apple security releases', detail: 'Safari and WebKit fixes ship often; WebKit bugs are a common exploit target.', evidence: sl.filter(r => vcmp(r.version, safari.version) > 0).map(r => `${r.name} — ${fmtDay(r.date)}`) });
      }
    }
    const appHits = [];
    if (kev.length) {
      for (const a of apps) {
        const rule = APP_KEV.find(([rx]) => rx.test(a._name || ''));
        if (!rule) continue;
        const rows = kev.filter(k => rule[1].some(r => r.vendor.test(k.vendorProject || '') && r.product.test(k.product || '')));
        if (!rows.length) continue;
        const mod = Date.parse(a.lastModified || '') || null;
        const after = mod ? rows.filter(k => Date.parse(k.dateAdded) > mod) : [];
        const recent = rows.filter(k => Date.now() - Date.parse(k.dateAdded) < recentDays * D);
        appHits.push({ app: a._name, version: a.version || '', path: a.path || '', modified: mod, total: rows.length, recent: recent.length,
          after: after.map(k => ({ cve: k.cveID, added: k.dateAdded, name: k.vulnerabilityName, ransomware: k.knownRansomwareCampaignUse === 'Known' })) });
      }
    }
    view.apps.kev = appHits;
    const stale = appHits.filter(h => h.after.length);
    if (stale.length) add({ sev: stale.some(h => h.after.some(k => Date.now() - Date.parse(k.added) < 90 * D)) ? 'high' : 'medium', area: 'Vulnerabilities',
      title: `${plural(stale.length, 'app')} not updated since known-exploited vulnerabilities were announced`, source: 'CISA KEV + app inventory',
      detail: 'CISA added exploited-in-the-wild vulnerabilities for these products after the app bundle was last modified on disk, so this copy probably predates the fix. Update the app (or confirm its version is past the fixed release).',
      evidence: stale.flatMap(h => [`${h.app} ${h.version} (last updated ${fmtDay(h.modified)}) — ${h.path}`, ...h.after.slice(0, 8).map(k => `    ${k.cve} added ${k.added}${k.ransomware ? ' [ransomware use]' : ''}: ${k.name}`)]) });
    const watch = appHits.filter(h => !h.after.length && h.recent);
    if (watch.length) add({ sev: 'info', area: 'Vulnerabilities', title: `${plural(watch.length, 'installed app')} with known-exploited vulnerabilities in the last year (updated since)`, source: 'CISA KEV + app inventory',
      detail: 'These products are actively targeted; your copies were updated after the latest KEV entry. Keep auto-update on.', evidence: watch.map(h => `${h.app} ${h.version}: ${h.recent} KEV entries in ${recentDays} days`) });

    // ---- Homebrew
    const brew = this.brewFindings(kevIds);
    view.brew = brew.view;
    for (const f of brew.findings) add(f);
    return { findings, view };
  }

  brewFindings(kevIds) {
    const out = { findings: [], view: { source: '', packages: [] } };
    let pkgs = null;
    const j = this.inbox('user/brew-vulns.json', true);
    const t = this.inbox('user/brew-vulns.txt');
    if (j) { pkgs = parseBrewVulnsJson(j); out.view.source = 'brew vulns --json'; }
    else if (t && /vulnerabilit|Scanning/i.test(t) && !/not available/i.test(t)) { pkgs = parseBrewVulnsText(t); out.view.source = 'brew vulns'; }
    else if (this.osv && this.osv.results) {
      pkgs = this.osv.results.map(r => ({ name: r.name, version: r.version, vulns: r.vulns.map(v => ({ id: v.id, severity: v.severity || '', summary: v.summary || '', aliases: v.aliases || [] })) }));
      out.view.source = `OSV.dev (GIT ecosystem, ${this.osv.scanned} formulae with a GitHub/GitLab/Codeberg source; ${this.osv.skipped} skipped)`;
    }
    if (!pkgs) { out.view.source = this.inbox('user/brew-info.json') ? 'waiting for OSV lookup' : 'no Homebrew inventory yet'; return out; }
    for (const p of pkgs) for (const v of p.vulns) { const ids = [v.id, ...(v.aliases || [])]; const k = ids.map(i => kevIds.get(i)).find(Boolean); if (k) v.kev = k.dateAdded; }
    out.view.packages = pkgs;
    const isHigh = v => v.kev || /CRITICAL|HIGH/i.test(v.severity || '');
    const hi = pkgs.filter(p => p.vulns.some(isHigh)), rest = pkgs.filter(p => !p.vulns.some(isHigh) && p.vulns.length);
    const line = p => `${p.name} ${p.version}: ${p.vulns.slice(0, 6).map(v => `${v.id}${v.severity ? ' [' + v.severity + ']' : ''}${v.kev ? ' [KEV ' + v.kev + ']' : ''}`).join(', ')}${p.vulns.length > 6 ? ` +${p.vulns.length - 6} more` : ''}`;
    if (hi.length) out.findings.push({ sev: hi.some(p => p.vulns.some(v => v.kev)) ? 'high' : 'medium', area: 'Vulnerabilities', title: `${plural(hi.length, 'Homebrew package')} with high/critical or exploited vulnerabilities`, source: out.view.source,
      detail: 'Run `brew upgrade <name>`. Many CLI tools only matter if they process untrusted input or listen on the network — services (brew services list) matter most.', evidence: hi.map(line) });
    if (rest.length) out.findings.push({ sev: 'low', area: 'Vulnerabilities', title: `${plural(rest.length, 'Homebrew package')} with other published vulnerabilities`, source: out.view.source, evidence: rest.map(line) });
    return out;
  }

  status() {
    return { kev: this.meta.kev, apple: this.meta.apple, osv: this.meta.osv };
  }
}

function hashBrew(info) { return (info.formulae || []).map(f => f.name + '@' + (((f.installed || [])[0] || {}).version || '')).join(',').length + ':' + (info.formulae || []).length; }

function parseBrewVulnsText(text) {
  const pkgs = []; let cur = null;
  for (const line of String(text).split('\n')) {
    let m;
    if ((m = line.match(/^(\S+)\s+\(([^)]+)\)\s+-\s+\d+\s+vulnerabilit/i))) { cur = { name: m[1], version: m[2], vulns: [] }; pkgs.push(cur); continue; }
    if (cur && (m = line.match(/^\s+\[(\w+)\]\s+(\S+)\s+-\s+(.*)$/))) cur.vulns.push({ id: m[2], severity: m[1].toUpperCase(), summary: m[3].trim().slice(0, 200) });
    else if (cur && (m = line.match(/^\s+(CVE-\d{4}-\d+|GHSA-[\w-]+)\b\s*-?\s*(.*)$/))) cur.vulns.push({ id: m[1], severity: '', summary: m[2].trim().slice(0, 200) });
  }
  return pkgs;
}
// Tolerant reader: the JSON shape of `brew vulns --json` is not documented yet.
function parseBrewVulnsJson(j) {
  const pkgs = [];
  const visit = (x, depth = 0) => {
    if (!x || typeof x !== 'object' || depth > 6) return;
    if (Array.isArray(x)) { x.forEach(y => visit(y, depth + 1)); return; }
    const vl = x.vulnerabilities || x.vulns || x.advisories;
    if ((x.name || x.formula || x.package) && Array.isArray(vl)) {
      pkgs.push({ name: x.name || x.formula || (x.package && x.package.name) || x.package, version: x.version || x.installed_version || '',
        vulns: vl.map(v => ({ id: v.id || v.cve || v.ID || '?', severity: String(v.severity || (v.database_specific || {}).severity || '').toUpperCase(), summary: String(v.summary || v.title || '').slice(0, 200), aliases: v.aliases || [] })) });
      return;
    }
    Object.values(x).forEach(y => visit(y, depth + 1));
  };
  visit(j);
  return pkgs.filter(p => p.vulns.length);
}

module.exports = { Vulns, parseAppleReleases, parseBrewVulnsText, parseBrewVulnsJson, vcmp };
