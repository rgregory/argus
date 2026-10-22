'use strict';
// Attribution and hygiene:
//   * which program reached a flagged domain    Little Snitch hostnames ↔ indicators
//   * Wi-Fi networks, DNS resolvers, VPN state  snapshots/network.txt (every 5 min)
//   * USB and Bluetooth devices                 snapshots/devices.json (hourly)
//   * container image vulnerabilities           user/images/*.json (grype or trivy, daily)
const fs = require('node:fs');
const path = require('node:path');
const engine = require('./engine');
const { cfg } = require('./util');

const D = 86400e3, KEEP = 7 * D;
const plural = (n, w, p) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? w : (p || w + 's')}`;
const fmt = ms => engine.fmtTs(new Date(ms));
const list = s => String(s || '').split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
function changeLog(store, key, fresh, keep = KEEP) {
  const all = [...(store.kvGet(key, []) || []).filter(c => Date.now() - c.at < keep), ...fresh].slice(-500);
  store.kvSet(key, all);
  return all;
}

// ------------------------------------------------------ DNS → program
function analyzeDnsAttribution(hs, add) {
  let have; try { have = hs.store.get("SELECT 1 FROM ls_flows LIMIT 1"); } catch (e) { return { available: false, why: 'needs Little Snitch' }; }
  if (!have) return { available: false, why: 'needs Little Snitch' };
  const flagged = hs.store.all("SELECT value, risk, risk_score, reasons, sources FROM observables WHERE type = 'domain' AND risk_score >= 40 ORDER BY risk_score DESC LIMIT 300")
    .filter(d => !(hs.intel && hs.intel.allowedBy(d.value, 'domain')));
  const since = Date.now() - KEEP;
  const rows = [];
  for (const d of flagged) {
    const progs = hs.store.all(`SELECT path, MAX(parent) AS parent, SUM(connects) AS c, SUM(denies) AS dn, SUM(bytes_out) AS bo, MAX(last_seen) AS last, GROUP_CONCAT(DISTINCT host) AS hosts
      FROM ls_flows WHERE last_seen > ? AND (host = ? OR host LIKE ?) GROUP BY path ORDER BY last DESC LIMIT 10`, since, d.value, '%.' + d.value);
    rows.push({ domain: d.value, risk: d.risk, score: d.risk_score, why: (JSON.parse(d.reasons || '[]')[0] || ''), queried: /"dns/.test(d.sources),
      programs: progs.map(p => ({ path: p.path, parent: p.parent || '', connects: p.c, denies: p.dn, bytesOut: p.bo, last: p.last, hosts: String(p.hosts || '').split(',').slice(0, 4) })) });
  }
  const hit = rows.filter(r => r.programs.length);
  if (hit.length) add({ sev: hit.some(r => r.risk === 'malicious' && r.programs.some(p => p.connects > 0)) ? 'high' : 'medium', area: 'Network', title: `${plural(hit.length, 'flagged domain')} traced to the program that used it`, source: 'Pi-hole / threat intel + Little Snitch',
    detail: 'Each flagged domain with the program on this Mac that connected to it (last 7 days). "denied" means Little Snitch blocked it. Other devices on your network show in Pi-hole but not here.',
    evidence: hit.flatMap(r => [`${r.domain} [${r.risk}] ${r.why}`, ...r.programs.map(p => `    ${p.path}${p.parent ? ' (' + p.parent.split('/').pop() + ')' : ''} — ${p.connects} connections${p.denies ? `, ${p.denies} denied` : ''}, last ${fmt(p.last)}`)]) });
  return { available: true, flagged: rows.length, traced: hit.length, rows };
}

// -------------------------------------------- Wi-Fi, DNS resolvers, VPN
function parseNetwork(text) {
  const sec = {}; let cur = '';
  for (const line of String(text || '').split('\n')) {
    const h = line.match(/^== (\S+)/); if (h) { cur = h[1]; sec[cur] = []; continue; }
    if (cur && line.trim()) sec[cur].push(line.trim());
  }
  const kv = Object.fromEntries((sec.wifi || []).map(l => { const m = l.match(/^(.+?)\s*:\s*(.*)$/); return m ? [m[1].trim(), m[2].trim()] : [l, '']; }));
  const route = Object.fromEntries((sec.route || []).map(l => l.split(/:\s*|\s+/).filter(Boolean)).map(([k, v]) => [k, v || '']));
  const vpn = sec.vpn || [];
  const mull = vpn.find(l => /^mullvad:/i.test(l));
  const iface = route.interface || '';
  let vpnState = 'off', vpnDetail = '';
  if (mull) { vpnState = /connected/i.test(mull) && !/disconnected/i.test(mull) ? 'on' : 'off'; vpnDetail = mull.replace(/^mullvad:\s*/i, 'Mullvad: '); }
  else if (vpn.some(l => /\(Connected\)/.test(l))) { vpnState = 'on'; vpnDetail = vpn.find(l => /\(Connected\)/.test(l)); }
  else if (/^(utun|ipsec|ppp|wg)/.test(iface)) { vpnState = 'on'; vpnDetail = `default route via ${iface}`; }
  const ssid = kv.SSID && !/^(None|<redacted>|)$/i.test(kv.SSID) ? kv.SSID : '';
  return { ssid, bssid: kv.BSSID || '', security: kv.Security || '', power: kv.Power || '', dns: (sec.dns || []).filter(x => /^[0-9a-f.:]+$/i.test(x)), iface, gateway: route.gateway || '', vpn: vpnState, vpnDetail };
}

function analyzeNetwork(hs, add) {
  const cur = hs.read('snapshots/network.txt', parseNetwork);
  if (!cur) return { available: false, posture: [] };
  const ver = hs.mtimes.get('snapshots/network.txt');
  const st = hs.store.kvGet('net.state', { networks: {}, last: null, ver: null, since: Date.now() });
  const fresh = [];
  if (st.ver !== ver) {
    const now = Date.now();
    if (cur.ssid) {
      const k = cur.ssid;
      const n = st.networks[k] || { ssid: cur.ssid, security: cur.security, first: now, last: now, joins: 0, bssids: [] };
      if (!st.last || st.last.ssid !== cur.ssid) { n.joins++; fresh.push({ at: now, kind: 'joined', detail: `${cur.ssid} (${cur.security || 'security unknown'})`, open: isOpen(cur.security), isNew: !st.networks[k] && now - st.since > D }); }
      n.last = now; n.security = cur.security || n.security;
      if (cur.bssid && !n.bssids.includes(cur.bssid)) n.bssids = [...n.bssids, cur.bssid].slice(-10);
      st.networks[k] = n;
    }
    const dnsKey = cur.dns.join(' ');
    if (st.last && st.last.dns !== dnsKey) fresh.push({ at: now, kind: 'dns', detail: `DNS ${st.last.dns || 'none'} → ${dnsKey || 'none'}` });
    if (st.last && st.last.vpn !== cur.vpn) fresh.push({ at: now, kind: 'vpn', detail: `VPN ${cur.vpn === 'on' ? 'connected' : 'disconnected'}${cur.vpnDetail ? ' — ' + cur.vpnDetail : ''}` });
    st.last = { ssid: cur.ssid, dns: dnsKey, vpn: cur.vpn };
    st.ver = ver;
    const names = Object.keys(st.networks);
    if (names.length > 200) for (const k of names.sort((a, b) => st.networks[a].last - st.networks[b].last).slice(0, names.length - 200)) delete st.networks[k];
    hs.store.kvSet('net.state', st);
  }
  const events = changeLog(hs.store, 'net.events', fresh);
  const expDns = list(process.env.ARGUS_EXPECTED_DNS);
  const expVpn = /^(1|true|yes|on)$/i.test(process.env.ARGUS_EXPECT_VPN || '');
  const dnsOk = !expDns.length || (cur.dns.length && cur.dns.every(d => expDns.includes(d)));
  const posture = [];
  if (cur.ssid) posture.push({ control: 'Wi-Fi security', status: isOpen(cur.security) ? 'fail' : /WEP|WPA\b(?!2|3)|WPA Personal$/i.test(cur.security) ? 'warn' : 'pass', value: `${cur.ssid} · ${cur.security || 'unknown'}`, why: 'On an open network anyone nearby can see unencrypted traffic and spoof the router.', warnTitle: `Wi-Fi "${cur.ssid}" uses weak security (${cur.security})`, failTitle: `Connected to open Wi-Fi "${cur.ssid}"` });
  posture.push({ control: 'DNS resolvers', status: expDns.length ? (dnsOk ? 'pass' : 'fail') : 'info', value: cur.dns.join(', ') || 'none', why: expDns.length ? `Expected: ${expDns.join(', ')} (ARGUS_EXPECTED_DNS).` : 'Set ARGUS_EXPECTED_DNS to your Pi-hole or VPN resolver to get an alert when DNS goes elsewhere.', failTitle: `DNS is not going through ${expDns.join(' / ')}` });
  posture.push({ control: 'VPN', status: expVpn ? (cur.vpn === 'on' ? 'pass' : 'fail') : 'info', value: cur.vpn === 'on' ? (cur.vpnDetail || 'connected') : `off${cur.vpnDetail ? ' — ' + cur.vpnDetail : ''}`, why: expVpn ? 'ARGUS_EXPECT_VPN=1: the VPN should always be up.' : 'Set ARGUS_EXPECT_VPN=1 to get an alert when the VPN is down.', failTitle: 'VPN is not connected' });

  for (const p of posture) if (p.status === 'fail' || p.status === 'warn') add({ sev: p.status === 'fail' ? 'medium' : 'low', area: 'Network', title: p.status === 'fail' ? p.failTitle : p.warnTitle, source: 'network snapshot', detail: p.why, evidence: [p.value] });
  const open = events.filter(e => e.kind === 'joined' && e.open);
  if (open.length) add({ sev: 'medium', area: 'Network', title: `Joined ${plural(new Set(open.map(e => e.detail)).size, 'open Wi-Fi network')} (last 7 days)`, source: 'wdutil', detail: 'No Wi-Fi encryption. Anything not going through HTTPS or your VPN was visible to others on that network.', evidence: open.map(e => `${fmt(e.at)}  ${e.detail}`) });
  const nw = events.filter(e => e.kind === 'joined' && e.isNew && !e.open);
  if (nw.length) add({ sev: 'low', area: 'Network', title: `${plural(nw.length, 'new Wi-Fi network')} joined (last 7 days)`, source: 'wdutil', evidence: nw.map(e => `${fmt(e.at)}  ${e.detail}`) });
  if (expDns.length) {
    const off = events.filter(e => e.kind === 'dns' && !e.detail.split('→')[1].trim().split(' ').every(d => expDns.includes(d)));
    if (off.length) add({ sev: 'medium', area: 'Network', title: `DNS left ${expDns.join(' / ')} ${plural(off.length, 'time')} (last 7 days)`, source: 'scutil --dns', detail: 'While DNS goes elsewhere, Pi-hole blocking and logging (and the DNS findings here) miss those lookups.', evidence: off.map(e => `${fmt(e.at)}  ${e.detail}`) });
  }
  if (expVpn) {
    const down = events.filter(e => e.kind === 'vpn' && /disconnected/.test(e.detail));
    if (down.length) add({ sev: 'low', area: 'Network', title: `VPN dropped ${plural(down.length, 'time')} (last 7 days)`, source: 'scutil / mullvad', evidence: down.map(e => `${fmt(e.at)}  ${e.detail}`) });
  }
  return { available: true, current: cur, networks: Object.values(st.networks).sort((a, b) => b.last - a.last).slice(0, 100), events: events.slice().reverse().slice(0, 300), posture };
}
const isOpen = s => { s = String(s || '').trim(); return /^(none|open)$/i.test(s) || /\bopen\b/i.test(s); };

// ------------------------------------------------- USB / Bluetooth
function parseDevices(text) {
  let j; try { j = JSON.parse(text); } catch (e) { return null; }
  const usb = [], bt = [];
  const walkUsb = (x, depth = 0) => {
    if (!x || typeof x !== 'object' || depth > 12) return;
    if (Array.isArray(x)) { x.forEach(y => walkUsb(y, depth + 1)); return; }
    const vid = x.vendor_id || x.USBDeviceKeyVendorID || x['USB Vendor ID'];
    const pid = x.product_id || x.USBDeviceKeyProductID || x['USB Product ID'];
    if (x._name && (vid || pid)) usb.push({ name: x._name, vendor: x.manufacturer || x.USBDeviceKeyVendorName || '', vid: String(vid || ''), pid: String(pid || ''), serial: x.serial_num || x.USBDeviceKeySerialNumber || '',
      storage: !!(x.Media || x.bsd_name || /mass storage|disk|drive|flash/i.test(x._name)) });
    for (const v of Object.values(x)) if (v && typeof v === 'object') walkUsb(v, depth + 1);
  };
  walkUsb([...(j.SPUSBHostDataType || []), ...(j.SPUSBDataType || [])]);
  for (const b of j.SPBluetoothDataType || []) {
    for (const [group, connected] of [['device_connected', true], ['device_not_connected', false], ['devices_list', null]]) {
      for (const entry of b[group] || []) for (const [name, info] of Object.entries(entry || {})) {
        bt.push({ name, address: (info && (info.device_address || info.device_addr)) || '', type: (info && (info.device_minorType || info.device_majorType)) || '', connected: connected === null ? /yes|connected/i.test((info && info.device_connected) || '') : connected });
      }
    }
  }
  const uniq = (arr, k) => { const m = new Map(); arr.forEach(a => m.set(k(a), a)); return [...m.values()]; };
  return { usb: uniq(usb, d => [d.vid, d.pid, d.serial, d.name].join('|')), bt: uniq(bt, d => d.address || d.name) };
}
function analyzeDevices(hs, add) {
  const cur = hs.read('snapshots/devices.json', parseDevices);
  if (!cur) return { available: false };
  const ver = hs.mtimes.get('snapshots/devices.json');
  const uk = d => [d.vid, d.pid, d.serial, d.name].join('|'), bk = d => d.address || d.name;
  const prev = hs.store.kvGet('devices.baseline', null);
  const fresh = [];
  if (prev && prev.ver !== ver) {
    for (const d of cur.usb) if (!prev.usb.includes(uk(d))) fresh.push({ at: Date.now(), kind: 'USB', name: d.name, detail: `${d.vendor || ''} ${d.vid}:${d.pid}${d.serial ? ' serial ' + d.serial : ''}`.trim(), storage: d.storage });
    for (const d of cur.bt) if (!prev.bt.includes(bk(d))) fresh.push({ at: Date.now(), kind: 'Bluetooth', name: d.name, detail: `${d.type || 'device'} ${d.address}`.trim() });
  }
  if (!prev || prev.ver !== ver) hs.store.kvSet('devices.baseline', { usb: [...new Set([...(prev ? prev.usb : []), ...cur.usb.map(uk)])].slice(-2000), bt: [...new Set([...(prev ? prev.bt : []), ...cur.bt.map(bk)])].slice(-2000), ver, at: prev ? prev.at : Date.now() });
  const changes = changeLog(hs.store, 'devices.changes', fresh);
  const usbNew = changes.filter(c => c.kind === 'USB'), btNew = changes.filter(c => c.kind === 'Bluetooth');
  if (usbNew.length) add({ sev: usbNew.some(c => c.storage) ? 'medium' : 'low', area: 'Devices', title: `${plural(usbNew.length, 'new USB device')} connected (last 7 days)`, source: 'system_profiler (hourly)',
    detail: 'First time these were seen attached. Storage devices are rated higher: they are the usual way data walks out or malware walks in. Devices plugged in briefly between hourly snapshots are missed.', evidence: usbNew.map(c => `${fmt(c.at)}  ${c.name} — ${c.detail}${c.storage ? ' [storage]' : ''}`) });
  if (btNew.length) add({ sev: 'low', area: 'Devices', title: `${plural(btNew.length, 'new Bluetooth device')} seen (last 7 days)`, source: 'system_profiler (hourly)', detail: 'Newly paired or connected. A keyboard you did not pair yourself is worth a look.', evidence: btNew.map(c => `${fmt(c.at)}  ${c.name} — ${c.detail}`) });
  return { available: true, usb: cur.usb, bt: cur.bt, changes: changes.slice().reverse(), baselineAt: prev ? prev.at : Date.now() };
}

// ------------------------------------------- container image scans
let kevCache = { mtime: 0, ids: new Map() };
function kevIds() {
  const f = path.join(cfg.state, 'feeds', 'kev.json');
  try { const m = fs.statSync(f).mtimeMs; if (m !== kevCache.mtime) { const j = JSON.parse(fs.readFileSync(f, 'utf8')); kevCache = { mtime: m, ids: new Map((j.vulnerabilities || []).map(v => [v.cveID, v.dateAdded])) }; } } catch (e) { /* no KEV yet */ }
  return kevCache.ids;
}
function parseScan(j) {
  const vulns = [];
  if (j.tool === 'grype' && j.report) for (const m of j.report.matches || []) {
    const v = m.vulnerability || {}, a = m.artifact || {};
    vulns.push({ id: v.id, severity: String(v.severity || '').toUpperCase(), pkg: a.name, version: a.version, type: a.type, fix: ((v.fix || {}).versions || []).join(', '), aliases: (m.relatedVulnerabilities || []).map(r => r.id) });
  } else if (j.tool === 'trivy' && j.report) for (const r of j.report.Results || []) for (const v of r.Vulnerabilities || []) {
    vulns.push({ id: v.VulnerabilityID, severity: String(v.Severity || '').toUpperCase(), pkg: v.PkgName, version: v.InstalledVersion, type: r.Type, fix: v.FixedVersion || '', aliases: [] });
  }
  return vulns;
}
function analyzeImages(hs, add) {
  const dir = path.join(cfg.inbox, 'user', 'images');
  let files; try { files = fs.readdirSync(dir).filter(n => n.endsWith('.json')); } catch (e) { return { available: false }; }
  if (!files.length) return { available: false };
  const kev = kevIds();
  const images = [];
  for (const n of files) {
    const j = hs.read(path.join('user', 'images', n), t => JSON.parse(t));
    if (!j) continue;
    if (j.error || !j.report) { images.push({ image: j.image, tool: j.tool, scanned: (j.scanned || 0) * 1000, error: j.error || 'scan produced no report', counts: {}, top: [] }); continue; }
    const vs = parseScan(j);
    for (const v of vs) { const k = [v.id, ...v.aliases].find(i => kev.has(i)); if (k) v.kev = kev.get(k); }
    const counts = {}; vs.forEach(v => { counts[v.severity] = (counts[v.severity] || 0) + 1; });
    const rank = v => (v.kev ? 0 : 10) + ({ CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 }[v.severity] || 5) + (v.fix ? 0 : 0.5);
    images.push({ image: j.image, tool: j.tool, scanned: (j.scanned || 0) * 1000, counts, fixable: vs.filter(v => v.fix && /CRITICAL|HIGH/.test(v.severity)).length, kev: vs.filter(v => v.kev).length,
      top: vs.sort((a, b) => rank(a) - rank(b)).slice(0, 40) });
  }
  const bad = images.filter(i => i.kev || i.counts.CRITICAL || i.fixable);
  if (bad.length) add({ sev: bad.some(i => i.kev) ? 'high' : 'medium', area: 'Vulnerabilities', title: `${plural(bad.length, 'container image')} with critical or exploited vulnerabilities`, source: `${images[0].tool} image scan`,
    detail: 'Packages inside the images your running containers use. Pull a newer image tag (or rebuild) and restart the container; "fixable" means a patched package version exists.',
    evidence: bad.flatMap(i => [`${i.image}: ${i.counts.CRITICAL || 0} critical, ${i.counts.HIGH || 0} high (${i.fixable} fixable)${i.kev ? `, ${i.kev} in CISA KEV` : ''}`,
      ...i.top.filter(v => v.kev || v.severity === 'CRITICAL').slice(0, 6).map(v => `    ${v.id} [${v.severity}${v.kev ? ', KEV' : ''}] ${v.pkg} ${v.version}${v.fix ? ' → ' + v.fix : ''}`)]) });
  const failed = images.filter(i => i.error);
  if (failed.length) add({ sev: 'info', area: 'Vulnerabilities', title: `${plural(failed.length, 'container image')} could not be scanned`, source: 'image scan', evidence: failed.map(i => `${i.image}: ${i.error}`) });
  return { available: true, tool: images[0] && images[0].tool, images: images.sort((a, b) => (b.kev - a.kev) || ((b.counts.CRITICAL || 0) - (a.counts.CRITICAL || 0))) };
}

module.exports = { analyzeDnsAttribution, analyzeNetwork, analyzeDevices, analyzeImages, parseNetwork, parseDevices, parseScan };
