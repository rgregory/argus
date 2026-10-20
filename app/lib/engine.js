/* Argus — macOS log analysis engine.
 * Pure JS, no DOM, no dependencies. Used by the container service (Node) and
 * can also run in a browser (exposes globalThis.ArgusEngine).
 *
 * Feed it files with ingest(), then call finalize() for findings + views.
 * finalize() never mutates the accumulated state, so ingest/finalize can be
 * interleaved for incremental analysis.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ArgusEngine = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ------------------------------------------------------------------ utils
  const HOUR = 3600e3, DAY = 86400e3;
  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  const MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const tick = () => new Promise(r => setTimeout(r, 0));
  const trunc = (s, n = 400) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  const basename = p => String(p || '').replace(/\/+$/, '').split('/').pop() || '';
  const inc = (map, k, n = 1) => map.set(k, (map.get(k) || 0) + n);
  const topN = (map, n = 20) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([key, count]) => ({ key, count }));
  const pad = n => String(n).padStart(2, '0');
  const fmtTs = d => d ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` : '—';
  const tsOf = x => (x && x.ts ? x.ts.getTime() : 0);
  const byTs = (a, b) => tsOf(a) - tsOf(b);
  const plural = (n, w, p) => `${Number(n).toLocaleString('en-US')} ${n === 1 ? w : (p || w + 's')}`;
  const norm = s => String(s).replace(/0x[0-9a-f]+/gi, '#').replace(/[0-9a-f]{8}-[0-9a-f-]{27}/gi, '#').replace(/\d+/g, '#');
  const pushCap = (arr, item, cap) => { arr.push(item); if (arr.length > cap) arr.splice(0, arr.length - cap); };

  function parseTs(s) {
    if (!s) return null;
    const m = String(s).trim().match(/^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.(\d+))?\s*(?:([+-])(\d\d):?(\d\d)?)?/);
    if (!m) return null;
    const ms = (m[3] || '0').padEnd(3, '0').slice(0, 3);
    const tz = m[4] ? `${m[4]}${m[5]}:${m[6] || '00'}` : '';
    const d = new Date(`${m[1]}T${m[2]}.${ms}${tz}`);
    return isNaN(d) ? null : d;
  }
  function parseSyslogTs(s, ref) {
    const m = String(s).match(/^(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)/);
    if (!m || !(m[1] in MON)) return null;
    const d = new Date(ref.getFullYear(), MON[m[1]], +m[2], +m[3], +m[4], +m[5]);
    if (d - ref > 2 * DAY) d.setFullYear(d.getFullYear() - 1);
    return d;
  }
  function parseUsDate(date, time) {
    const m = String(date).match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
    if (!m) return null;
    const t = String(time || '0:0:0').split(':').map(Number);
    return new Date(+m[3], +m[1] - 1, +m[2], t[0] || 0, t[1] || 0, t[2] || 0);
  }
  function splitHostPort(s) {
    s = String(s).replace(/[,;]$/, '');
    const v6 = s.match(/^\[([^\]]+)\]:(\S+)$/);
    if (v6) return [v6[1], v6[2]];
    const i = s.lastIndexOf(':');
    if (i > 0 && s.indexOf(':') === i) return [s.slice(0, i), s.slice(i + 1)];
    return [s, ''];
  }

  function ipScope(raw) {
    let ip = String(raw || '').trim().replace(/^\[|\]$/g, '').replace(/%.*$/, '').toLowerCase();
    ip = ip.replace(/^::ffff:/, '');
    if (!ip) return 'unknown';
    if (ip === '*' || ip === '0.0.0.0' || ip === '::') return 'any';
    if (ip === 'localhost' || ip === '::1' || /^127\./.test(ip)) return 'loopback';
    const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (m) {
      const a = +m[1], b = +m[2];
      if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0) return 'private';
      if (a >= 224) return 'multicast';
      return 'public';
    }
    if (ip.includes(':')) {
      if (/^fe[89ab]/.test(ip) || /^f[cd]/.test(ip)) return 'private';
      if (/^ff/.test(ip)) return 'multicast';
      return 'public';
    }
    return 'host';
  }

  const SLD2 = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.jp', 'co.nz', 'com.br', 'com.cn', 'com.mx', 'co.in', 'co.kr', 'com.tr', 'com.sg', 'com.hk', 'co.za']);
  function baseDomain(d) {
    const p = String(d).toLowerCase().replace(/\.$/, '').split('.');
    if (p.length <= 2) return p.join('.');
    const last2 = p.slice(-2).join('.');
    return SLD2.has(last2) ? p.slice(-3).join('.') : last2;
  }
  function entropy(s) {
    const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
    let h = 0; for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }
  function dgaScore(l) {
    if (!l || l.length < 10) return 0;
    let s = 0;
    if (l.length >= 14) s++;
    if (entropy(l) >= 3.5) s++;
    if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(l)) s++;
    const digits = (l.match(/\d/g) || []).length / l.length;
    if (digits >= 0.2 && digits <= 0.7) s++;
    if (!/[aeiou]/.test(l)) s++;
    return s;
  }
  // Bases whose subdomains are machine-generated by design; skip DGA/tunnel heuristics.
  const CDN_BASES = new Set(('apple.com icloud.com icloud-content.com aaplimg.com apple-dns.net apple-cloudkit.com mzstatic.com cdn-apple.com ' +
    'akamaiedge.net akamai.net akadns.net akamaized.net akamaihd.net edgekey.net edgesuite.net cloudfront.net amazonaws.com ' +
    'googleapis.com google.com gstatic.com googleusercontent.com googlevideo.com ytimg.com youtube.com ggpht.com 1e100.net ' +
    'doubleclick.net googlesyndication.com microsoft.com azureedge.net azure.com windows.net msedge.net office.com live.com ' +
    'trafficmanager.net fastly.net fastly-edge.com cloudflare.com cloudflare-dns.com github.com githubusercontent.com ' +
    'plex.tv plex.direct spotify.com scdn.co facebook.com fbcdn.net sentry.io mozilla.net mozilla.org docker.io docker.com ' +
    'ollama.com anthropic.com claude.ai openai.com slack.com zoom.us salesforce.com force.com hubspot.com sharepoint.com ' +
    'outlook.com tailscale.com ts.net nflxvideo.net netflix.com amazon.com media-amazon.com ssl-images-amazon.com').split(' '));
  const SUS_TLDS = new Set('zip mov top xyz click gq tk ml cf ga work rest cam icu monster cyou sbs buzz country kim loan date racing bid stream download review party trade accountant science men surf quest'.split(' '));
  const SKIP_DNS = /(\.arpa|\.local|\.lan|\.internal|\.localdomain|\.home)$|^[^.]+$|^_/;

  const DEV_HIDDEN = /\/\.(local|cargo|nvm|docker|orbstack|rd|colima|bun|deno|volta|pyenv|rbenv|asdf|npm-global|npm|ollama|lmstudio|vscode|cursor|config|dotnet|sdkman|rustup|gem|bin|claude)\//;
  function pathRisk(p) {
    if (!p) return null;
    if (/^\/(private\/)?(tmp|var\/tmp)\//.test(p)) return 'runs from a temp directory';
    if (/^\/Users\/Shared\//.test(p)) return 'runs from /Users/Shared';
    if (/^\/(private\/)?var\/folders\//.test(p)) return 'runs from a per-user temp folder';
    if (/\/Library\/Caches\//.test(p)) return 'runs from a Caches folder';
    if (/\/Downloads\//.test(p)) return 'runs from Downloads';
    if (/\/\.[^/]+\//.test(p) && !DEV_HIDDEN.test(p)) return 'runs from a hidden directory';
    return null;
  }

  // ------------------------------------------------------------------ state
  function newState(opts = {}) {
    return {
      ref: opts.now ? new Date(opts.now) : new Date(),
      refFromPath: false,
      files: [],
      meta: { host: opts.host || '', os: '', build: '', minTs: null, maxTs: null },
      timeline: new Map(),
      u: {
        events: 0, procs: new Map(), sudo: [], ssh: [], screen: [], authd: new Map(), lock: [],
        gk: [], xp: [], xpSeen: new Map(), fw: [], tcc: new Map(), tccPending: new Map(), tccRaw: 0,
        btm: [], btmSeen: new Set(), faults: new Map(), faultCount: 0,
      },
      crashes: new Map(),
      raw: {},            // latest text per snapshot kind
      updates: [], tcp: [], udp: [], established: [],
      containerLogs: new Map(),
      dns: null, ollama: null,
    };
  }

  // ------------------------------------------------------------ classifying
  const NAME_KIND = {
    'launch-plists.txt': 'launchPlists', 'launch-dirs.txt': 'launchDirs', 'background-items.txt': 'btmDump',
    'system-extensions.txt': 'sysext', 'profiles.txt': 'profiles', 'crontab.txt': 'cron', 'launchctl-user.txt': 'launchctl',
    'posture.txt': 'posture', 'update-history.txt': 'updates', 'install.log': 'installLog', 'logins.txt': 'logins',
    'sleep-wake.txt': 'power', 'listening-tcp.txt': 'lsofListen', 'listening-udp.txt': 'lsofListen',
    'established-tcp.txt': 'lsofEstablished', '_list.txt': 'containerList', 'ollama-server.log': 'ollama', 'server.log': 'ollama',
  };
  function classify(path, head) {
    const p = String(path).toLowerCase(), b = basename(p);
    head = String(head || '').trimStart();
    if (/(^|\/)__macosx\//.test(p) || b === '.ds_store' || b.startsWith('._')) return 'ignore';
    if (/\.(ips|panic|diag|spin|hang|crash)$/.test(b)) return 'crash';
    if (/\.(ndjson|jsonl)$/.test(b) && !/remote/.test(b)) return 'unified';
    if ((head[0] === '{' || head[0] === '[') && head.slice(0, 4096).includes('"eventMessage"')) return 'unified';
    if (b === 'server.log' && !/ollama/.test(p)) { /* fall through to sniffing */ } else if (NAME_KIND[b]) return NAME_KIND[b];
    if (/-querylog\.txt$/.test(b)) return 'dns';
    if (/(^|\/)containers\//.test(p) && /\.log$/.test(b)) return 'containerLog';
    if (b === 'pihole.log') return 'dns';
    if (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d{4}\s+0x[0-9a-f]+\s+\w+/m.test(head) || /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+\s+(Df|Db|I|E|F)\s+\S/m.test(head) || /^Timestamp\s+Thread\s+Type/m.test(head)) return 'unifiedText';
    if (/Records for UID/.test(head)) return 'btmDump';
    if (/^== .+\.plist\s*$/m.test(head)) return 'launchPlists';
    if (/^== \/.*Launch(Agents|Daemons)\s*$/m.test(head)) return 'launchDirs';
    if (/System Integrity Protection status|FileVault is (On|Off)/.test(head)) return 'posture';
    if (/^COMMAND\s+PID\s+USER\s+FD\s+TYPE/m.test(head)) return /\(ESTABLISHED\)/.test(head) ? 'lsofEstablished' : 'lsofListen';
    if (/dnsmasq\[\d+\]:.*query\[/.test(head)) return 'dns';
    if (/\[GIN\]|level=(INFO|WARN|ERROR) source=/.test(head)) return 'ollama';
    if (/^wtmp begins|still logged in/m.test(head)) return 'logins';
    if (/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4}\s+(Sleep|Wake|DarkWake)\b/m.test(head)) return 'power';
    if (/^Display Name\s+Version\s+Date/m.test(head)) return 'updates';
    if (/installd\[\d+\]|PackageKit|softwareupdated\[\d+\]/.test(head)) return 'installLog';
    if (/^PID\s+Status\s+Label/m.test(head)) return 'launchctl';
    if (/system_extension|extension\(s\)/.test(head)) return 'sysext';
    return 'unknown';
  }

  // ---------------------------------------------------------------- ingest
  const RAW_KINDS = new Set(['launchPlists', 'launchDirs', 'btmDump', 'sysext', 'profiles', 'cron', 'launchctl', 'posture', 'installLog', 'logins', 'power', 'containerList']);

  async function ingest(st, path, text, onProgress, opts = {}) {
    const kind = opts.kind || classify(path, text.slice(0, 65536));
    if (kind === 'ignore') return null;
    if (!st.refFromPath) {
      const pm = String(path).match(/maclogs-(.+?)-(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d)(?:\/|\.zip|$)/);
      if (pm) {
        st.meta.host = st.meta.host || pm[1];
        st.ref = new Date(+pm[2], +pm[3] - 1, +pm[4], +pm[5], +pm[6]);
        st.refFromPath = true;
      }
    }
    const f = { path, kind, size: text.length, records: 0, note: '' };
    st.files.push(f);
    try {
      switch (kind) {
        case 'unified': await ingestUnifiedJson(st, f, text, onProgress); break;
        case 'unifiedText': await ingestUnifiedText(st, f, text, onProgress); break;
        case 'crash': ingestCrash(st, f, text); break;
        case 'lsofListen': ingestLsof(st, f, text, 'listen'); break;
        case 'lsofEstablished': ingestLsof(st, f, text, 'established'); break;
        case 'dns': await ingestDnsLog(st, f, text, onProgress); break;
        case 'containerLog': ingestContainerLog(st, f, text); break;
        case 'ollama': ingestOllama(st, f, text); break;
        case 'updates': ingestUpdates(st, f, text); break;
        case 'unknown': f.note = 'not recognized — skipped'; break;
        default:
          if (RAW_KINDS.has(kind)) {
            st.raw[kind] = (opts.append && st.raw[kind]) ? st.raw[kind] + '\n' + text : text;
            f.records = text.split('\n').length;
          }
      }
    } catch (e) { f.note = 'parse error: ' + e.message; }
    if (!f.records && !f.note && kind !== 'unknown') f.note = 'no records found';
    return f;
  }

  function bump(st, ts, cat) {
    if (!ts) return;
    const t = ts.getTime();
    if (st.meta.minTs === null || t < st.meta.minTs) st.meta.minTs = t;
    if (st.meta.maxTs === null || t > st.meta.maxTs) st.meta.maxTs = t;
    if (!cat) return;
    const h = Math.floor(t / HOUR) * HOUR;
    let row = st.timeline.get(h);
    if (!row) { row = { auth: 0, gatekeeper: 0, tcc: 0, firewall: 0, background: 0, fault: 0 }; st.timeline.set(h, row); }
    row[cat]++;
  }

  function eventFromObj(st, o) {
    if (!o || o.eventMessage === undefined) return false;
    handleEvent(st, {
      ts: parseTs(o.timestamp), proc: basename(o.processImagePath) || o.process || '',
      sub: o.subsystem || '', type: String(o.messageType || '').toLowerCase(), msg: String(o.eventMessage || ''),
    });
    return true;
  }

  async function ingestUnifiedJson(st, f, text, onProgress) {
    const t = text.trimStart();
    if (t[0] === '[') {
      let arr; try { arr = JSON.parse(t); } catch (e) { f.note = 'invalid JSON'; return; }
      for (let i = 0; i < arr.length; i++) {
        if (eventFromObj(st, arr[i])) f.records++;
        if ((i & 0x3fff) === 0x3fff) { onProgress && onProgress(i / arr.length, f.records); await tick(); }
      }
      return;
    }
    const len = text.length; let start = 0, i = 0;
    while (start < len) {
      let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
      if (text.charCodeAt(start) === 123) {
        let o = null; try { o = JSON.parse(text.slice(start, nl)); } catch (e) { /* partial line */ }
        if (o && eventFromObj(st, o)) f.records++;
      }
      start = nl + 1;
      if ((++i & 0x3fff) === 0) { onProgress && onProgress(start / len, f.records); await tick(); }
    }
  }

  const RX_U_DEFAULT = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d{4})\s+0x[0-9a-f]+\s+(\w+)\s+0x[0-9a-f]+\s+\d+\s+\d+\s+(.+?):\s(.*)$/;
  const RX_U_COMPACT = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(Df|Db|I|E|F|A\w*)\s+(.+?)\[\d+:[0-9a-f]+\]\s(.*)$/;
  const RX_U_SYSLOG = /^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d{4})\s+\S+\s+(.+?)\[\d+\]:?\s(.*)$/;
  const CODE = { Df: 'default', Db: 'debug', I: 'info', E: 'error', F: 'fault' };
  function splitRest(rest) {
    let sub = '', m;
    if ((m = rest.match(/^\(([^)]*)\)\s+/))) rest = rest.slice(m[0].length);
    if ((m = rest.match(/^\[([^:\]\s]+):([^\]]*)\]\s*/))) { sub = m[1]; rest = rest.slice(m[0].length); }
    if ((m = rest.match(/^<(\w+)>:\s*/))) rest = rest.slice(m[0].length);
    return { sub, msg: rest };
  }
  async function ingestUnifiedText(st, f, text, onProgress) {
    const len = text.length; let start = 0, i = 0, pend = null;
    const flush = () => { if (pend) { handleEvent(st, pend); f.records++; pend = null; } };
    while (start < len) {
      let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
      const line = text.slice(start, nl).replace(/\r$/, ''); start = nl + 1;
      let m, ev = null;
      if ((m = line.match(RX_U_DEFAULT))) { const r = splitRest(m[4]); ev = { ts: parseTs(m[1]), type: m[2].toLowerCase(), proc: m[3].trim(), sub: r.sub, msg: r.msg }; }
      else if ((m = line.match(RX_U_COMPACT))) { const r = splitRest(m[4]); ev = { ts: parseTs(m[1]), type: CODE[m[2]] || 'default', proc: m[3].trim(), sub: r.sub, msg: r.msg }; }
      else if ((m = line.match(RX_U_SYSLOG))) { const r = splitRest(m[3]); ev = { ts: parseTs(m[1]), type: 'default', proc: m[2].trim(), sub: r.sub, msg: r.msg }; }
      if (ev) { flush(); pend = ev; }
      else if (pend && line && !/^(Timestamp|Filtering|Skipping|---|Log\s+-)/.test(line)) pend.msg += '\n' + line;
      if ((++i & 0x3fff) === 0) { onProgress && onProgress(start / len, f.records); await tick(); }
    }
    flush();
  }

  // ----------------------------------------------------- unified dispatch
  function handleEvent(st, e) {
    const u = st.u; u.events++;
    inc(u.procs, e.proc || '(unknown)');
    bump(st, e.ts, null);
    if (e.type === 'fault') faultEvent(st, e);
    const p = e.proc;
    if (p === 'sudo') return sudoEvent(st, e);
    if (p === 'sshd' || p === 'sshd-session' || p === 'sshd-auth') return sshEvent(st, e);
    if (p === 'screensharingd') return screenEvent(st, e);
    if (p === 'authd') return authdEvent(st, e);
    if (p === 'loginwindow') return lockEvent(st, e);
    if (p === 'syspolicyd') return gkEvent(st, e);
    if (/^xprotect/i.test(p)) return xpEvent(st, e);
    if (p === 'socketfilterfw') return fwEvent(st, e);
    if (e.sub === 'com.apple.TCC' || p === 'tccd') return tccEvent(st, e);
    if (e.sub === 'com.apple.backgroundtaskmanagement' || p === 'backgroundtaskmanagementd') return btmEvent(st, e);
  }

  const COLLECTOR = [/^validate$/i, /\/lsof -nP -i(TCP|UDP)/, /sfltool dumpbtm/, /\/profiles list\s*$/, /\/find \/Library\/Logs\/DiagnosticReports /,
    /\/chown -R \S+ crash\/system\s*$/, /\/tail -n \d+ \/var\/log\/install\.log/, /systemsetup -getremotelogin/, /argus-collect/];
  const RISKY_CMD = [
    [/\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/, 'pipe-to-shell download'],
    [/\bcsrutil\b/, 'SIP change'],
    [/\bspctl\b.*--(master|global)-disable/, 'Gatekeeper disabled'],
    [/\bspctl\b.*--add\b/, 'Gatekeeper exception added'],
    [/\bxattr\b.*com\.apple\.quarantine|\bxattr\s+-[a-z]*c/, 'quarantine attribute removed'],
    [/socketfilterfw\b.*--setglobalstate\s+off/, 'firewall disabled'],
    [/systemsetup\b.*-setremotelogin\s+on/, 'Remote Login enabled'],
    [/\bdscl\b.*-append\s+\S*Groups\/admin|\bdseditgroup\b.*-a\b.*\badmin\b/, 'user added to admin'],
    [/\bsysadminctl\b.*-addUser|\bdscl\b.*-create\s+\/Users\//, 'user account created'],
    [/\blaunchctl\b\s+(load|bootstrap|enable)\b/, 'launchd job loaded'],
    [/\btccutil\b/, 'privacy permissions reset'],
    [/\bnvram\b/, 'NVRAM change'],
    [/\bpfctl\b\s+-d\b/, 'packet filter disabled'],
    [/\bkextload\b|\bkmutil\b\s+load/, 'kernel extension load'],
    [/\bsecurity\b\s+(dump-keychain|find-(generic|internet)-password)/, 'keychain access'],
    [/\bchmod\b.*(\+s|\b[4267][0-7]{3})\b/, 'setuid/setgid bit'],
    [/\bvisudo\b|\/etc\/sudoers/, 'sudoers change'],
    [/\bdefaults\b\s+write\s+\/Library\/Preferences\/com\.apple\.(SoftwareUpdate|alf|security)/, 'security setting change'],
  ];
  const RX_SUDO = /^\s*([\w.\-@]+)\s*:\s*(.*?)\s*;?\s*TTY=([^;]*?)\s*;\s*PWD=([^;]*?)\s*;\s*USER=([^;]*?)\s*;\s*(?:[A-Z]+=[^;]*;\s*)*COMMAND=(.*)$/;

  function sudoEvent(st, e) {
    const m = e.msg.match(RX_SUDO);
    if (!m) {
      if (/incorrect password|authentication failure|NOT in sudoers|password is required/i.test(e.msg)) {
        pushCap(st.u.sudo, { ts: e.ts, user: '', reason: trunc(e.msg, 200), tty: '', pwd: '', runas: '', command: '', ok: false, collector: false, risk: '' }, 20000);
        bump(st, e.ts, 'auth');
      }
      return;
    }
    const command = m[6].trim(), reason = m[2].trim();
    const rec = { ts: e.ts, user: m[1], reason, tty: m[3].trim(), pwd: m[4].trim(), runas: m[5].trim(), command, ok: !reason, collector: COLLECTOR.some(r => r.test(command)), risk: '' };
    for (const [rx, label] of RISKY_CMD) if (rx.test(command)) { rec.risk = label; break; }
    pushCap(st.u.sudo, rec, 20000);
    bump(st, e.ts, 'auth');
  }

  function sshEvent(st, e) {
    let m, rec = null;
    if ((m = e.msg.match(/Accepted (\S+) for (\S+) from (\S+) port (\d+)/))) rec = { ok: true, method: m[1], user: m[2], ip: m[3], port: m[4] };
    else if ((m = e.msg.match(/Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/))) rec = { ok: false, method: m[1], user: m[2], ip: m[3], port: m[4] };
    else if ((m = e.msg.match(/Invalid user (\S*) from (\S+)(?: port (\d+))?/))) rec = { ok: false, method: 'invalid user', user: m[1], ip: m[2], port: m[3] || '' };
    if (!rec) return;
    rec.ts = e.ts; pushCap(st.u.ssh, rec, 20000); bump(st, e.ts, 'auth');
  }

  function screenEvent(st, e) {
    const m = e.msg.match(/Authentication:\s*(SUCCEEDED|FAILED)\s*::\s*User Name:\s*(.*?)\s*::\s*Viewer Address:\s*(\S+?)\s*(?:::|$)/i);
    if (!m) return;
    pushCap(st.u.screen, { ts: e.ts, ok: /SUCCEEDED/i.test(m[1]), user: m[2], ip: m[3] }, 20000);
    bump(st, e.ts, 'auth');
  }

  function authdEvent(st, e) {
    const m = e.msg.match(/^(Succeeded|Failed to) authoriz(?:ing|e) right '([^']+)' by client '([^']+)'/);
    if (!m) return;
    const key = m[2] + '|' + m[3];
    let a = st.u.authd.get(key);
    if (!a) { a = { right: m[2], client: m[3], ok: 0, fail: 0, last: null }; st.u.authd.set(key, a); }
    if (m[1] === 'Succeeded') a.ok++; else { a.fail++; bump(st, e.ts, 'auth'); }
    if (e.ts && (!a.last || e.ts > a.last)) a.last = e.ts;
  }

  function lockEvent(st, e) {
    const kind = /screenIsLocked/.test(e.msg) ? 'lock' : /screenIsUnlocked/.test(e.msg) ? 'unlock' : null;
    if (!kind) return;
    const prev = st.u.lock[st.u.lock.length - 1];
    if (prev && prev.kind === kind && e.ts && prev.ts && Math.abs(e.ts - prev.ts) < 5000) return;
    pushCap(st.u.lock, { ts: e.ts, kind }, 5000);
    bump(st, e.ts, 'auth');
  }

  // \b around "blocked": QUIC's quic_conn_log_summary lines report DATA_BLOCKED/STREAM_DATA_BLOCKED
  // flow-control frame counters (routine networking stats, nothing to do with Gatekeeper), and a loose
  // "blocked" substring match misclassified every one of them as a blocked-launch event.
  const GK_INTEREST = /Prompt shown|rejection|rejected|Terminating process|\bblocked\b|malware|notariz|Disallow|user override|evaluateScanResult|process assessment/i;
  function gkEvent(st, e) {
    if (!GK_INTEREST.test(e.msg)) return;
    let outcome = 'scan';
    if (/malware/i.test(e.msg)) outcome = 'malware';
    else if (/rejection|rejected|Terminating process|\bblocked\b|Disallow/i.test(e.msg)) outcome = 'blocked';
    else if (/Prompt shown/i.test(e.msg)) outcome = 'prompt';
    else if (/override/i.test(e.msg)) outcome = 'override';
    else if (/not notariz|unnotariz/i.test(e.msg)) outcome = 'unnotarized';
    const path = (e.msg.match(/\(path: ([^)]+)\)/) || e.msg.match(/(\/(?:Applications|Users|Volumes|private|tmp|opt|usr\/local|Library)[^\s,()'"<]*)/) || [])[1] || '';
    const team = (e.msg.match(/\(team: ([^)]*)\)/) || [])[1];
    pushCap(st.u.gk, { ts: e.ts, outcome, path: path.trim(), team: team === undefined ? '' : team.replace(/^\(/, '').trim(), msg: trunc(e.msg, 300) }, 20000);
    if (outcome !== 'scan') bump(st, e.ts, 'gatekeeper');
  }

  const XP_INTEREST = /malware|detect|remediat|infect|threat|quarantin|violat|bastion|signature match|matched rule|yara/i;
  // XProtect's actual wire format has no spaces ("NoThreatDetected", "status_code":20) and routine
  // startup/connection chatter ("Initialized libYARA", "activating connection... quarantine-resolver")
  // that the word-boundary phrases below never matched — without these, every clean scan (the vast
  // majority of events) was misclassified as "worth reviewing".
  const XP_NEG = /\b(no (threats?|malware|matches?|detections?)|not (detected|found)|nothing (found|detected)|0 (threats|detections|matches))\b|nothreatdetected|"status_code"\s*:\s*20\b|^initialized libyara|activating connection:|got path from launchservices/i;
  const XP_HIGH = /(malware|infect)[^.]*(detect|found|remov|quarantin)|(detect|found|remov|quarantin)[^.]*(malware|infect)/i;
  function xpEvent(st, e) {
    if (!XP_INTEREST.test(e.msg) || XP_NEG.test(e.msg)) return;
    const k = e.proc + '|' + norm(e.msg).slice(0, 200);
    const seen = st.u.xpSeen.get(k);
    if (seen) { seen.count++; seen.last = e.ts; return; }
    const rec = { ts: e.ts, last: e.ts, proc: e.proc, msg: trunc(e.msg, 400), high: XP_HIGH.test(e.msg), count: 1 };
    st.u.xpSeen.set(k, rec);
    pushCap(st.u.xp, rec, 5000);
    bump(st, e.ts, 'gatekeeper');
  }

  function fwEvent(st, e) {
    let m, rec = null;
    if ((m = e.msg.match(/Stealth Mode connection attempt to (TCP|UDP) (\S+?):(\d+) from (\S+?):(\d+)/i))) {
      rec = { action: 'stealth', app: '', proto: m[1].toUpperCase(), src: m[4], port: m[3] };
    } else if ((m = e.msg.match(/\b(Deny|Allow)\s+(.+?)\s+(?:data in|connecting)\s+from\s+(\S+)(?:\s+to port (\d+))?(?:\s+proto=(\d+))?/))) {
      const hp = splitHostPort(m[3]);
      rec = { action: m[1].toLowerCase(), app: m[2], proto: m[5] === '17' ? 'UDP' : m[5] === '6' ? 'TCP' : '', src: hp[0], port: m[4] || hp[1] };
    }
    if (!rec) return;
    rec.ts = e.ts; pushCap(st.u.fw, rec, 50000); bump(st, e.ts, 'firewall');
  }

  function tccEvent(st, e) {
    const m0 = e.msg.match(/AUTHREQ_(CTX|ATTRIBUTION|RESULT): msgID=([\d.]+)/);
    if (!m0) return;
    st.u.tccRaw++;
    const pend = st.u.tccPending;
    if (pend.size > 50000) pend.clear();
    const id = m0[2];
    let r = pend.get(id);
    if (!r) { r = { ts: e.ts }; pend.set(id, r); }
    if (m0[1] === 'CTX') {
      const s = e.msg.match(/service=kTCCService(\w+)/); if (s) r.service = s[1];
      r.preflight = /preflight=yes/.test(e.msg);
    } else if (m0[1] === 'ATTRIBUTION') {
      const resp = e.msg.match(/responsible=\{TCCDProcess: ([^}]*)\}/);
      if (resp) {
        r.client = (resp[1].match(/identifier=([^,]+)/) || [])[1] || '';
        r.path = (resp[1].match(/binary_path=([^,]+)/) || resp[1].match(/responsible_path=([^,]+)/) || [])[1] || '';
      }
    } else {
      const v = e.msg.match(/authValue=(\d+)/);
      r.value = v ? +v[1] : null;
      pend.delete(id);
      const client = r.client || basename(r.path) || '(unknown)';
      const service = r.service || '(unknown)';
      const key = client + '|' + service;
      let a = st.u.tcc.get(key);
      if (!a) {
        a = { client, path: r.path || '', service, allowed: 0, denied: 0, other: 0, preflight: 0, last: null,
          apple: /^com\.apple\./.test(client) || /^\/(System|usr|bin|sbin)\//.test(r.path || '') };
        st.u.tcc.set(key, a);
      }
      if (r.preflight) a.preflight++;
      if (r.value === 2 || r.value === 3) a.allowed++; else if (r.value === 0) a.denied++; else a.other++;
      if (e.ts && (!a.last || e.ts > a.last)) a.last = e.ts;
      if (!r.preflight) bump(st, e.ts, 'tcc');
    }
  }

  const BTM_INTEREST = /advisory|notif|item.*(added|registered|enabled)|(added|registered|registering|enabled).*(item|agent|daemon|login)|new (item|login|background)/i;
  function btmEvent(st, e) {
    if (!BTM_INTEREST.test(e.msg)) return;
    const k = norm(e.msg).slice(0, 200);
    if (st.u.btmSeen.has(k) || st.u.btmSeen.size > 2000) return;
    st.u.btmSeen.add(k);
    pushCap(st.u.btm, { ts: e.ts, msg: trunc(e.msg, 400) }, 300);
    bump(st, e.ts, 'background');
  }

  function faultEvent(st, e) {
    st.u.faultCount++;
    const k = (e.proc || '?') + '\u0001' + (e.sub || '');
    let f = st.u.faults.get(k);
    if (!f) { f = { proc: e.proc || '?', sub: e.sub || '', count: 0, sample: trunc(e.msg, 300), last: null }; st.u.faults.set(k, f); }
    f.count++;
    if (e.ts && (!f.last || e.ts > f.last)) f.last = e.ts;
    bump(st, e.ts, 'fault');
  }

  // ---------------------------------------------------------- other inputs
  function ingestCrash(st, f, text) {
    const name = basename(f.path);
    let header = null, body = null;
    const nl = text.indexOf('\n');
    try { header = JSON.parse(nl > 0 ? text.slice(0, nl) : text); } catch (e) { /* not JSON */ }
    if (header && nl > 0) { try { body = JSON.parse(text.slice(nl + 1)); } catch (e) { /* text body */ } }
    const c = { file: name, path: f.path, ts: null, app: '', kind: '', bugType: '', exception: '', detail: '', procPath: '', team: '', version: '',
      source: /\/crash\/system\/|^\/host\/Library\//.test(f.path) ? 'system' : /\/crash\/user\/|\/home\//.test(f.path) ? 'user' : '' };
    if (header && typeof header === 'object') {
      c.ts = parseTs(header.timestamp);
      c.app = header.app_name || header.name || header.process_name || '';
      c.bugType = String(header.bug_type || '');
      c.version = header.app_version || '';
    }
    if (body && typeof body === 'object') {
      c.procPath = body.procPath || '';
      c.app = c.app || body.procName || '';
      if (body.exception) c.exception = [body.exception.type, body.exception.signal].filter(Boolean).join(' / ');
      if (body.termination && body.termination.indicator) c.detail = trunc(body.termination.indicator, 200);
      c.team = body.codeSigningTeamID || '';
      if (body.panicString) c.detail = trunc(String(body.panicString).split('\n')[0], 240);
    }
    if (!header) {
      c.app = (text.match(/^Process:\s+(.+?)\s+\[\d+\]/m) || [])[1] || '';
      c.procPath = (text.match(/^Path:\s+(.+)$/m) || [])[1] || '';
      c.ts = parseTs((text.match(/^Date\/Time:\s+(.+)$/m) || [])[1]);
      c.exception = (text.match(/^Exception Type:\s+(.+)$/m) || [])[1] || '';
    }
    if (!c.detail) { const pm = text.match(/"panicString"\s*:\s*"((?:[^"\\]|\\.){0,240})/); if (pm) c.detail = pm[1].replace(/\\n/g, ' '); }
    if (!c.ts) {
      const dm = name.match(/(\d{4}-\d\d-\d\d)-(\d\d)(\d\d)(\d\d)/);
      if (dm) c.ts = new Date(`${dm[1]}T${dm[2]}:${dm[3]}:${dm[4]}`);
    }
    const bt = c.bugType;
    if (/^JetsamEvent/i.test(name) || bt === '298') c.kind = 'Jetsam (memory pressure)';
    else if (/panic/i.test(name) || bt === '210') c.kind = 'Kernel panic';
    else if (/\.(hang|spin)$/i.test(name) || bt === '288') c.kind = 'Hang';
    else if (/resource|\.diag$/i.test(name)) c.kind = 'Resource limit';
    else if (bt === '309' || bt === '109' || c.exception || /\.crash$/i.test(name)) c.kind = 'Crash';
    else c.kind = bt ? `Diagnostic (type ${bt})` : 'Diagnostic';
    if (!c.app) c.app = name.replace(/[-_.]\d{4}-\d\d-\d\d.*$/, '').replace(/\.(ips|crash|diag|spin|hang|panic)$/, '');
    st.crashes.set(name, c);
    f.records = 1;
  }

  const RX_LSOF = /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(IPv4|IPv6)\s+(\S+)\s+(\S+)\s+(TCP|UDP)\s+(.+)$/;
  function ingestLsof(st, f, text, mode) {
    if (mode === 'established') st.established = [];
    else if (/udp/i.test(basename(f.path))) st.udp = [];
    else if (/tcp/i.test(basename(f.path))) st.tcp = [];
    for (const line of text.split('\n')) {
      const m = line.match(RX_LSOF);
      if (!m) continue;
      const name = m[9].trim();
      const state = (name.match(/\(([A-Z_0-9]+)\)\s*$/) || [])[1] || '';
      const conn = name.replace(/\s*\([A-Z_0-9]+\)\s*$/, '');
      const [local, remote] = conn.split('->');
      const cmd = m[1].replace(/\\x20/g, ' ');
      if (mode === 'established' || state === 'ESTABLISHED') {
        if (!remote) continue;
        const [rh, rp] = splitHostPort(remote);
        st.established.push({ cmd, pid: +m[2], user: m[3], proto: m[8], local, rhost: rh, rport: rp, scope: ipScope(rh) });
        f.records++;
        continue;
      }
      if (m[8] === 'TCP' && state && state !== 'LISTEN') continue;
      const [host, port] = splitHostPort(local);
      if (!port || port === '*') continue;
      (m[8] === 'TCP' ? st.tcp : st.udp).push({ cmd, pid: +m[2], user: m[3], fam: m[5], proto: m[8], host, port: +port || port, scope: ipScope(host) });
      f.records++;
    }
  }

  function ensureDns(st) {
    if (!st.dns) st.dns = { queries: 0, blocked: 0, byDomain: new Map(), byClient: new Map(), blockedDomains: new Map(), types: new Map(), byHour: new Map() };
    return st.dns;
  }
  function addDnsQuery(st, q) {
    const d = ensureDns(st);
    const dom = String(q.domain || '').toLowerCase().replace(/\.$/, '');
    if (!dom) return;
    d.queries++;
    inc(d.byDomain, dom); if (q.client) inc(d.byClient, q.client); if (q.type) inc(d.types, q.type);
    if (q.ts) inc(d.byHour, Math.floor(q.ts.getTime() / HOUR) * HOUR);
    if (q.blocked) { d.blocked++; inc(d.blockedDomains, dom); }
  }
  async function ingestDnsLog(st, f, text, onProgress) {
    const d = ensureDns(st);
    const len = text.length; let start = 0, i = 0;
    while (start < len) {
      let nl = text.indexOf('\n', start); if (nl === -1) nl = len;
      const line = text.slice(start, nl); start = nl + 1;
      if (line.indexOf('dnsmasq[') !== -1) {
        let m;
        if ((m = line.match(/query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/))) {
          addDnsQuery(st, { ts: parseSyslogTs(line, st.ref), domain: m[2], client: m[3], type: m[1] });
          f.records++;
        } else if ((m = line.match(/\b(gravity blocked|(?:exactly|regex) (?:blacklisted|denied)|special domain)\s+(\S+)\s+is\s/))) {
          d.blocked++; inc(d.blockedDomains, m[2].toLowerCase());
        }
      }
      if ((++i & 0x3fff) === 0) { onProgress && onProgress(start / len, f.records); await tick(); }
    }
  }

  function ingestContainerLog(st, f, text) {
    const name = basename(f.path).replace(/\.log$/, '').replace(/^_runtime$/, '(container runtime)');
    const lines = text.split('\n');
    let errors = 0, warns = 0; const samples = [];
    for (const l of lines) {
      if (/\b(error|err|fatal|panic|critical|crit|exception|traceback|failed)\b/i.test(l) && !/\b(no errors?|0 errors?|errors?=0)\b/i.test(l)) {
        errors++; pushCap(samples, trunc(l, 300), 8);
      } else if (/\bwarn(ing)?\b/i.test(l)) warns++;
    }
    st.containerLogs.set(name, { name, lines: lines.filter(Boolean).length, errors, warns, samples, path: f.path });
    f.records = lines.length;
  }

  function ingestOllama(st, f, text) {
    const o = st.ollama = { requests: 0, byClient: new Map(), byPath: new Map(), status: new Map(), errors: [] };
    for (const line of text.split('\n')) {
      let m;
      if ((m = line.match(/\[GIN\]\s+(\d{4}\/\d\d\/\d\d - \d\d:\d\d:\d\d)\s*\|\s*(\d{3})\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(\w+)\s+"([^"]+)"/))) {
        o.requests++; f.records++;
        inc(o.byClient, m[4]); inc(o.byPath, m[5] + ' ' + m[6]); inc(o.status, m[2]);
      } else if ((m = line.match(/level=(ERROR|WARN)\b.*?msg="((?:[^"\\]|\\.)*)"/))) {
        pushCap(o.errors, { level: m[1], msg: trunc(m[2], 300) }, 500);
      }
    }
  }

  function ingestUpdates(st, f, text) {
    st.updates = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^(.+?)\s{2,}(\S+)\s{2,}(\d{1,2}\/\d{1,2}\/\d{4}),?\s+(\d{1,2}:\d\d:\d\d)/);
      if (!m || /^Display Name/.test(line)) continue;
      st.updates.push({ ts: parseUsDate(m[3], m[4]), name: m[1].trim(), version: m[2], source: 'softwareupdate' });
      f.records++;
    }
  }

  // --------------------------------------------------------------- finalize
  const TCC_NAMES = {
    SystemPolicyAllFiles: 'Full Disk Access', Accessibility: 'Accessibility', ScreenCapture: 'Screen Recording', ListenEvent: 'Input Monitoring',
    PostEvent: 'Synthetic input', Camera: 'Camera', Microphone: 'Microphone', AppleEvents: 'Automation (AppleEvents)',
    SystemPolicyDesktopFolder: 'Desktop folder', SystemPolicyDocumentsFolder: 'Documents folder', SystemPolicyDownloadsFolder: 'Downloads folder',
    SystemPolicyNetworkVolumes: 'Network volumes', SystemPolicyRemovableVolumes: 'Removable volumes', SystemPolicySysAdminFiles: 'Admin files',
    AddressBook: 'Contacts', Calendar: 'Calendars', Reminders: 'Reminders', Photos: 'Photos', PhotosAdd: 'Photos (add only)',
    BluetoothAlways: 'Bluetooth', DeveloperTool: 'Developer Tools', EndpointSecurityClient: 'Endpoint Security', MediaLibrary: 'Media library',
    SpeechRecognition: 'Speech recognition', SystemPolicyAppBundles: 'App Management', SystemPolicyAppData: "Other apps' data",
    RemoteDesktop: 'Remote Desktop', FocusStatus: 'Focus status', UserAvailability: 'Focus status', Motion: 'Motion & fitness',
  };
  const TCC_HIGH = new Set(['SystemPolicyAllFiles', 'Accessibility', 'ScreenCapture', 'ListenEvent', 'PostEvent', 'EndpointSecurityClient', 'Camera', 'Microphone', 'AppleEvents', 'SystemPolicyAppBundles', 'SystemPolicyAppData', 'RemoteDesktop']);
  const svcName = s => TCC_NAMES[s] || s;

  const PORT_NAMES = { 22: 'SSH', 53: 'DNS', 80: 'HTTP', 88: 'Kerberos', 443: 'HTTPS', 445: 'SMB', 548: 'AFP', 631: 'IPP/CUPS', 3000: 'dev HTTP', 3306: 'MySQL', 3389: 'RDP',
    5000: 'AirPlay / dev HTTP', 5432: 'PostgreSQL', 5900: 'VNC / Screen Sharing', 6379: 'Redis', 7000: 'AirPlay', 8000: 'dev HTTP', 8080: 'HTTP alt', 8443: 'HTTPS alt',
    9000: 'dev / PHP-FPM', 9200: 'Elasticsearch', 11434: 'Ollama API', 27017: 'MongoDB', 32400: 'Plex' };
  const RISKY_PORTS = new Set([22, 445, 548, 3306, 3389, 5432, 5900, 6379, 9200, 11434, 27017]);
  const APPLE_PROC = /^(ControlCe|rapportd|sharingd|mDNSRespo|identitys|remoted|launchd|netbiosd|UserEvent|WiFiAgent|airportd|configd|symptomsd|AirPlayXP|replicato|screensha|kdc|smbd|cupsd|apsd|bluetooth|timed|nsurlsess|syslogd|IPNExtens|homed|mobileass|accountsd|WirelessR|Universal|corespeec|coreaudio|com\.apple|SystemUIS|NetAuthSy|captivea|networkse)/;

  function finalize(st) {
    const ctx = { st, ref: st.ref, findings: [], iocs: new Map() };
    const add = f => ctx.findings.push({
      sev: f.sev, area: f.area, title: f.title, detail: f.detail || '', source: f.source || '',
      evidence: (f.evidence || []).slice(0, 200).map(e => trunc(e, 500)),
      count: f.count !== undefined ? f.count : (f.evidence ? f.evidence.length : 1),
    });
    ctx.add = add;
    ctx.ioc = (value, type, source, context) => {
      if (!value) return;
      const k = type + '|' + value;
      let i = ctx.iocs.get(k);
      if (!i) { i = { value, type, sources: new Set(), context: trunc(context, 200), hits: 0 }; ctx.iocs.set(k, i); }
      i.sources.add(source); i.hits++;
    };

    const posture = parsePosture(ctx);
    const installs = parseInstalls(ctx);
    postureFindings(ctx, posture);
    const access = analyzeAccess(ctx);
    const protect = analyzeProtection(ctx);
    const persistence = analyzePersistence(ctx);
    const network = analyzeNetwork(ctx);
    const crashes = analyzeCrashes(ctx);
    const system = analyzeSystem(ctx, installs);
    posture.push(...system.extraPosture);
    const containers = analyzeContainers(ctx);
    const dns = analyzeDns(ctx);
    const ollama = analyzeOllama(ctx);

    ctx.findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || b.count - a.count);
    ctx.findings.forEach((f, i) => { f.id = i + 1; });
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    ctx.findings.forEach(f => { counts[f.sev]++; });

    let timeline = [...st.timeline.entries()].sort((a, b) => a[0] - b[0]);
    if (timeline.length > 1) {
      const first = timeline[0][0], last = timeline[timeline.length - 1][0];
      if ((last - first) / HOUR <= 24 * 14) {
        const filled = [];
        for (let t = first; t <= last; t += HOUR) filled.push([t, st.timeline.get(t) || { auth: 0, gatekeeper: 0, tcc: 0, firewall: 0, background: 0, fault: 0 }]);
        timeline = filled;
      }
    }

    return {
      generated: new Date(),
      meta: { ...st.meta, minTs: st.meta.minTs ? new Date(st.meta.minTs) : null, maxTs: st.meta.maxTs ? new Date(st.meta.maxTs) : null, events: st.u.events, ref: st.ref },
      files: st.files.slice(-500),
      findings: ctx.findings,
      iocs: [...ctx.iocs.values()].map(i => ({ value: i.value, type: i.type, sources: [...i.sources].join(', '), context: i.context, hits: i.hits })),
      posture, timeline: timeline.map(([t, v]) => ({ t: new Date(t), ...v })),
      access, protect, persistence, network, crashes, system, containers, dns, ollama, counts,
    };
  }

  // ---- posture
  const POSTURE_SEV = {
    'System Integrity Protection': ['high', 'medium'], 'Gatekeeper': ['high', 'medium'], 'FileVault': ['high', 'low'],
    'Application firewall': ['medium', 'low'], 'Stealth mode': ['low', 'low'], 'Remote Login (SSH)': ['medium', 'medium'],
    'Check for updates automatically': ['high', 'medium'], 'Download updates automatically': ['low', 'low'],
    'Install Rapid Security Responses / system files': ['high', 'medium'], 'Install XProtect / security data': ['high', 'medium'],
    'XProtect definitions': ['medium', 'medium'],
  };
  function parsePosture(ctx) {
    const st = ctx.st, out = [], text = st.raw.posture;
    if (!text) return out;
    const sec = {}; let cur = '_';
    for (const line of text.split('\n')) {
      const h = line.match(/^== (.+?)\s*$/);
      if (h) { cur = h[1]; sec[cur] = []; continue; }
      (sec[cur] = sec[cur] || []).push(line);
    }
    const get = k => (sec[k] || []).join('\n').trim();
    const mac = get('macOS');
    st.meta.os = (mac.match(/ProductVersion:\s*(\S+)/) || [])[1] || st.meta.os;
    st.meta.build = (mac.match(/BuildVersion:\s*(\S+)/) || [])[1] || st.meta.build;
    const host = get('Host'); if (host) st.meta.host = host.split('\n')[0].trim() || st.meta.host;
    const row = (control, status, value, why, warnTitle) => out.push({ control, status, value: trunc(String(value).trim().split('\n')[0] || '—', 160), why, warnTitle });
    const sip = get('SIP');
    if (sip) row('System Integrity Protection', /status:\s*enabled/i.test(sip) ? (/custom/i.test(sip) ? 'warn' : 'pass') : /disabled/i.test(sip) ? 'fail' : 'unknown', sip, 'Protects system files and processes from modification, even by root.');
    const gk = get('Gatekeeper');
    if (gk) row('Gatekeeper', /assessments enabled/i.test(gk) ? 'pass' : /disabled/i.test(gk) ? 'fail' : 'unknown', gk, 'Blocks unsigned or un-notarized apps on first launch.');
    const fv = get('FileVault');
    if (fv) row('FileVault', /FileVault is On/i.test(fv) ? 'pass' : /in progress/i.test(fv) ? 'warn' : /FileVault is Off/i.test(fv) ? 'fail' : 'unknown', fv, 'Full-disk encryption: the main protection if the laptop is lost or stolen.');
    const fw = sec['App firewall'] || [];
    const g = fw.find(l => /Firewall is|State =/i.test(l)) || '';
    if (g) row('Application firewall', /enabled|State = [12]/i.test(g) ? 'pass' : 'fail', g, 'Blocks unsolicited inbound connections to apps; matters most on public Wi-Fi.');
    const s = fw.find(l => /stealth/i.test(l)) || '';
    if (s) row('Stealth mode', /(is on|enabled)/i.test(s) && !/(is off|disabled)/i.test(s) ? 'pass' : 'warn', s, 'Ignores pings and probes to closed ports on untrusted networks.', 'Stealth mode is off');
    const ba = fw.find(l => /block all/i.test(l)) || '';
    if (ba) row('Block all incoming', /(set to enabled|ENABLED)/.test(ba) ? 'pass' : 'info', ba, 'Optional hardening; breaks sharing services when on.');
    const rl = get('Remote Login');
    if (rl) row('Remote Login (SSH)', /Remote Login:\s*On/i.test(rl) ? 'warn' : /Remote Login:\s*Off/i.test(rl) ? 'pass' : 'unknown', rl, 'SSH access to this Mac. "unknown" usually means the collector lacks Full Disk Access.', 'Remote Login (SSH) is enabled');
    const su = get('Software Update prefs');
    if (su) {
      const missing = /does not exist/i.test(su);
      const key = k => { const m = su.match(new RegExp(k + '\\s*=\\s*(\\d)')); return m ? +m[1] : null; };
      const chk = (label, k, offStatus, why) => {
        const v = missing ? null : key(k);
        row(label, v === 0 ? offStatus : 'pass', v === null ? `${k}: not set (system default: on)` : `${k} = ${v}`, why);
      };
      chk('Check for updates automatically', 'AutomaticCheckEnabled', 'fail', 'Without this, security updates are not discovered.');
      chk('Download updates automatically', 'AutomaticDownload', 'warn', 'Speeds up patching.');
      chk('Install Rapid Security Responses / system files', 'CriticalUpdateInstall', 'fail', 'Delivers urgent security fixes between OS releases.');
      chk('Install XProtect / security data', 'ConfigDataInstall', 'fail', 'Keeps XProtect malware signatures current.');
    }
    return out;
  }
  function postureFindings(ctx, posture) {
    for (const p of posture) {
      if (p.status !== 'fail' && p.status !== 'warn') continue;
      const sevs = POSTURE_SEV[p.control] || ['medium', 'low'];
      ctx.add({ sev: p.status === 'fail' ? sevs[0] : sevs[1], area: 'Posture',
        title: p.status === 'fail' ? `${p.control} is off` : (p.warnTitle || `${p.control} needs attention`),
        detail: p.why, evidence: [p.value], source: 'posture snapshot' });
    }
  }

  function parseInstalls(ctx) {
    const st = ctx.st, list = st.updates.slice();
    for (const line of String(st.raw.installLog || '').split('\n')) {
      let m = line.match(/Installed\s+"([^"]+)"\s*\(([^)]*)\)/);
      if (m) { list.push({ ts: parseTs(line), name: m[1], version: m[2], source: 'install.log' }); continue; }
      m = line.match(/Product archive (\/.+?\.m?pkg)\b/i);
      if (m) list.push({ ts: parseTs(line), name: basename(m[1]), version: '', source: 'install.log (package)', path: m[1] });
    }
    const seen = new Set(), out = [];
    for (const i of list.sort((a, b) => tsOf(b) - tsOf(a))) {
      const k = i.name + '|' + i.version + '|' + (i.ts ? i.ts.toDateString() : '');
      if (seen.has(k)) continue; seen.add(k); out.push(i);
    }
    const xp = out.find(i => /xprotect/i.test(i.name) && i.ts);
    ctx.xprotect = xp || null;
    return out;
  }

  // ---- access
  function parseLogins(ctx) {
    const st = ctx.st, text = st.raw.logins;
    if (!text) return [];
    const out = [];
    for (const line of text.split('\n')) {
      const m = line.match(/^(\S+)\s+(\S+)\s+(?:(\S+)\s+)?(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\w{3})\s+(\d{1,2})\s+(\d\d):(\d\d)\s*(.*)$/);
      if (!m || !(m[5] in MON) || m[1] === 'wtmp') continue;
      const ts = new Date(st.ref.getFullYear(), MON[m[5]], +m[6], +m[7], +m[8]);
      if (ts - st.ref > 2 * DAY) ts.setFullYear(ts.getFullYear() - 1);
      const host = m[3] || '';
      const scope = host ? ipScope(host) : '';
      const remote = !!host && (scope === 'public' || scope === 'private' || (/\./.test(host) && !/^(tmux|screen)/.test(host)));
      out.push({ ts, user: m[1], tty: m[2], host, remote, scope, session: m[9].trim() });
    }
    return out;
  }

  function analyzeAccess(ctx) {
    const st = ctx.st, u = st.u, add = ctx.add;
    const sudo = u.sudo.slice().sort(byTs);
    const fails = sudo.filter(s => !s.ok);
    if (fails.length) {
      add({ sev: fails.some(f => /NOT in sudoers/i.test(f.reason)) || fails.length >= 10 ? 'high' : 'medium', area: 'Access',
        title: plural(fails.length, 'failed sudo attempt'), source: 'unified log: sudo',
        detail: 'Wrong passwords, missing sudoers rights, or sudo run without credentials. A burst on one terminal can mean someone guessing at an unlocked session.',
        evidence: fails.map(f => `${fmtTs(f.ts)}  ${f.user || '?'}  ${f.reason}${f.command ? '  → ' + f.command : ''}`) });
    }
    const risky = sudo.filter(s => s.risk && !s.collector);
    if (risky.length) {
      add({ sev: 'medium', area: 'Access', title: `${plural(risky.length, 'security-sensitive command')} run as root`, source: 'unified log: sudo',
        detail: 'Commands that weaken protections, add persistence or touch credentials. Confirm each one was you.',
        evidence: risky.map(s => `${fmtTs(s.ts)}  ${s.user} [${s.risk}]  ${s.command}`) });
    }
    const ssh = u.ssh.slice().sort(byTs);
    const sshOk = ssh.filter(s => s.ok), sshBad = ssh.filter(s => !s.ok);
    if (sshOk.length) {
      add({ sev: sshOk.some(s => ipScope(s.ip) === 'public') ? 'high' : 'medium', area: 'Access', title: plural(sshOk.length, 'successful SSH login'), source: 'unified log: sshd',
        detail: 'Remote Login is on and was used. Confirm every source address is yours.',
        evidence: sshOk.map(s => `${fmtTs(s.ts)}  ${s.user} from ${s.ip} (${s.method})`) });
    }
    if (sshBad.length) {
      const byIp = new Map(); sshBad.forEach(s => inc(byIp, s.ip));
      add({ sev: sshBad.length >= 20 ? 'high' : 'medium', area: 'Access', title: plural(sshBad.length, 'failed SSH authentication'), source: 'unified log: sshd',
        detail: 'Password guessing or a misconfigured client. CrowdSec also scores these for brute-force patterns.',
        evidence: topN(byIp, 50).map(x => `${x.key} — ${x.count} failures (${ipScope(x.key)})`) });
    }
    ssh.forEach(s => { if (ipScope(s.ip) === 'public') ctx.ioc(s.ip, 'ip', 'ssh', s.ok ? 'successful SSH login' : 'failed SSH login'); });
    const screen = u.screen.slice().sort(byTs);
    const scOk = screen.filter(s => s.ok), scBad = screen.filter(s => !s.ok);
    if (scOk.length) add({ sev: scOk.some(s => ipScope(s.ip) === 'public') ? 'high' : 'medium', area: 'Access', title: plural(scOk.length, 'Screen Sharing session'), source: 'unified log: screensharingd',
      detail: 'Someone authenticated to Screen Sharing / VNC. Confirm each viewer address.', evidence: scOk.map(s => `${fmtTs(s.ts)}  ${s.user} from ${s.ip}`) });
    if (scBad.length) add({ sev: scBad.length >= 10 ? 'high' : 'medium', area: 'Access', title: plural(scBad.length, 'failed Screen Sharing login'), source: 'unified log: screensharingd',
      detail: 'Failed VNC / Screen Sharing authentication.', evidence: scBad.map(s => `${fmtTs(s.ts)}  ${s.user || '?'} from ${s.ip}`) });
    screen.forEach(s => { if (ipScope(s.ip) === 'public') ctx.ioc(s.ip, 'ip', 'screensharing', s.ok ? 'screen sharing login' : 'failed screen sharing'); });

    const authd = [...u.authd.values()].sort((a, b) => b.fail - a.fail || b.ok - a.ok);
    const authFails = authd.filter(a => a.fail > 0);
    if (authFails.length) add({ sev: 'low', area: 'Access', title: `Authorization failures on ${plural(authFails.length, 'right')}`, source: 'unified log: authd',
      detail: 'Admin prompts that were cancelled or got the wrong password. Usually benign; repeated failures on system.privilege.admin are worth a look.',
      evidence: authFails.map(a => `${a.right} ← ${a.client}: ${a.fail} failed, ${a.ok} ok`) });

    const logins = parseLogins(ctx);
    const users = new Map(); logins.forEach(l => { if (!/^(reboot|shutdown|root|_mbsetupuser)$/.test(l.user)) inc(users, l.user); });
    const primary = topN(users, 1)[0];
    const remote = logins.filter(l => l.remote);
    if (remote.length) add({ sev: 'medium', area: 'Access', title: plural(remote.length, 'remote login session') + ' in login history', source: 'last',
      detail: 'wtmp records sessions from another host (SSH or similar).', evidence: remote.map(l => `${fmtTs(l.ts)}  ${l.user} on ${l.tty} from ${l.host}`) });
    const rootL = logins.filter(l => l.user === 'root');
    if (rootL.length) add({ sev: 'medium', area: 'Access', title: 'Direct root logins recorded', source: 'last', detail: 'The root account was logged in directly.', evidence: rootL.map(l => `${fmtTs(l.ts)}  root on ${l.tty} ${l.host}`) });
    const others = [...users.keys()].filter(x => primary && x !== primary.key);
    if (others.length) add({ sev: 'low', area: 'Access', title: `Logins by other accounts: ${others.join(', ')}`, source: 'last', detail: 'Accounts besides the main user logged in. Expected on shared Macs.', evidence: logins.filter(l => others.includes(l.user)).map(l => `${fmtTs(l.ts)}  ${l.user} on ${l.tty}`) });
    const lock = u.lock;

    return {
      sudo: sudo.slice(-5000), sshEvents: ssh.slice(-5000), screen: screen.slice(-2000), authd: authd.slice(0, 500), logins: logins.slice(0, 1000),
      locks: { lock: lock.filter(l => l.kind === 'lock').length, unlock: lock.filter(l => l.kind === 'unlock').length },
      primaryUser: primary ? primary.key : '',
    };
  }

  // ---- gatekeeper / xprotect / firewall / tcc / btm
  function analyzeProtection(ctx) {
    const st = ctx.st, u = st.u, add = ctx.add;
    const groups = new Map();
    for (const g of u.gk) {
      const k = g.outcome + '|' + (g.path || norm(g.msg).slice(0, 120));
      let x = groups.get(k);
      if (!x) { x = { outcome: g.outcome, path: g.path, team: g.team, count: 0, first: g.ts, last: g.ts, sample: g.msg }; groups.set(k, x); }
      x.count++;
      if (g.ts && (!x.first || g.ts < x.first)) x.first = g.ts;
      if (g.ts && (!x.last || g.ts > x.last)) x.last = g.ts;
      if (g.team && !x.team) x.team = g.team;
    }
    const gk = [...groups.values()].sort((a, b) => (b.last || 0) - (a.last || 0));
    const unsigned = t => !t || /^null/.test(t);
    const mal = gk.filter(g => g.outcome === 'malware');
    const blocked = gk.filter(g => g.outcome === 'blocked');
    const prompts = gk.filter(g => g.outcome === 'prompt');
    if (mal.length) add({ sev: 'high', area: 'Gatekeeper', title: 'Gatekeeper flagged malware', source: 'unified log: syspolicyd', detail: 'macOS identified known malware at launch.', evidence: mal.map(g => `${fmtTs(g.last)}  ${g.path || g.sample}`) });
    if (blocked.length) add({ sev: 'medium', area: 'Gatekeeper', title: `Gatekeeper blocked ${plural(blocked.length, 'item')}`, source: 'unified log: syspolicyd', detail: 'Launches rejected for signing or notarization problems. Check where these files came from.', evidence: blocked.map(g => `${fmtTs(g.last)}  ${g.path || g.sample} (×${g.count})`) });
    const up = prompts.filter(g => unsigned(g.team));
    if (up.length) add({ sev: 'medium', area: 'Gatekeeper', title: `First-launch prompts for ${plural(up.length, 'unsigned app')}`, source: 'unified log: syspolicyd', detail: 'Downloaded apps without a Developer ID team. Fine if you built or trust them; otherwise check their origin.', evidence: up.map(g => `${fmtTs(g.last)}  ${g.path}`) });
    const sp = prompts.filter(g => !unsigned(g.team));
    if (sp.length) add({ sev: 'info', area: 'Gatekeeper', title: `${plural(sp.length, 'downloaded app')} opened for the first time`, source: 'unified log: syspolicyd', evidence: sp.map(g => `${fmtTs(g.last)}  ${g.path} (team ${g.team})`) });

    const xp = u.xp.slice().sort(byTs);
    if (xp.length) add({ sev: xp.some(x => x.high) ? 'high' : 'medium', area: 'Gatekeeper', title: xp.some(x => x.high) ? 'XProtect reported a detection' : 'XProtect activity worth reviewing', source: 'unified log: XProtect',
      detail: 'Messages from Apple’s built-in anti-malware mentioning detections, remediation or rule violations.', evidence: xp.map(x => `${fmtTs(x.ts)}  ${x.proc}: ${x.msg}${x.count > 1 ? ` (×${x.count})` : ''}`) });

    const bySrc = new Map(), byApp = new Map();
    for (const e of u.fw) {
      let s = bySrc.get(e.src);
      if (!s) { s = { src: e.src, scope: ipScope(e.src), count: 0, stealth: 0, deny: 0, ports: new Set(), apps: new Set(), last: null }; bySrc.set(e.src, s); }
      s.count++; if (e.action === 'stealth') s.stealth++; if (e.action === 'deny') s.deny++;
      if (e.port) s.ports.add(e.port); if (e.app) s.apps.add(e.app);
      if (e.ts && (!s.last || e.ts > s.last)) s.last = e.ts;
      if (e.app) inc(byApp, e.app);
    }
    const fwSrc = [...bySrc.values()].sort((a, b) => b.count - a.count).map(s => ({ ...s, ports: [...s.ports].slice(0, 12).join(', '), apps: [...s.apps].slice(0, 6).join(', ') }));
    const pub = fwSrc.filter(s => s.scope === 'public' && (s.stealth || s.deny));
    if (pub.length) add({ sev: pub.some(s => s.count >= 50) ? 'medium' : 'low', area: 'Firewall', title: `Inbound attempts from ${plural(pub.length, 'public address', 'public addresses')} blocked`, source: 'unified log: socketfilterfw',
      detail: 'The application firewall dropped connection attempts. Heavy repeat sources suggest scanning.', evidence: pub.map(s => `${s.src} — ${s.count} attempts, ports ${s.ports || '?'}`) });
    pub.forEach(s => ctx.ioc(s.src, 'ip', 'firewall', `${s.count} blocked inbound attempts`));
    const lanProbe = fwSrc.filter(s => s.scope === 'private' && s.count >= 50);
    if (lanProbe.length) add({ sev: 'low', area: 'Firewall', title: 'Repeated inbound attempts from the local network', source: 'unified log: socketfilterfw', detail: 'Another device on this network keeps connecting to closed or blocked services. On public Wi-Fi this can be a scan.', evidence: lanProbe.map(s => `${s.src} — ${s.count} attempts, ports ${s.ports}`) });

    const tcc = [...u.tcc.values()].sort((a, b) => (TCC_HIGH.has(b.service) - TCC_HIGH.has(a.service)) || (b.allowed + b.denied) - (a.allowed + a.denied));
    const third = tcc.filter(t => !t.apple && TCC_HIGH.has(t.service) && t.allowed > 0);
    if (third.length) add({ sev: 'medium', area: 'Permissions', title: `${plural(third.length, 'third-party permission')} with high-impact access in use`, source: 'unified log: TCC',
      detail: 'Full Disk Access, Accessibility, Screen Recording, Input Monitoring and similar let an app read everything or watch and control input. Make sure each one is expected.',
      evidence: third.map(t => `${t.client} → ${svcName(t.service)} (allowed ×${t.allowed})`) });
    const denied = tcc.filter(t => !t.apple && TCC_HIGH.has(t.service) && t.denied > 0 && !t.allowed);
    if (denied.length) add({ sev: 'low', area: 'Permissions', title: `${plural(denied.length, 'app')} asked for high-impact access and was denied`, source: 'unified log: TCC', evidence: denied.map(t => `${t.client} → ${svcName(t.service)} (denied ×${t.denied})`) });
    if (u.tccRaw > 0 && tcc.length === 0) add({ sev: 'info', area: 'Permissions', title: 'TCC events present but not in a recognized format', source: 'unified log: TCC', evidence: [`${u.tccRaw} TCC messages`] });
    if (u.btm.length) add({ sev: 'info', area: 'Persistence', title: `${plural(u.btm.length, 'background-item registration message')} logged`, source: 'unified log: BTM', detail: 'Apps registering login items or launch agents. Cross-check with the Background Items inventory.', evidence: u.btm.map(b => `${fmtTs(b.ts)}  ${b.msg}`) });

    return {
      gatekeeper: gk.slice(0, 2000), xprotect: xp.slice(-1000), firewall: { events: u.fw.length, sources: fwSrc.slice(0, 1000), apps: topN(byApp, 30) },
      tcc: tcc.slice(0, 2000).map(t => ({ ...t, serviceName: svcName(t.service), high: TCC_HIGH.has(t.service) })), btm: u.btm.slice(-300),
    };
  }

  // ---- persistence
  function parseLaunchDirs(text, ref) {
    const map = new Map(); let dir = '';
    for (const line of String(text || '').split('\n')) {
      const h = line.match(/^== (.+?)\s*$/);
      if (h) { dir = h[1].replace(/\/$/, ''); continue; }
      const m = line.match(/^([\-dlrwxsStT@+.]{10,12})\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}:\d\d|\d{4})\s+(.+)$/);
      if (!m || m[7] === '.' || m[7] === '..' || !(m[4] in MON)) continue;
      let mtime;
      if (m[6].includes(':')) {
        const [hh, mm] = m[6].split(':');
        mtime = new Date(ref.getFullYear(), MON[m[4]], +m[5], +hh, +mm);
        if (mtime - ref > 2 * DAY) mtime.setFullYear(mtime.getFullYear() - 1);
      } else mtime = new Date(+m[6], MON[m[4]], +m[5]);
      map.set(dir + '/' + m[7].replace(/ -> .*$/, ''), { perms: m[1], owner: m[2], group: m[3], mtime });
    }
    return map;
  }
  function parseLaunchPlists(text) {
    const items = [];
    const parts = String(text || '').split(/^== (.+?\.plist)\s*$/m);
    for (let i = 1; i < parts.length; i += 2) {
      const path = parts[i], body = parts[i + 1] || '';
      const str = k => { const m = body.match(new RegExp('"' + k + '" => "((?:[^"\\\\]|\\\\.)*)"')); return m ? m[1] : ''; };
      const label = str('Label'), program = str('Program');
      let args = [];
      const pa = body.match(/"ProgramArguments" => \[\n?([\s\S]*?)\n\s*\]/);
      if (pa) args = [...pa[1].matchAll(/^\s*\d+ => "((?:[^"\\]|\\.)*)"/gm)].map(x => x[1]);
      const flag = k => new RegExp('"' + k + '" => (1|true)\\b').test(body);
      items.push({ path, label, program: program || args[0] || '', args, runAtLoad: flag('RunAtLoad'),
        keepAlive: /"KeepAlive" =>/.test(body) && !/"KeepAlive" => (0|false)\b/.test(body), disabled: flag('Disabled'),
        scheduled: /"StartInterval"|"StartCalendarInterval"/.test(body), watch: /"WatchPaths"|"QueueDirectories"/.test(body) });
    }
    return items;
  }
  function parseBtmDump(text) {
    const items = []; let uid = '', cur = null;
    for (const line of String(text || '').split('\n')) {
      let m;
      if ((m = line.match(/Records for UID (-?\d+)/))) { uid = m[1]; cur = null; continue; }
      if ((m = line.match(/^\s*#(\d+):\s*$/))) { cur = { uid }; items.push(cur); continue; }
      if (cur && (m = line.match(/^\s*([A-Z][A-Za-z ]+?):\s+(.*?)\s*$/)) && !(m[1] in cur)) cur[m[1]] = m[2];
    }
    return items.map(r => {
      const disp = r['Disposition'] || '';
      const ident = r['Identifier'] || r['Bundle Identifier'] || '';
      const exe = r['Executable Path'] || '';
      let url = r['URL'] || '';
      try { if (url.startsWith('file://')) url = decodeURIComponent(url.slice(7)); } catch (e) { /* keep raw */ }
      return { uid: r.uid, name: r['Name'] || '', developer: r['Developer Name'] || '', team: r['Team Identifier'] || '',
        type: (r['Type'] || '').replace(/\s*\(0x[0-9a-f]+\)\s*$/i, ''), disposition: disp.replace(/\s*\(0x[0-9a-f]+\)\s*$/i, ''),
        enabled: /\benabled\b/.test(disp) && !/\bdisabled\b/.test(disp), ident, exe, url, parent: r['Parent Identifier'] || '',
        apple: /^com\.apple\./.test(ident) || /^\/System\//.test(exe) };
    });
  }
  function parseSysext(text) {
    const out = []; let cat = '';
    for (const line of String(text || '').split('\n')) {
      const h = line.match(/^---\s+(\S+)/);
      if (h) { cat = h[1].replace(/^com\.apple\.system_extension\./, ''); continue; }
      const p = line.split('\t');
      if (p.length >= 6 && p[2].trim() !== 'teamID' && /\(.*\)/.test(p[3])) {
        const bm = p[3].match(/^(\S+)\s+\(([^)]*)\)/);
        out.push({ category: cat, enabled: p[0].trim() === '*', active: p[1].trim() === '*', team: p[2].trim(), bundle: bm ? bm[1] : p[3], version: bm ? bm[2] : '', name: (p[4] || '').trim(), state: (p[5] || '').replace(/[[\]]/g, '').trim() });
      }
    }
    return out;
  }

  function analyzePersistence(ctx) {
    const st = ctx.st, add = ctx.add, ref = ctx.ref;
    const dirs = parseLaunchDirs(st.raw.launchDirs, ref);
    const launch = parseLaunchPlists(st.raw.launchPlists).map(it => {
      const meta = dirs.get(it.path);
      const domain = /\/Library\/LaunchDaemons\//.test(it.path) ? 'Daemon (root)' : /^\/Library\/LaunchAgents\//.test(it.path) ? 'Agent (all users)' : 'Agent (your account)';
      if (/^com\.argus\.collect/.test(it.label) && /\/usr\/local\/libexec\/argus\//.test(it.args.join(' '))) {
        return { ...it, domain, flags: ['Argus collector'], sev: 'info', mtime: meta ? meta.mtime : null, owner: meta ? meta.owner : '' };
      }
      const flags = []; let sev = 'info';
      const up = s => { if (SEV_ORDER[s] < SEV_ORDER[sev]) sev = s; };
      const pr = pathRisk(it.program); if (pr) { flags.push(pr); up('medium'); }
      const cmd = it.args.join(' ');
      if (/(^|\/)(sh|bash|zsh|dash|python3?|perl|ruby|osascript|node|php)$/.test(it.program)) { flags.push('runs a script interpreter'); up('low'); }
      if (/\b(curl|wget)\b|base64|\beval\b|\/dev\/tcp|\bnc\s|mkfifo|osascript\s+-e/.test(cmd)) { flags.push('inline download / encoded / shell payload'); up('high'); }
      if (/^com\.apple\./.test(it.label)) { flags.push('Apple label outside /System'); up('medium'); }
      const fileBase = basename(it.path).replace(/\.plist$/, '');
      if (it.label && fileBase !== it.label) { flags.push('label ≠ filename'); up('low'); }
      if (meta) {
        if (meta.perms[8] === 'w') { flags.push('world-writable plist'); up('high'); }
        if (/^\/Library\/Launch(Daemons|Agents)\//.test(it.path) && meta.owner !== 'root') { flags.push(`owned by ${meta.owner}, not root`); up('medium'); }
        if (meta.mtime && ref - meta.mtime < 14 * DAY && ref - meta.mtime > -DAY) { flags.push('changed in the last 14 days'); up('low'); }
      }
      if (it.disabled) flags.push('disabled');
      if (!it.program) flags.push('no program found');
      return { ...it, domain, flags, sev, mtime: meta ? meta.mtime : null, owner: meta ? meta.owner : '' };
    });
    for (const it of launch.filter(i => i.sev === 'high' || i.sev === 'medium')) {
      add({ sev: it.sev, area: 'Persistence', title: `Launch item ${it.label || basename(it.path)}: ${it.flags.filter(f => f !== 'disabled').join(', ')}`, source: 'launch plists',
        detail: 'Launch agents and daemons start automatically; most malware on macOS persists this way.',
        evidence: [`plist: ${it.path}`, `program: ${it.program}`, it.args.length > 1 ? `args: ${it.args.join(' ')}` : '', it.mtime ? `modified: ${fmtTs(it.mtime)}` : ''].filter(Boolean) });
    }
    const lowItems = launch.filter(i => i.sev === 'low');
    if (lowItems.length) add({ sev: 'low', area: 'Persistence', title: `${plural(lowItems.length, 'launch item')} with minor anomalies`, source: 'launch plists', evidence: lowItems.map(i => `${i.label || basename(i.path)}: ${i.flags.join(', ')}`) });
    if (launch.length) add({ sev: 'info', area: 'Persistence', title: `${plural(launch.length, 'third-party launch item')} installed`, source: 'launch plists', evidence: launch.map(i => `${i.domain}: ${i.label} → ${i.program}`) });

    const btmAll = parseBtmDump(st.raw.btmDump);
    const btm = btmAll.filter(b => !b.apple && !/^developer$/i.test(b.type));
    const noTeam = btm.filter(b => !b.team && b.enabled && /daemon|agent|login item/i.test(b.type));
    if (noTeam.length) add({ sev: 'medium', area: 'Persistence', title: `${plural(noTeam.length, 'enabled background item')} without a Developer Team ID`, source: 'sfltool dumpbtm',
      detail: 'Unsigned or ad-hoc signed items that start automatically. Common for Homebrew services and self-built tools; unusual for anything you did not install yourself.',
      evidence: noTeam.map(b => `${b.type}: ${b.name || b.ident} → ${b.exe || b.url}`) });
    const btmRisk = btm.filter(b => pathRisk(b.exe));
    if (btmRisk.length) add({ sev: 'high', area: 'Persistence', title: 'Background items running from unusual locations', source: 'sfltool dumpbtm', evidence: btmRisk.map(b => `${b.name || b.ident}: ${pathRisk(b.exe)} (${b.exe})`) });

    const sysext = parseSysext(st.raw.sysext);
    const ext3 = sysext.filter(s => s.team && s.team !== 'Apple' && s.enabled);
    if (ext3.length) add({ sev: 'info', area: 'Persistence', title: `${plural(ext3.length, 'third-party system extension')} enabled`, source: 'systemextensionsctl', detail: 'Network filters, endpoint security agents and drivers run with elevated privileges. Confirm each vendor.', evidence: ext3.map(s => `${s.category}: ${s.name} (${s.bundle}, team ${s.team}) [${s.state}]`) });

    const pText = String(st.raw.profiles || '');
    const profiles = /There are no configuration profiles/i.test(pText) ? [] : [...new Set([...pText.matchAll(/profileIdentifier:\s*(\S+)/g)].map(m => m[1]))];
    if (profiles.length) add({ sev: 'low', area: 'Persistence', title: `${plural(profiles.length, 'configuration profile')} installed`, source: 'profiles', detail: 'Profiles can set proxies, certificates, DNS and restrictions. Expected under MDM; verify otherwise.', evidence: profiles });

    const cText = String(st.raw.cron || '');
    const cron = /no crontab/i.test(cText) ? [] : cText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#') && !/^crontab:/.test(l));
    if (cron.length) add({ sev: cron.some(c => /\b(curl|wget|base64|nc\s|osascript)\b/.test(c)) ? 'high' : 'medium', area: 'Persistence', title: plural(cron.length, 'crontab entry', 'crontab entries'), source: 'crontab -l', detail: 'cron is rarely used on modern macOS; check each entry.', evidence: cron });

    const agents = [];
    for (const line of String(st.raw.launchctl || '').split('\n')) {
      const m = line.match(/^(\S+)\t(-?\d+)\t(.+)$/);
      if (!m || m[1] === 'PID' || /^(com\.apple\.|application\.|0x)/.test(m[3])) continue;
      agents.push({ pid: m[1] === '-' ? '' : m[1], status: +m[2], label: m[3] });
    }
    const failing = agents.filter(a => a.status !== 0);
    if (failing.length) add({ sev: 'low', area: 'Persistence', title: `${plural(failing.length, 'third-party agent')} exiting with errors`, source: 'launchctl list', evidence: failing.map(a => `${a.label} (last exit ${a.status})`) });

    return { launch, btm, sysext, profiles, cron, agents };
  }

  // ---- network
  function analyzeNetwork(ctx) {
    const st = ctx.st, add = ctx.add;
    const dedupe = list => { const seen = new Set(); return list.filter(x => { const k = x.cmd + '|' + x.port + '|' + x.scope + '|' + x.host; if (seen.has(k)) return false; seen.add(k); return true; }); };
    const tcp = dedupe(st.tcp).map(t => ({ ...t, service: PORT_NAMES[t.port] || '', apple: APPLE_PROC.test(t.cmd) })).sort((a, b) => a.port - b.port);
    const udp = dedupe(st.udp).map(t => ({ ...t, service: PORT_NAMES[t.port] || '', apple: APPLE_PROC.test(t.cmd) })).sort((a, b) => a.port - b.port);
    const exposed = tcp.filter(t => t.scope !== 'loopback' && !t.apple);
    if (exposed.length) {
      const risky = exposed.filter(t => RISKY_PORTS.has(t.port) && t.scope === 'any');
      add({ sev: risky.length ? 'high' : 'medium', area: 'Network', title: `${plural(exposed.length, 'service')} listening beyond localhost`, source: 'lsof',
        detail: 'Reachable by other devices on the same network (on public Wi-Fi, by strangers) unless the firewall blocks them. Bind dev servers and containers to 127.0.0.1.',
        evidence: exposed.map(t => `${t.cmd} (pid ${t.pid}) on ${t.host}:${t.port}${t.service ? ' — ' + t.service : ''}`) });
    }
    const est = st.established.map(e => ({ ...e }));
    const byRemote = new Map();
    for (const e of est) {
      if (e.scope !== 'public') continue;
      let r = byRemote.get(e.rhost);
      if (!r) { r = { ip: e.rhost, ports: new Set(), procs: new Set(), count: 0 }; byRemote.set(e.rhost, r); }
      r.count++; r.ports.add(e.rport); r.procs.add(e.cmd);
    }
    const remotes = [...byRemote.values()].map(r => ({ ip: r.ip, ports: [...r.ports].join(', '), procs: [...r.procs].join(', '), count: r.count })).sort((a, b) => b.count - a.count);
    remotes.forEach(r => ctx.ioc(r.ip, 'ip', 'connection', `${r.procs} → :${r.ports}`));
    const oddPorts = remotes.filter(r => r.ports.split(', ').some(p => !['443', '80', '993', '995', '465', '587', '5223', '853', '8443', '3478', '19302', '22'].includes(p)));
    if (oddPorts.length) add({ sev: 'info', area: 'Network', title: `${plural(oddPorts.length, 'outbound connection')} on uncommon ports`, source: 'lsof established', evidence: oddPorts.slice(0, 100).map(r => `${r.procs} → ${r.ip}:${r.ports}`) });
    return { tcp, udp, established: est.slice(0, 2000), remotes: remotes.slice(0, 1000) };
  }

  // ---- crashes
  function analyzeCrashes(ctx) {
    const add = ctx.add;
    const list = [...ctx.st.crashes.values()].sort((a, b) => tsOf(b) - tsOf(a));
    const panics = list.filter(c => c.kind === 'Kernel panic');
    if (panics.length) add({ sev: 'high', area: 'Crashes', title: plural(panics.length, 'kernel panic'), source: 'DiagnosticReports', detail: 'The whole system crashed. Repeated panics point at hardware, drivers or a kernel extension.', evidence: panics.map(c => `${fmtTs(c.ts)}  ${c.detail || c.file}`) });
    const odd = list.filter(c => pathRisk(c.procPath));
    if (odd.length) add({ sev: 'medium', area: 'Crashes', title: 'Crashes from programs in unusual locations', source: 'DiagnosticReports', evidence: odd.map(c => `${fmtTs(c.ts)}  ${c.app}: ${c.procPath}`) });
    const byApp = new Map(); list.filter(c => c.kind === 'Crash').forEach(c => inc(byApp, c.app));
    const rep = topN(byApp, 50).filter(x => x.count >= 3);
    if (rep.length) add({ sev: 'low', area: 'Crashes', title: `Repeated crashes in ${plural(rep.length, 'app')}`, source: 'DiagnosticReports', evidence: rep.map(x => `${x.key} ×${x.count}`) });
    const jet = list.filter(c => /Jetsam/.test(c.kind));
    if (jet.length) add({ sev: 'low', area: 'Crashes', title: plural(jet.length, 'memory-pressure event'), source: 'DiagnosticReports', detail: 'macOS killed processes to free memory. Containers, local models and browsers compete for RAM.', evidence: jet.map(c => `${fmtTs(c.ts)}  ${c.file}`) });
    return list.slice(0, 2000);
  }

  // ---- system
  function analyzeSystem(ctx, installs) {
    const st = ctx.st, add = ctx.add;
    const faults = [...st.u.faults.values()].sort((a, b) => b.count - a.count);
    const heavy = faults.filter(f => f.count >= 1000);
    if (heavy.length) add({ sev: 'low', area: 'System', title: `${plural(heavy.length, 'process', 'processes')} logging heavy faults`, source: 'unified log: faults', evidence: heavy.map(f => `${f.proc}${f.sub ? ' [' + f.sub + ']' : ''}: ${f.count} faults — ${f.sample}`) });

    const power = { days: [], reasons: [], events: 0 };
    const byDay = new Map(), reasons = new Map();
    for (const line of String(st.raw.power || '').split('\n')) {
      const m = line.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d{4})\s+(Sleep|Wake|DarkWake)\b(?!\s+Requests)\s*(.*)$/);
      if (!m) continue;
      const ts = parseTs(m[1] + m[2]); if (!ts) continue;
      const kind = m[3].toLowerCase();
      const day = `${ts.getFullYear()}-${pad(ts.getMonth() + 1)}-${pad(ts.getDate())}`;
      let d = byDay.get(day); if (!d) { d = { day, sleep: 0, wake: 0, darkwake: 0 }; byDay.set(day, d); }
      d[kind]++; power.events++;
      const r = kind === 'sleep' ? (m[4].match(/due to '([^']+)'/) || [])[1] : (m[4].match(/due to\s+([^\s/:]+(?:\s+Assertion)?)/) || [])[1];
      if (r) inc(reasons, `${kind}: ${r}`);
    }
    power.days = [...byDay.values()].sort((a, b) => a.day < b.day ? -1 : 1);
    power.reasons = topN(reasons, 15);

    const xp = ctx.xprotect;
    const posture = [];
    if (installs.length) {
      if (xp) {
        const age = Math.round((ctx.ref - xp.ts) / DAY);
        posture.push({ control: 'XProtect definitions', status: age <= 30 ? 'pass' : 'warn', value: `last update ${fmtTs(xp.ts)} (${age} d ago): ${xp.name} ${xp.version}`, why: 'XProtect signatures update silently in the background; a stale date means background updates are blocked.', warnTitle: 'XProtect definitions are stale' });
      } else posture.push({ control: 'XProtect definitions', status: 'unknown', value: 'no XProtect install found in history', why: 'Install history did not include an XProtect update.' });
      const os = installs.find(i => /^macOS/i.test(i.name) && i.ts);
      if (os) posture.push({ control: 'Last macOS update', status: 'info', value: `${os.name} ${os.version} on ${fmtTs(os.ts)}`, why: '' });
    }
    postureFindings(ctx, posture);
    return { faults: faults.slice(0, 300), faultCount: st.u.faultCount, procs: topN(st.u.procs, 40), power, installs: installs.slice(0, 1000), extraPosture: posture };
  }

  // ---- containers
  function parseContainerList(text) {
    const lines = String(text || '').split('\n').filter(l => l.trim());
    const hi = lines.findIndex(l => /^ID\s+/.test(l));
    if (hi === -1) return { headers: [], rows: [] };
    const header = lines[hi];
    const cols = [...header.matchAll(/\S+/g)].map(m => ({ name: m[0], start: m.index }));
    const rows = lines.slice(hi + 1).map(l => {
      const o = {}, tok = l.trim().split(/\s+/);
      if (tok.length <= cols.length) cols.forEach((c, i) => { o[c.name] = tok[i] || ''; });   // values never contain spaces
      else cols.forEach((c, i) => { o[c.name] = l.slice(c.start, i + 1 < cols.length ? cols[i + 1].start : undefined).trim(); });
      return o;
    });
    return { headers: cols.map(c => c.name), rows };
  }
  function analyzeContainers(ctx) {
    const st = ctx.st, add = ctx.add;
    const list = parseContainerList(st.raw.containerList);
    const logs = [...st.containerLogs.values()].sort((a, b) => b.errors - a.errors);
    const noisy = logs.filter(l => l.errors >= 20);
    if (noisy.length) add({ sev: 'low', area: 'Containers', title: `${plural(noisy.length, 'container')} logging many errors`, source: 'container logs', evidence: noisy.map(l => `${l.name}: ${l.errors} errors / ${l.lines} lines — ${l.samples[l.samples.length - 1] || ''}`) });
    const stopped = list.rows.filter(r => r.STATE && !/running/i.test(r.STATE));
    if (stopped.length) add({ sev: 'info', area: 'Containers', title: `${plural(stopped.length, 'container')} not running`, source: 'container list', evidence: stopped.map(r => `${r.ID}: ${r.STATE}`) });
    return { list, logs };
  }

  // ---- dns
  function analyzeDns(ctx) {
    const d = ctx.st.dns; const add = ctx.add;
    if (!d) return null;
    const baseCount = new Map(), baseSubs = new Map(), suspicious = [];
    for (const [dom, n] of d.byDomain) {
      if (SKIP_DNS.test(dom)) continue;
      const base = baseDomain(dom);
      inc(baseCount, base, n);
      let s = baseSubs.get(base); if (!s) { s = new Set(); baseSubs.set(base, s); }
      if (s.size < 5000) s.add(dom);
      if (CDN_BASES.has(base)) continue;
      const reasons = [];
      const labels = dom.split('.');
      if (Math.max(...labels.map(l => l.length)) >= 50 || dom.length >= 120) reasons.push('very long name (possible DNS tunneling)');
      const tld = labels[labels.length - 1];
      if (SUS_TLDS.has(tld)) reasons.push(`.${tld} TLD`);
      if (dgaScore(base.split('.')[0]) >= 3) reasons.push('random-looking name (possible DGA)');
      if (reasons.length) suspicious.push({ domain: dom, base, queries: n, reasons: reasons.join('; '), blocked: d.blockedDomains.has(dom) });
    }
    for (const [base, set] of baseSubs) if (set.size >= 300 && !CDN_BASES.has(base)) suspicious.push({ domain: '*.' + base, base, queries: baseCount.get(base), reasons: `${set.size}+ unique subdomains (possible tunneling or beaconing)`, blocked: false });
    suspicious.sort((a, b) => b.queries - a.queries);
    const strong = suspicious.filter(s => !/^\.\w+ TLD$/.test(s.reasons));
    if (strong.length) add({ sev: 'medium', area: 'DNS', title: `${plural(strong.length, 'suspicious-looking DNS name')} queried`, source: 'Pi-hole',
      detail: 'Heuristics for algorithmically generated names and tunneling. Check the Indicators view for feed and OSINT results.', evidence: strong.map(s => `${s.domain} ×${s.queries} — ${s.reasons}${s.blocked ? ' (blocked)' : ''}`) });
    const tldOnly = suspicious.filter(s => /^\.\w+ TLD$/.test(s.reasons) && !s.blocked);
    if (tldOnly.length) add({ sev: 'low', area: 'DNS', title: `${plural(tldOnly.length, 'lookup')} in frequently abused TLDs`, source: 'Pi-hole', evidence: tldOnly.map(s => `${s.domain} ×${s.queries} (${s.reasons})`) });
    suspicious.forEach(s => { if (!s.domain.startsWith('*.')) ctx.ioc(s.domain, 'domain', 'dns', s.reasons); });
    if (d.queries > 200 && d.blocked === 0) add({ sev: 'low', area: 'DNS', title: 'Pi-hole blocked nothing', source: 'Pi-hole', detail: 'Usually means gravity (blocklists) is empty or failed to update.', evidence: [`${d.queries} queries, 0 blocked`] });
    return {
      queries: d.queries, blocked: d.blocked, unique: d.byDomain.size, clients: topN(d.byClient, 30), topDomains: topN(d.byDomain, 50), topBases: topN(baseCount, 50),
      topBlocked: topN(d.blockedDomains, 50), types: topN(d.types, 12), byHour: [...d.byHour.entries()].sort((a, b) => a[0] - b[0]).map(([t, n]) => ({ t: new Date(t), n })), suspicious: suspicious.slice(0, 1000),
    };
  }

  function analyzeOllama(ctx) {
    const o = ctx.st.ollama; const add = ctx.add;
    if (!o) return null;
    const clients = topN(o.byClient, 30).map(c => ({ ...c, scope: ipScope(c.key) }));
    const remote = clients.filter(c => c.scope !== 'loopback');
    if (remote.length) add({ sev: remote.some(c => c.scope === 'public') ? 'high' : 'low', area: 'Ollama', title: 'Ollama API reached from other hosts', source: 'Ollama server.log',
      detail: 'Ollama has no authentication. Private 192.168.64.x addresses are usually your own containers; anything else means the API is exposed (OLLAMA_HOST=0.0.0.0).', evidence: remote.map(c => `${c.key} (${c.scope}) — ${c.count} requests`) });
    const s5 = [...o.status.entries()].filter(([k]) => k.startsWith('5')).reduce((a, [, v]) => a + v, 0);
    if (s5 >= 10) add({ sev: 'low', area: 'Ollama', title: `${s5} Ollama server errors`, source: 'Ollama server.log', evidence: o.errors.slice(-20).map(e => `${e.level}: ${e.msg}`) });
    return { requests: o.requests, clients, paths: topN(o.byPath, 20), status: topN(o.status, 10), errors: o.errors.slice(-100) };
  }

  return { newState, classify, ingest, finalize, handleEvent, addDnsQuery, ipScope, baseDomain, dgaScore, parseTs, pathRisk, fmtTs, CDN_BASES, SKIP_DNS, SEV_ORDER, TCC_NAMES };
});
