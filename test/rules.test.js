'use strict';
// Two-source rule, alert holding, triage backup/restore and IPv6 owners.
// Run: node --test test/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-rules-'));
process.env.ARGUS_STATE = dir; process.env.ARGUS_DATA = dir;
const lib = p => require(path.join(__dirname, '..', 'app', 'lib', p));
const { Store } = lib('store');
const { FindingState } = lib('findings');
const { Intel } = lib('intel');
const { Asn } = lib('asn');
const triage = lib('triage');

const store = new Store(dir);
new FindingState(store);
const intel = new Intel(store, { defs: [{ id: 'c2', severity: 'high' }, { id: 'meh', severity: 'medium' }], match: () => [] }, { match: () => null });
const obs = (value, reasons, sources = ['connection'], feeds = []) => {
  store.run('DELETE FROM feed_hits WHERE value = ?', value);
  for (const f of feeds) store.run('INSERT INTO feed_hits(value, type, feed, matched, label, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)', value, 'ip', f, value, '', 1, 1);
  store.run(`INSERT OR REPLACE INTO observables(value, type, first_seen, last_seen, hits, sources, context, priority, risk, risk_score, reasons) VALUES (?, 'ip', 1, 2, 3, ?, 'curl → :443', 3, 'suspicious', 60, ?)`,
    value, JSON.stringify(sources), JSON.stringify(reasons));
};
const sevOf = v => intel.findings().find(f => f.indicator.value === v).sev;

test('one reputation source: low; two: normal; strong sources and inbound: normal', () => {
  obs('5.5.5.1', ['AlienVault OTX: 3 OTX pulses: x']);
  assert.strictEqual(sevOf('5.5.5.1'), 'low');
  assert.match(intel.findings().find(f => f.indicator.value === '5.5.5.1').detail, /Only one source \(AlienVault OTX\)/);
  obs('5.5.5.2', ['AlienVault OTX: 3 OTX pulses: x', 'AbuseIPDB: confidence 60%, 9 reports; Hetzner (DE)']);
  assert.strictEqual(sevOf('5.5.5.2'), 'medium');
  obs('5.5.5.3', ['feed: C2 list'], ['connection'], ['c2']);
  assert.strictEqual(sevOf('5.5.5.3'), 'medium');
  obs('5.5.5.4', ['feed: Medium list'], ['connection'], ['meh']);
  assert.strictEqual(sevOf('5.5.5.4'), 'low');
  obs('5.5.5.5', ['AbuseIPDB: confidence 60%; x'], ['ssh']);
  assert.strictEqual(sevOf('5.5.5.5'), 'medium');
  obs('5.5.5.6', ['CrowdSec local detection: ssh-bf']);
  assert.strictEqual(sevOf('5.5.5.6'), 'medium');
});

test('ARGUS_MIN_SOURCES=1 turns the rule off', () => {
  process.env.ARGUS_MIN_SOURCES = '1';
  obs('5.5.5.7', ['AlienVault OTX: 3 OTX pulses: x']);
  assert.strictEqual(sevOf('5.5.5.7'), 'medium');
  delete process.env.ARGUS_MIN_SOURCES;
});

test('triage backup and restore merge acknowledgements and the allow list', () => {
  store.run("INSERT INTO finding_acks(id, fp, title, note, at) VALUES ('f1', 'aaaa', 't', 'n', 1000)");
  intel.allowAdd('17.0.0.0/8', 'Apple');
  const file = triage.write(store, 'triage-test.json');
  store.run('DELETE FROM finding_acks'); store.run('DELETE FROM allowlist'); intel.allowRules = null;
  store.run("INSERT INTO finding_acks(id, fp, title, note, at) VALUES ('f2', 'bbbb', 't2', '', 5000)");
  const r = triage.restore(store, intel, path.basename(file));
  assert.deepStrictEqual([r.acks, r.allow], [1, 1]);
  assert.strictEqual(store.all('SELECT id FROM finding_acks ORDER BY id').map(x => x.id).join(','), 'f1,f2');
  assert.strictEqual(intel.allowedBy('17.1.1.1', 'ip'), '17.0.0.0/8');
  assert.throws(() => triage.restore(store, intel, '../../etc/passwd'));
});

test('alerts: quiet hours hold all but highs; batched severities wait for the morning', async () => {
  const hour = new Date().getHours();
  process.env.ARGUS_ALERT_QUIET = `${hour}-${(hour + 1) % 24}`;
  process.env.ARGUS_ALERT_SEV = 'medium';
  process.env.ARGUS_ALERT_MAC = '0';
  const { Alerts } = lib('alerts');
  const a = new Alerts(store); const sent = []; a.send = async m => sent.push(m);
  store.kvSet('alerts.init', 1);
  const rep = fs_ => ({ host: { name: 'mac' }, findings: fs_, health: { checks: [] } });
  await a.process(rep([{ id: 'x1', sev: 'medium', title: 'm', area: 'A', fp: '1', evidence: [] }, { id: 'x2', sev: 'high', title: 'h', area: 'A', fp: '2', evidence: [] }]));
  assert.strictEqual(sent.length, 1); assert.match(sent[0].title, /high/); assert.strictEqual(a.held, 1);
  delete process.env.ARGUS_ALERT_QUIET;
  process.env.ARGUS_ALERT_BATCH = 'medium'; process.env.ARGUS_DIGEST_HOUR = String((hour + 3) % 24);
  const b = new Alerts(store); const sent2 = []; b.send = async m => sent2.push(m);
  await b.process(rep([{ id: 'x1', sev: 'medium', title: 'm', area: 'A', fp: '1', evidence: [] }]));
  assert.strictEqual(sent2.length, 0); assert.strictEqual(b.held, 1);
  process.env.ARGUS_DIGEST_HOUR = String(hour);
  const c = new Alerts(store); const sent3 = []; c.send = async m => sent3.push(m);
  await c.process(rep([{ id: 'x1', sev: 'medium', title: 'm', area: 'A', fp: '1', evidence: [] }]));
  assert.strictEqual(sent3.length, 1);
});

test('IPv6 owners, including IPv4-mapped addresses', () => {
  const a = new Asn();
  a.use(a.parse('17.0.0.0\t17.255.255.255\t714\tUS\tAPPLE-ENGINEERING\n'));
  a.use(a.parse('2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n', true));
  assert.strictEqual(a.lookup('2001:4860:4860::8888').label, 'AS15169 GOOGLE (US)');
  assert.strictEqual(a.lookup('::ffff:17.253.1.1').asn, 714);
  assert.strictEqual(a.lookup('2a00::1'), null);
  assert.strictEqual(a.lookup('not:an:ip::zz'), null);
});

test('views count an indicator as flagged only when the findings would (allow list, two-source rule)', () => {
  obs('6.6.6.1', ['AlienVault OTX: 3 OTX pulses: x']);
  obs('6.6.6.2', ['AlienVault OTX: 3 OTX pulses: x', 'AbuseIPDB: confidence 60%; Hetzner (DE)']);
  assert.strictEqual(intel.flaggedFor('6.6.6.1', 'ip'), null);
  assert.strictEqual(intel.flaggedFor('6.6.6.2', 'ip').level, 'medium');
  intel.allowAdd('6.6.6.2');
  assert.strictEqual(intel.flaggedFor('6.6.6.2', 'ip'), null);
  intel.allowRemove('6.6.6.2');
  assert.strictEqual(intel.flaggedFor('6.6.6.2', 'ip').level, 'medium');
});
