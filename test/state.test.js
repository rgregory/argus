'use strict';
// Acknowledgements, the allow list and the trend counts against a throwaway database.
// Run: node --test test/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'argus-test-'));
process.env.ARGUS_STATE = dir; process.env.ARGUS_DATA = dir;
const lib = p => require(path.join(__dirname, '..', 'app', 'lib', p));
const { Store } = lib('store');
const { FindingState, fingerprintV1 } = lib('findings');
const { Intel } = lib('intel');
const { Trends } = lib('trends');
const { Asn } = lib('asn');

const store = new Store(dir);
const fs_ = new FindingState(store);
const D = 86400e3;
const finding = (id, ev) => ({ id, sev: 'medium', area: 'Threat intel', title: id, evidence: ev });

test('acknowledgement holds while only times move, and expires when time-limited', () => {
  const f1 = finding('a', ['x', 'first seen 10/19/2026, 2:58:47 AM, last 10/22/2026, 5:56:45 PM, 44 hits']);
  fs_.annotate([f1]); fs_.ack(f1.id, f1.fp, f1.title, 'ok');
  const f2 = finding('a', ['x', 'first seen 10/19/2026, 2:58:47 AM, last 10/22/2026, 7:00:00 PM, 50 hits']);
  fs_.annotate([f2]); assert.ok(f2.acked);
  fs_.ack(f2.id, f2.fp, f2.title, 'week', 7);
  const f3 = finding('a', f2.evidence); fs_.annotate([f3]); assert.ok(f3.acked && f3.acked.until > Date.now());
  store.run('UPDATE finding_acks SET until = ? WHERE id = ?', Date.now() - 1000, 'a');
  const f4 = finding('a', f2.evidence); fs_.annotate([f4]); assert.ok(!f4.acked && f4.ackExpired);
});

test('acknowledgements written before 1.4.0 still match and are upgraded', () => {
  const ev = ['context: firefox → :443', 'seen 2026-10-01 10:00:00 from 1.2.3.4'];
  store.run('INSERT INTO finding_acks(id, fp, title, note, at) VALUES (?, ?, ?, ?, ?)', 'old', fingerprintV1({ evidence: ev }), 'old', '', Date.now());
  const f = finding('old', ev); fs_.annotate([f]);
  assert.ok(f.acked);
  assert.strictEqual(store.get('SELECT fp FROM finding_acks WHERE id = ?', 'old').fp, f.fp);
});

test('allow list: IP, CIDR, domain with subdomains, AS number', () => {
  const intel = new Intel(store, { defs: [], match: () => [] }, { match: () => null, findings: () => [] });
  const asn = new Asn(); asn.use(asn.parse('34.64.0.0\t34.127.255.255\t396982\tUS\tGOOGLE-CLOUD-PLATFORM\n'));
  intel.asn = asn;
  assert.strictEqual(intel.allowAdd('17.0.0.0/8'), '17.0.0.0/8');
  assert.strictEqual(intel.allowAdd('*.Mozilla.com.'), 'mozilla.com');
  assert.strictEqual(intel.allowAdd('as396982'), 'AS396982');
  assert.strictEqual(intel.allowAdd('1.2.3.4'), '1.2.3.4');
  assert.strictEqual(intel.allowAdd('not a thing!'), null);
  assert.strictEqual(intel.allowedBy('17.253.119.202', 'ip'), '17.0.0.0/8');
  assert.strictEqual(intel.allowedBy('push.services.mozilla.com', 'domain'), 'mozilla.com');
  assert.strictEqual(intel.allowedBy('34.107.243.93', 'ip'), 'AS396982');
  assert.strictEqual(intel.allowedBy('1.2.3.4', 'ip'), '1.2.3.4');
  assert.strictEqual(intel.allowedBy('5.5.5.5', 'ip'), '');
  assert.strictEqual(intel.allowedBy('notmozilla.com', 'domain'), '');
  intel.allowRemove('1.2.3.4');
  assert.strictEqual(intel.allowedBy('1.2.3.4', 'ip'), '');
  assert.strictEqual(intel.owner('34.107.243.93', 'ip'), 'AS396982 GOOGLE-CLOUD-PLATFORM (US)');
});

test('trend counts what was set aside', () => {
  const tr = new Trends(store);
  const now = Date.now();
  for (const [ts, rows] of [[now - D, [['h1', 'high', 'Access', 0], ['m1', 'medium', 'Threat intel', 1]]], [now - 60e3, [['h1', 'high', 'Access', 0], ['t1', 'low', 'Threat intel', 0], ['m1', 'medium', 'Threat intel', 1]]]]) {
    for (const [id, sev, area, acked] of rows) store.run('INSERT INTO finding_snap(ts, id, sev, area, title, fp, acked) VALUES (?, ?, ?, ?, ?, ?, ?)', ts, id, sev, area, id, 'x', acked);
  }
  const f = tr.findings(30);
  const i = f.days.length - 1;
  assert.strictEqual(f.total.high[i], 1);
  assert.strictEqual(f.total.acked[i], 1);
  assert.strictEqual(f.total.toned[i], 1);
});
