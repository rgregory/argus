'use strict';
// Acknowledgements hold while a finding's fingerprint is unchanged, so anything in
// the evidence that drifts on its own (timestamps, ages, repeat counters) must be
// normalised away, in every format the code writes it. Run: node --test test/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const lib = p => require(path.join(__dirname, '..', 'app', 'lib', p));
const { normLine, fingerprint, fingerprintV1 } = lib('findings');
const { fmtTs } = lib('engine');

const T1 = new Date('2026-10-19T02:58:47Z'), T2 = new Date('2026-10-22T21:56:45Z');
const H = 3600e3;
const healthAgo = ms => ms < H ? `${Math.round(ms / 60e3)} min` : ms < 48 * H ? `${Math.round(ms / H)} h` : `${Math.round(ms / 86400e3)} days`;

// Every way the code puts a time into evidence, written at two different times.
const producers = {
  'engine.fmtTs': t => fmtTs(t),
  'toLocaleString()': t => t.toLocaleString(),
  'toLocaleString en-US': t => t.toLocaleString('en-US'),
  'toISOString': t => t.toISOString(),
  'ISO day': t => t.toISOString().slice(0, 10),
  'locale time': t => t.toLocaleTimeString('en-US'),
};
for (const [name, fmt] of Object.entries(producers)) {
  for (const shape of [x => x, x => `last update ${x}`, x => `${x} first run · /Applications/Foo.app`, x => `seen ${x} from 10.0.0.2`]) {
    test(`stable across time: ${name} in "${shape('…')}"`, () => assert.strictEqual(normLine(shape(fmt(T1))), normLine(shape(fmt(T2)))));
  }
}

const pairs = [
  ['first seen 10/19/2026, 2:58:47 AM, last 10/22/2026, 5:56:45 PM, 44 hits', 'first seen 10/19/2026, 2:58:47 AM, last 10/22/2026, 6:51:02 PM, 47 hits'],
  ['AbuseIPDB: confidence 95%, 174 reports; Google LLC (US)', 'AbuseIPDB: confidence 96%, 181 reports; Google LLC (US)'],
  ['AlienVault OTX: 19 OTX pulses: IOC Records', 'AlienVault OTX: 23 OTX pulses: IOC Records'],
  ['sshd: Failed password for root from 1.2.3.4 (×12)', 'sshd: Failed password for root from 1.2.3.4 (×340)'],
  ['XProtect last update 2026-10-01 03:00:00 (4 d ago): XProtect 5310', 'XProtect last update 2026-10-01 03:00:00 (21 d ago): XProtect 5310'],
  [`Host collector last ran ${healthAgo(20 * 60e3)} ago`, `Host collector last ran ${healthAgo(5 * H)} ago`],
  ['1,589 connections to 34.107.243.93', '2,004 connections to 34.107.243.93'],
];
for (const [a, b] of pairs) test(`stable: ${a}`, () => assert.strictEqual(normLine(a), normLine(b)));

// Real changes must still change the fingerprint.
const different = [
  ['context: firefox → :443', 'context: curl → :443'],
  ['AbuseIPDB: confidence 95%, 174 reports; Google LLC (US)', 'AbuseIPDB: confidence 95%, 174 reports; Hetzner Online GmbH (DE)'],
  ['/Library/LaunchDaemons/com.foo.plist → /usr/local/bin/foo', '/Library/LaunchDaemons/com.foo.plist → /tmp/foo'],
  ['port 22 open on 0.0.0.0', 'port 2222 open on 0.0.0.0'],
  ['CVE-2026-1234 in openssl 3.0.1', 'CVE-2026-1235 in openssl 3.0.1'],
];
for (const [a, b] of different) test(`still distinct: ${a} / ${b}`, () => assert.notStrictEqual(normLine(a), normLine(b)));

test('whole findings: same fingerprint when only times and counts move', () => {
  const ev = t => ({ evidence: ['AbuseIPDB: confidence 95%, 174 reports; Google LLC (US)', 'context: firefox → :443', `first seen ${T1.toLocaleString()}, last ${t.toLocaleString()}, 44 hits`] });
  assert.strictEqual(fingerprint(ev(T1)), fingerprint(ev(T2)));
});
test('order and duplicates of evidence lines do not matter', () => {
  assert.strictEqual(fingerprint({ evidence: ['a', 'b', 'a'] }), fingerprint({ evidence: ['b', 'a'] }));
});
test('the version 1 fingerprint is still computed (pre-1.4.0 acknowledgements)', () => {
  assert.match(fingerprintV1({ evidence: ['x'] }), /^[0-9a-f]{16}$/);
});

// Guard: any new way of writing a time into evidence should be added to `producers` above.
test('no unknown time formatter feeds evidence', () => {
  const fs = require('node:fs'), dir = path.join(__dirname, '..', 'app', 'lib');
  const suspicious = /toLocaleDateString\(|toUTCString\(|toDateString\(|toTimeString\(|Intl\.DateTimeFormat/;
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.js'))) {
    fs.readFileSync(path.join(dir, f), 'utf8').split('\n').forEach((l, i) => {
      if (/evidence/.test(l) && suspicious.test(l)) assert.fail(`${f}:${i + 1} writes a date format the fingerprint test doesn't cover`);
    });
  }
});
