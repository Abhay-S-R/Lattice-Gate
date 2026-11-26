'use strict';
// Task 2.4: kig alerts (features P0-10 operator view, architecture §5.7).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { runKig } = require('../helpers/run-kig.cjs');
const { freshCtx, setupReq } = require('../helpers/state.cjs');
const ops = require('../../src/adapter/ops.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const provider = require('../../src/crypto/provider.cjs');
const { safe, safeJson } = require('../../src/cli/text.cjs');

const ESC = '\u001b[31mRED\u001b[0m';
const C1 = 'a\u009bb';
const BIDI = 'user\u202egnp.exe';

/** Store in which every P0-10 rule has fired at least once. */
async function storeWithAllAlerts() {
  const ctx = freshCtx();
  const dbPath = schema.adapterDbPath(ctx.stateDir);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  fs.writeFileSync(dbPath, 'garbage, not a database '.repeat(300));           // → A-STATE-FAULT on setup
  await ops.setup(ctx, setupReq({ owners: { brief: 'maya', other: 'bob' }, contents: { brief: 'b1', other: 'b2' } }));
  await ops.read(ctx, { actor: 'maya', asset: 'other', request_id: 'x1' });   // A-CROSS-OWNER
  await ops.read(ctx, { actor: ESC, asset: C1, request_id: BIDI });           // A-HOSTILE-ID (+ cross-owner/unknown)
  await ops.recordInvalid(ctx, 'read', { actor: 'eve', request_id: 'bad1' }); // A-INVALID-INPUT
  await ops.protectedRead(ctx, { actor: 'bob', asset: 'other', challenge: 'c', publicKey: Buffer.alloc(1184, 0xff), request_id: null }); // A-INVALID-KEY
  await ops.revoke(ctx, { actor: 'maya' });
  for (let i = 0; i < 5; i++) await ops.read(ctx, { actor: 'maya', asset: 'brief', request_id: `rv${i}` }); // A-REVOKED-RETRY, A-BURST
  return ctx;
}

test('safe() escapes control, C1, bidi and lone surrogates; plain text stays readable', () => {
  assert.equal(safe('maya'), '"maya"');
  for (const s of [ESC, C1, BIDI, 'x\ud800y', 'l\u2028n', 'del\u007f']) {
    const out = safe(s);
    assert.doesNotMatch(out, /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/, JSON.stringify(out));
    assert.ok(out.isWellFormed());
    assert.equal(JSON.parse(out), s, 'escaped form must still decode to the original');
  }
});

test('safeJson output is valid JSON with the same value and no raw dangerous characters', () => {
  const v = [{ actor: ESC, asset: BIDI, n: 1 }];
  const out = safeJson(v);
  assert.deepEqual(JSON.parse(out), v);
  assert.doesNotMatch(out, /[\u001b\u009b\u202e]/);
});

test('kig alerts lists every P0-10 rule, newest first', async () => {
  const ctx = await storeWithAllAlerts();
  const r = runKig(['alerts', '--adapter', ctx.stateDir]);
  assert.equal(r.code, 0, r.stderr);
  for (const rule of ['A-STATE-FAULT', 'A-CROSS-OWNER', 'A-HOSTILE-ID', 'A-INVALID-INPUT', 'A-INVALID-KEY', 'A-REVOKED-RETRY', 'A-BURST']) {
    assert.match(r.stdout, new RegExp(`\\b${rule}\\b`), rule);
  }
  const seqs = r.stdout.trim().split('\n').map((l) => Number(/^#(\d+) /.exec(l)[1]));
  assert.deepEqual(seqs, [...seqs].sort((a, b) => b - a));
});

test('terminal output never contains raw escape, C1 or bidi characters', async () => {
  const ctx = await storeWithAllAlerts();
  const r = runKig(['alerts', '--adapter', ctx.stateDir]);
  assert.doesNotMatch(r.stdout, /[\u001b\u009b\u202e]/);
  assert.match(r.stdout, /\\u001b\[31mRED/); // shown, escaped
});

test('--json gives decodable records with the true identifiers', async () => {
  const ctx = await storeWithAllAlerts();
  const r = runKig(['alerts', '--adapter', ctx.stateDir, '--json']);
  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /[\u001b\u009b\u202e]/);
  const list = JSON.parse(r.stdout);
  assert.ok(Array.isArray(list) && list.length >= 7);
  for (const a of list) {
    for (const k of ['seq', 'time', 'rule', 'severity', 'reason']) assert.ok(k in a, k);
    assert.match(a.time, /^\d{4}-\d\d-\d\dT/);
  }
  const hostile = list.find((a) => a.rule === 'A-HOSTILE-ID' && a.request_id === BIDI);
  assert.ok(hostile, 'hostile-id alert keeps the exact request id');
  assert.equal(hostile.actor, ESC);
});

test('--limit keeps the newest N', async () => {
  const ctx = await storeWithAllAlerts();
  const all = runKig(['alerts', '--adapter', ctx.stateDir]).stdout.trim().split('\n');
  const two = runKig(['alerts', '--adapter', ctx.stateDir, '--limit', '2']).stdout.trim().split('\n');
  assert.deepEqual(two, all.slice(0, 2));
  assert.equal(runKig(['alerts', '--adapter', ctx.stateDir, '--limit', 'x']).code, 2);
  assert.equal(runKig(['alerts', '--adapter', ctx.stateDir, '--limit', '0']).code, 2);
});

test('store without alerts → "no alerts", exit 0', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ owners: { a: 'maya' }, contents: { a: 'x' } }));
  await ops.read(ctx, { actor: 'maya', asset: 'a', request_id: 'ok' });
  const r = runKig(['alerts', '--adapter', ctx.stateDir]);
  assert.equal(r.code, 0);
  assert.equal(r.stdout, 'no alerts\n');
});

test('tampered alert detail does not break or inject into the listing', async () => {
  const ctx = await storeWithAllAlerts();
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(schema.adapterDbPath(ctx.stateDir));
  db.exec('DROP TRIGGER audit_no_update');
  db.prepare("UPDATE audit_events SET detail = ? WHERE seq = (SELECT max(seq) FROM audit_events WHERE kind = 'alert')")
    .run('{"severity":"\u001b[2J","reason":5}');
  db.prepare("UPDATE audit_events SET detail = 'not json' WHERE seq = (SELECT min(seq) FROM audit_events WHERE kind = 'alert')").run();
  db.close();
  const r = runKig(['alerts', '--adapter', ctx.stateDir]);
  assert.equal(r.code, 0, r.stderr);
  assert.doesNotMatch(r.stdout, /\u001b/);
  void provider;
});
