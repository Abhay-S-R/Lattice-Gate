'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb, tx } = require('../../src/store/db.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { sha256 } = require('../../src/crypto/provider.cjs');
const { encode } = require('../../src/core/encoding.cjs');

function fresh() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-audit-'));
  return openDb(path.join(dir, 'adapter.db'), { create: true, version: schema.VERSION, init: schema.init });
}

const access = (db, gen, request_id, actor, decision, extra = {}) =>
  tx(db, () => audit.append(db, {
    gen, kind: 'access', op: 'read', request_id, actor, asset: 'a1', decision,
    rule: decision === 'allow' ? 'owner_allowed' : 'not_owner', ...extra,
  }));

function chainOf(n) {
  const db = fresh();
  for (let i = 1; i <= n; i++) access(db, 1, `r${i}`, i % 2 ? 'maya' : 'bob', i % 3 ? 'allow' : 'deny');
  return db;
}

test('empty chain verifies with genesis head', () => {
  const db = fresh();
  const genesis = sha256(encode('kig/v1/genesis', [schema.getMeta(db, 'db_id')]));
  const r = audit.verifyChain(db);
  assert.equal(r.ok, true);
  assert.equal(r.count, 0);
  assert.deepEqual(r.head, genesis);
  db.close();
});

test('first event links to genesis; seq starts at 1', () => {
  const db = fresh();
  const genesis = sha256(encode('kig/v1/genesis', [schema.getMeta(db, 'db_id')]));
  const { seq, hash } = tx(db, () => audit.append(db, { gen: 0, kind: 'revoke', actor: 'x' }));
  assert.equal(seq, 1);
  const row = db.prepare('SELECT prev_hash, hash FROM audit_events WHERE seq = 1').get();
  assert.deepEqual(Buffer.from(row.prev_hash), genesis);
  assert.deepEqual(Buffer.from(row.hash), hash);
  db.close();
});

test('chain of 50 verifies', () => {
  const db = chainOf(50);
  const last = db.prepare('SELECT hash FROM audit_events WHERE seq = 50').get();
  const r = audit.verifyChain(db);
  assert.equal(r.ok, true);
  assert.equal(r.count, 50);
  assert.deepEqual(r.head, Buffer.from(last.hash));
  db.close();
});

test('append outside a transaction throws', () => {
  const db = fresh();
  assert.throws(() => audit.append(db, { gen: 0, kind: 'setup' }), /transaction/);
  db.close();
});

test('edited row detected', () => {
  const db = chainOf(50);
  db.exec('DROP TRIGGER audit_no_update');
  db.exec(`UPDATE audit_events SET decision = CASE decision WHEN 'allow' THEN 'deny' ELSE 'allow' END WHERE seq = 20`);
  assert.deepEqual(audit.verifyChain(db), { ok: false, seq: 20, reason: 'content_edit' });
  db.close();
});

test('edited timestamp detected', () => {
  const db = chainOf(10);
  db.exec('DROP TRIGGER audit_no_update');
  db.exec('UPDATE audit_events SET ts_ms = ts_ms + 1 WHERE seq = 4');
  assert.deepEqual(audit.verifyChain(db), { ok: false, seq: 4, reason: 'content_edit' });
  db.close();
});

test('edited row with recomputed hash breaks the next link', () => {
  const db = chainOf(10);
  db.exec('DROP TRIGGER audit_no_update');
  db.exec(`UPDATE audit_events SET hash = x'00' WHERE seq = 5`);
  const r = audit.verifyChain(db);
  assert.equal(r.ok, false);
  assert.equal(r.seq, 5);
  db.close();
});

test('deleted row detected', () => {
  const db = chainOf(50);
  db.exec('DROP TRIGGER audit_no_delete');
  db.exec('DELETE FROM audit_events WHERE seq = 20');
  assert.deepEqual(audit.verifyChain(db), { ok: false, seq: 20, reason: 'missing_or_reordered' });
  db.close();
});

test('reordered rows detected', () => {
  const db = chainOf(10);
  db.exec('DROP TRIGGER audit_no_update');
  // Swap seq 3 and 4 (via a temporary seq).
  db.exec('UPDATE audit_events SET seq = 1000 WHERE seq = 3');
  db.exec('UPDATE audit_events SET seq = 3 WHERE seq = 4');
  db.exec('UPDATE audit_events SET seq = 4 WHERE seq = 1000');
  const r = audit.verifyChain(db);
  assert.equal(r.ok, false);
  assert.equal(r.seq, 3);
  assert.equal(r.reason, 'missing_or_reordered');
  db.close();
});

test('injection actor is one event', () => {
  const db = fresh();
  const actor = 'x\n{"actor":"admin","decision":"allow"}';
  access(db, 1, 'r1', actor, 'deny');
  const rows = db.prepare('SELECT actor, decision FROM audit_events').all();
  assert.equal(rows.length, 1);
  assert.equal(ids.dec(rows[0].actor), actor);
  assert.equal(rows[0].decision, 'deny');
  assert.equal(audit.verifyChain(db).ok, true);
  db.close();
});

test('client strings stored D-04 encoded; detail is JSON', () => {
  const db = fresh();
  tx(db, () => audit.append(db, {
    gen: 1, kind: 'access', op: 'read', request_id: '\ud800', actor: '__proto__', asset: 'a\u0000b',
    decision: 'deny', rule: 'not_owner', detail: { n: 1 },
  }));
  const row = db.prepare('SELECT * FROM audit_events').get();
  assert.equal(ids.dec(row.request_id), '\ud800');
  assert.equal(ids.dec(row.actor), '__proto__');
  assert.equal(ids.dec(row.asset), 'a\u0000b');
  assert.equal(row.kind, 'access');
  assert.equal(row.op, 'read');
  assert.deepEqual(JSON.parse(row.detail), { n: 1 });
  assert.equal(audit.verifyChain(db).ok, true);
  db.close();
});

test('missing optional fields stored as NULL', () => {
  const db = fresh();
  tx(db, () => audit.append(db, { gen: 0, kind: 'setup' }));
  const row = db.prepare('SELECT op, request_id, actor, asset, decision, rule, detail FROM audit_events').get();
  assert.deepEqual({ ...row }, { op: null, request_id: null, actor: null, asset: null, decision: null, rule: null, detail: null });
  db.close();
});

test('latestAccessDecision returns last of reused id', () => {
  const db = fresh();
  access(db, 1, 'r1', 'maya', 'allow');
  access(db, 1, 'r1', 'bob', 'deny');
  tx(db, () => audit.append(db, { gen: 1, kind: 'audit_query', request_id: 'r1', rule: 'hit' }));
  assert.equal(audit.latestAccessDecision(db, 1, 'r1'), 'deny');
  assert.equal(audit.latestAccessDecision(db, 1, 'nope'), null);
  db.close();
});

test('scoped to generation', () => {
  const db = fresh();
  access(db, 1, 'r1', 'maya', 'allow');
  assert.equal(audit.latestAccessDecision(db, 1, 'r1'), 'allow');
  assert.equal(audit.latestAccessDecision(db, 2, 'r1'), null);
  access(db, 2, 'r1', 'bob', 'deny');
  assert.equal(audit.latestAccessDecision(db, 1, 'r1'), 'allow');
  assert.equal(audit.latestAccessDecision(db, 2, 'r1'), 'deny');
  db.close();
});

test('countRecentDenies', () => {
  const db = fresh();
  const now = Date.now();
  for (let i = 0; i < 3; i++) access(db, 1, `r${i}`, 'eve', 'deny');
  access(db, 1, 'rx', 'eve', 'allow');
  access(db, 1, 'ry', 'bob', 'deny');
  access(db, 2, 'rz', 'eve', 'deny');
  assert.equal(audit.countRecentDenies(db, 1, 'eve', now - 60000), 3);
  assert.equal(audit.countRecentDenies(db, 1, 'eve', Date.now() + 1000), 0);
  assert.equal(audit.countRecentDenies(db, 2, 'eve', 0), 1);
  db.close();
});
