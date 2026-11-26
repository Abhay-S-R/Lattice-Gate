'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const ops = require('../../src/adapter/ops.cjs');
const alerts = require('../../src/core/alerts.cjs');
const audit = require('../../src/core/audit.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const ids = require('../../src/core/ids.cjs');
const p = require('../../src/crypto/provider.cjs');
const { freshCtx, setupReq, withState } = require('../helpers/state.cjs');

const SCEN = { owners: { brief: 'maya', other: 'peer' }, contents: { brief: 'demo note', other: 'peer note' }, disabled: [] };
const rd = (actor, asset, request_id) => ({ actor, asset, request_id });

const alertRows = (ctx) => withState(ctx, (db) => db.prepare(
  `SELECT rule, actor, detail FROM audit_events WHERE kind = 'alert' ORDER BY seq`).all()
  .map((r) => ({ rule: r.rule, actor: r.actor === null ? null : ids.dec(r.actor), detail: JSON.parse(r.detail) })));
const rules = (ctx) => alertRows(ctx).map((a) => a.rule);

function memDb() {
  const db = new DatabaseSync(':memory:');
  schema.init(db);
  return db;
}

// ---- evaluate (pure rules) ----

test('evaluate: each rule and its severity', () => {
  const db = memDb();
  const ev = (c) => alerts.evaluate(db, 1, { hostile: [], ...c }).map((a) => [a.rule, a.severity]);
  assert.deepEqual(ev({ op: 'read', rule: 'actor_revoked', decision: 'deny' }), [['A-REVOKED-RETRY', 'medium']]);
  assert.deepEqual(ev({ op: 'protected_read', rule: 'actor_revoked', decision: 'deny' }), [['A-REVOKED-RETRY', 'medium']]);
  assert.deepEqual(ev({ op: 'read', rule: 'not_owner', decision: 'deny' }), [['A-CROSS-OWNER', 'low']]);
  assert.deepEqual(ev({ op: 'read', invalidInput: true }), [['A-INVALID-INPUT', 'low']]);
  assert.deepEqual(ev({ op: 'protected_read', invalidKey: true }), [['A-INVALID-KEY', 'medium']]);
  assert.deepEqual(ev({ op: 'revoke', hostile: ['__proto__'] }), [['A-HOSTILE-ID', 'info']]);
  assert.deepEqual(ev({ op: 'read', rule: 'owner_allowed', decision: 'allow' }), []);
  assert.deepEqual(ev({ op: 'read', rule: 'unknown_asset', decision: 'deny' }), []);
  for (const a of alerts.evaluate(db, 1, { op: 'read', rule: 'not_owner', hostile: ['x\n'] })) {
    assert.equal(typeof a.reason, 'string');
  }
});

// ---- one test per rule firing, through the ops ----

test('A-REVOKED-RETRY on read and protected_read by a revoked actor', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ ...SCEN, disabled: ['eve'] }));
  await ops.revoke(ctx, { actor: 'maya' });
  await ops.read(ctx, rd('maya', 'brief', 'r1'));
  const { publicKey } = p.kemGenerate();
  const raw = await p.kemExportRawPublic(publicKey);
  await ops.protectedRead(ctx, { actor: 'eve', asset: 'brief', challenge: 'c', publicKey: raw, request_id: null });
  assert.deepEqual(rules(ctx), ['A-REVOKED-RETRY', 'A-REVOKED-RETRY']);
  assert.deepEqual(alertRows(ctx).map((a) => a.actor), ['maya', 'eve']);
});

test('A-CROSS-OWNER on reading an existing asset of another owner', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.read(ctx, rd('maya', 'other', 'r1'));
  await ops.read(ctx, rd('maya', 'no-such-asset', 'r2')); // unknown asset is not cross-owner
  assert.deepEqual(rules(ctx), ['A-CROSS-OWNER']);
});

test('A-INVALID-INPUT recorded when a store exists', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.recordInvalid(ctx, 'read', { request_id: 'bad-1' });
  assert.deepEqual(rules(ctx), ['A-INVALID-INPUT']);
  // the invalid read is a recorded deny, so audit can answer for it
  assert.deepEqual(await ops.audit(ctx, { request_id: 'bad-1' }), { request_id: 'bad-1', decision: 'deny' });
});

test('A-INVALID-INPUT: no store → nothing created', async () => {
  const fs = require('node:fs');
  const ctx = freshCtx();
  await ops.recordInvalid(ctx, 'read', { request_id: 'x' });
  assert.deepEqual(fs.readdirSync(ctx.stateDir), []);
});

test('A-INVALID-INPUT is never recorded for setup (state untouched)', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const before = withState(ctx, (db) => audit.verifyChain(db).count);
  await ops.recordInvalid(ctx, 'setup', {});
  assert.equal(withState(ctx, (db) => audit.verifyChain(db).count), before);
});

test('A-INVALID-KEY on a key that fails the FIPS 203 check', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.protectedRead(ctx, { actor: 'maya', asset: 'brief', challenge: 'c', publicKey: Buffer.alloc(1184, 0xff), request_id: null });
  assert.deepEqual(rules(ctx), ['A-INVALID-KEY']);
});

test('A-HOSTILE-ID on any op; the id is not copied into detail', async () => {
  const ctx = freshCtx();
  const hostile = 'x\n{"actor":"admin"}';
  // JSON.parse, as requests arrive: a '__proto__' key in an object literal would set the prototype instead.
  await ops.setup(ctx, setupReq(JSON.parse('{"owners":{"__proto__":"maya"},"contents":{"__proto__":"b"}}')));
  await ops.read(ctx, rd('maya', '__proto__', hostile));
  await ops.revoke(ctx, { actor: '../etc' });
  await ops.audit(ctx, { request_id: 'a\u0000b' });
  assert.deepEqual(rules(ctx), ['A-HOSTILE-ID', 'A-HOSTILE-ID', 'A-HOSTILE-ID', 'A-HOSTILE-ID']);
  for (const a of alertRows(ctx)) {
    assert.deepEqual(Object.keys(a.detail).sort(), ['reason', 'severity']);
    assert.ok(!JSON.stringify(a.detail).includes('admin'));
  }
});

test('burst fires once at the fifth deny', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ owners: { a: 'owner' }, contents: { a: 'x' } }));
  for (let i = 1; i <= 4; i++) await ops.read(ctx, rd('mallory', 'missing', `r${i}`));
  assert.deepEqual(rules(ctx), []);
  await ops.read(ctx, rd('mallory', 'missing', 'r5'));
  assert.deepEqual(rules(ctx), ['A-BURST']);
  assert.equal(alertRows(ctx)[0].detail.severity, 'high');
  for (let i = 6; i <= 8; i++) await ops.read(ctx, rd('mallory', 'missing', `r${i}`));
  assert.deepEqual(rules(ctx), ['A-BURST']);
  // other actors have their own count
  for (let i = 1; i <= 4; i++) await ops.read(ctx, rd('trent', 'missing', `t${i}`));
  assert.deepEqual(rules(ctx), ['A-BURST']);
});

test('burst ignores denies outside the window', () => {
  const db = memDb();
  const realNow = Date.now;
  try {
    db.exec('BEGIN IMMEDIATE');
    Date.now = () => 1_000_000;
    for (let i = 0; i < 4; i++) audit.append(db, { gen: 1, kind: 'access', op: 'read', actor: 'm', decision: 'deny', rule: 'x' });
    Date.now = () => 1_000_000 + 60_001;
    audit.append(db, { gen: 1, kind: 'access', op: 'read', actor: 'm', decision: 'deny', rule: 'x' });
    assert.deepEqual(alerts.evaluate(db, 1, { op: 'read', actor: 'm', decision: 'deny', rule: 'x', hostile: [] }), []);
    db.exec('COMMIT');
  } finally {
    Date.now = realNow;
  }
});

// ---- no noise, no effect on responses ----

test('happy path no alerts', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.read(ctx, rd('maya', 'brief', 'r1'));
  await ops.read(ctx, rd('peer', 'other', 'r2'));
  await ops.revoke(ctx, { actor: 'someone' });
  await ops.audit(ctx, { request_id: 'r1' });
  assert.deepEqual(rules(ctx), []);
});

async function scenario() {
  const ctx = freshCtx();
  const out = [];
  out.push(await ops.setup(ctx, setupReq({ ...SCEN, disabled: ['eve'] })));
  out.push(await ops.read(ctx, rd('maya', 'brief', 'r1')));
  out.push(await ops.read(ctx, rd('maya', 'other', 'r2')));
  out.push(await ops.revoke(ctx, { actor: 'maya' }));
  for (let i = 0; i < 6; i++) out.push(await ops.read(ctx, rd('maya', 'brief', `x${i}`)));
  out.push(await ops.read(ctx, rd('__proto__', 'brief', 'r3')));
  out.push(await ops.audit(ctx, { request_id: 'x5' }));
  out.push(await ops.read(ctx, rd('peer', 'other', 'r4')));
  return { out, ctx };
}

test('responses identical with alerts on', async () => {
  const on = await scenario();
  assert.ok(rules(on.ctx).length > 0);
  const real = alerts.evaluate;
  alerts.evaluate = () => [];
  let off;
  try { off = await scenario(); } finally { alerts.evaluate = real; }
  assert.deepEqual(rules(off.ctx), []);
  assert.deepEqual(JSON.stringify(on.out), JSON.stringify(off.out));
});

test('a failing alert rule never changes the response or the decision record', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const real = alerts.evaluate;
  alerts.evaluate = () => { throw new Error('boom'); };
  try {
    assert.deepEqual(await ops.read(ctx, rd('maya', 'brief', 'r1')), { decision: 'allow', body: 'demo note' });
    assert.deepEqual(await ops.revoke(ctx, { actor: 'maya' }), {});
  } finally {
    alerts.evaluate = real;
  }
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r1' }), { request_id: 'r1', decision: 'allow' });
  withState(ctx, (db) => assert.equal(audit.verifyChain(db).ok, true));
});

test('chain verifies with alerts interleaved', async () => {
  const { ctx } = await scenario();
  withState(ctx, (db) => assert.equal(audit.verifyChain(db).ok, true));
});
