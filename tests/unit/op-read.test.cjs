'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ops = require('../../src/adapter/ops.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { freshCtx, setupReq, withState } = require('../helpers/state.cjs');

const SCEN = { owners: { brief: 'maya', other: 'peer' }, contents: { brief: 'demo note', other: 'peer note' }, disabled: [] };
const rd = (actor, asset, request_id) => ({ actor, asset, request_id });

const accessEvents = (db) => db.prepare(`SELECT op, request_id, actor, asset, decision, rule
  FROM audit_events WHERE kind = 'access' ORDER BY seq`).all()
  .map((r) => ({ ...r, request_id: ids.dec(r.request_id), actor: ids.dec(r.actor), asset: ids.dec(r.asset) }));

test('owner allowed exact body', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.read(ctx, rd('maya', 'brief', 'r01')), { decision: 'allow', body: 'demo note' });
  assert.deepEqual(await ops.read(ctx, rd('peer', 'other', 'r02')), { decision: 'allow', body: 'peer note' });
});

test('unicode body', async () => {
  const ctx = freshCtx();
  const bodies = { u: 'ünïcode ✓ 🙂', s: 'a\ud800b', e: '', n: 'x\u0000y' };
  await ops.setup(ctx, setupReq({ owners: { u: 'maya', s: 'maya', e: 'maya', n: 'maya' }, contents: bodies }));
  for (const [asset, body] of Object.entries(bodies)) {
    assert.deepEqual(await ops.read(ctx, rd('maya', asset, `r-${asset}`)), { decision: 'allow', body });
  }
});

test('wrong owner denied', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.read(ctx, rd('maya', 'other', 'r01')), { decision: 'deny' });
});

test('deny response has exactly one key', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ ...SCEN, disabled: ['peer'] }));
  for (const req of [rd('maya', 'other', 'a'), rd('maya', 'nope', 'b'), rd('peer', 'other', 'c')]) {
    const res = await ops.read(ctx, req);
    assert.deepEqual(Object.keys(res), ['decision']);
    assert.equal(res.decision, 'deny');
  }
});

test('revoked owner then denied', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.revoke(ctx, { actor: 'maya' });
  assert.deepEqual(await ops.read(ctx, rd('maya', 'brief', 'r02')), { decision: 'deny' });
  assert.deepEqual(await ops.read(ctx, rd('peer', 'other', 'r03')), { decision: 'allow', body: 'peer note' });
});

test('read before setup denies and creates no file', async () => {
  const ctx = freshCtx();
  assert.deepEqual(await ops.read(ctx, rd('maya', 'brief', 'r01')), { decision: 'deny' });
  assert.deepEqual(fs.readdirSync(ctx.stateDir), []);
});

test('read in generation 0 (revoke before setup) denies without writing', async () => {
  const ctx = freshCtx();
  await ops.revoke(ctx, { actor: 'x' });
  const before = withState(ctx, (db) => audit.verifyChain(db).count);
  assert.deepEqual(await ops.read(ctx, rd('x', 'a', 'r1')), { decision: 'deny' });
  withState(ctx, (db) => assert.equal(audit.verifyChain(db).count, before));
});

test('every read appends one access event with rule', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ ...SCEN, disabled: ['eve'] }));
  await ops.read(ctx, rd('maya', 'brief', 'r1'));
  await ops.read(ctx, rd('maya', 'other', 'r2'));
  await ops.read(ctx, rd('maya', 'missing', 'r3'));
  await ops.read(ctx, rd('eve', 'brief', 'r4'));
  withState(ctx, (db) => {
    assert.deepEqual(accessEvents(db), [
      { op: 'read', request_id: 'r1', actor: 'maya', asset: 'brief', decision: 'allow', rule: 'owner_allowed' },
      { op: 'read', request_id: 'r2', actor: 'maya', asset: 'other', decision: 'deny', rule: 'not_owner' },
      { op: 'read', request_id: 'r3', actor: 'maya', asset: 'missing', decision: 'deny', rule: 'unknown_asset' },
      { op: 'read', request_id: 'r4', actor: 'eve', asset: 'brief', decision: 'deny', rule: 'actor_revoked' },
    ]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('audit sees the read decision', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.read(ctx, rd('maya', 'brief', 'r01'));
  await ops.revoke(ctx, { actor: 'maya' });
  await ops.read(ctx, rd('maya', 'brief', 'r02'));
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r01' }), { request_id: 'r01', decision: 'allow' });
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r02' }), { request_id: 'r02', decision: 'deny' });
});

test('body is never written to the audit log', async () => {
  const ctx = freshCtx();
  const body = 'BODY-MARKER-31c9';
  await ops.setup(ctx, setupReq({ owners: { a: 'maya' }, contents: { a: body } }));
  await ops.read(ctx, rd('maya', 'a', 'r1'));
  withState(ctx, (db) => {
    const rows = JSON.stringify(db.prepare('SELECT kind, op, request_id, actor, asset, decision, rule, detail FROM audit_events').all());
    assert.ok(!rows.includes(body));
  });
});
