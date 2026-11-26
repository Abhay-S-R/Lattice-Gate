'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ops = require('../../src/adapter/ops.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { tx } = require('../../src/store/db.cjs');
const { freshCtx, setupReq, withState } = require('../helpers/state.cjs');

const SCEN = { owners: { r1: 'maya', r2: 'bob' }, contents: { r1: 'maya body', r2: 'bob body' }, disabled: [] };

// Until read (Task 1.9) lands, seed the access events a read would append.
function seedAccess(ctx, request_id, decision, actor = 'maya') {
  withState(ctx, (db) => tx(db, () => audit.append(db, {
    gen: ops.currentGen(db), kind: 'access', op: 'read', request_id, actor, asset: 'r1', decision,
    rule: decision === 'allow' ? 'owner_allowed' : 'not_owner',
  })));
}

const queryEvents = (db) => db.prepare(`SELECT gen, request_id, decision, rule FROM audit_events
  WHERE kind = 'audit_query' ORDER BY seq`).all()
  .map((r) => ({ gen: r.gen, request_id: ids.dec(r.request_id), decision: r.decision, rule: r.rule }));

test('matches denied read', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'r-deny', 'deny', 'bob');
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r-deny' }), { request_id: 'r-deny', decision: 'deny' });
});

test('matches allowed read and records a hit', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'r-ok', 'allow');
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r-ok' }), { request_id: 'r-ok', decision: 'allow' });
  withState(ctx, (db) => {
    assert.deepEqual(queryEvents(db), [{ gen: 1, request_id: 'r-ok', decision: null, rule: 'hit' }]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('latest of reused id', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'dup', 'allow');
  seedAccess(ctx, 'dup', 'deny', 'bob');
  assert.equal((await ops.audit(ctx, { request_id: 'dup' })).decision, 'deny');
});

test('unknown id deny and audit_lookup_miss recorded', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.audit(ctx, { request_id: 'never' }), { request_id: 'never', decision: 'deny' });
  withState(ctx, (db) => assert.deepEqual(queryEvents(db), [{ gen: 1, request_id: 'never', decision: null, rule: 'audit_lookup_miss' }]));
});

test('audit queries do not count as access decisions', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'q', 'allow');
  await ops.audit(ctx, { request_id: 'q' });
  await ops.audit(ctx, { request_id: 'q' });
  assert.equal((await ops.audit(ctx, { request_id: 'q' })).decision, 'allow');
});

test('previous generation id is unknown', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'r1', 'allow');
  assert.equal((await ops.audit(ctx, { request_id: 'r1' })).decision, 'allow');
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r1' }), { request_id: 'r1', decision: 'deny' });
});

test('exactly two keys, in order', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, 'k', 'allow');
  for (const id of ['k', 'missing']) {
    const res = await ops.audit(ctx, { request_id: id });
    assert.deepEqual(Object.keys(res), ['request_id', 'decision']);
  }
});

test('hostile request ids round-trip exactly and stay distinct', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  seedAccess(ctx, '\ud800', 'allow');
  assert.deepEqual(await ops.audit(ctx, { request_id: '\ud800' }), { request_id: '\ud800', decision: 'allow' });
  assert.equal((await ops.audit(ctx, { request_id: '�' })).decision, 'deny');
  assert.equal((await ops.audit(ctx, { request_id: '__proto__' })).request_id, '__proto__');
});

test('audit before setup: deny, no file created', async () => {
  const ctx = freshCtx();
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r1' }), { request_id: 'r1', decision: 'deny' });
  assert.equal(fs.existsSync(path.join(ctx.stateDir, 'kig')), false);
});

test('audit after revoke-only store (gen 0): deny', async () => {
  const ctx = freshCtx();
  await ops.revoke(ctx, { actor: 'x' });
  assert.deepEqual(await ops.audit(ctx, { request_id: 'r1' }), { request_id: 'r1', decision: 'deny' });
});
