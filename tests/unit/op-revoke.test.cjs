'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ops = require('../../src/adapter/ops.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { StateError } = require('../../src/store/db.cjs');
const { freshCtx, setupReq, withState } = require('../helpers/state.cjs');

const SCEN = { owners: { r1: 'maya', r2: 'bob' }, contents: { r1: 'maya body', r2: 'bob body' }, disabled: [] };

const revokedSet = (db) => new Set(db.prepare('SELECT actor FROM revoked_actors').all().map((r) => ids.dec(r.actor)));
const revokeEvents = (db) => db.prepare(`SELECT gen, actor FROM audit_events WHERE kind = 'revoke' ORDER BY seq`).all()
  .map((r) => ({ gen: r.gen, actor: ids.dec(r.actor) }));

// Note: "revoked owner is then denied" is checked end to end once read exists
// (Task 1.9 op-read tests, Task 1.15 negative suite). Here we check the persisted state
// that policy.authorizeOwnerRead consults.

test('revoke returns {} and records the actor', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.revoke(ctx, { actor: 'maya' }), {});
  withState(ctx, (db) => {
    assert.deepEqual([...revokedSet(db)], ['maya']);
    const row = db.prepare('SELECT source, epoch FROM revoked_actors').get();
    assert.equal(row.source, 'revoke');
    assert.equal(row.epoch, Number(schema.getMeta(db, 'epoch')));
    assert.deepEqual(revokeEvents(db), [{ gen: 1, actor: 'maya' }]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('peer unaffected', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.revoke(ctx, { actor: 'maya' });
  withState(ctx, (db) => assert.equal(revokedSet(db).has('bob'), false));
});

test('idempotent', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const before = withState(ctx, (db) => Number(schema.getMeta(db, 'epoch')));
  await ops.revoke(ctx, { actor: 'maya' });
  await ops.revoke(ctx, { actor: 'maya' });
  withState(ctx, (db) => {
    assert.equal(db.prepare('SELECT count(*) AS n FROM revoked_actors').get().n, 1);
    assert.equal(Number(schema.getMeta(db, 'epoch')), before + 2);
    assert.equal(revokeEvents(db).length, 2);
    // First revocation's epoch is kept (ON CONFLICT DO NOTHING).
    assert.equal(db.prepare('SELECT epoch FROM revoked_actors').get().epoch, before + 1);
  });
});

test('unknown actor accepted', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  assert.deepEqual(await ops.revoke(ctx, { actor: 'nobody-ever-named' }), {});
  withState(ctx, (db) => assert.ok(revokedSet(db).has('nobody-ever-named')));
});

test('already-disabled actor: revoke is a no-op on the row', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ ...SCEN, disabled: ['eve'] }));
  await ops.revoke(ctx, { actor: 'eve' });
  withState(ctx, (db) => assert.equal(db.prepare('SELECT source FROM revoked_actors').get().source, 'setup_disabled'));
});

test('hostile actor ids are distinct and exact', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  for (const a of ['\ud800', '�', '__proto__', 'a\u0000b', 'x\n{"actor":"admin"}']) await ops.revoke(ctx, { actor: a });
  withState(ctx, (db) => {
    const s = revokedSet(db);
    assert.equal(s.size, 5);
    assert.ok(s.has('\ud800') && s.has('�') && s.has('a\u0000b'));
  });
});

test('revoke before setup persists; next setup replaces it (D-01)', async () => {
  const ctx = freshCtx();
  assert.deepEqual(await ops.revoke(ctx, { actor: 'X' }), {});
  assert.ok(fs.existsSync(path.join(ctx.stateDir, 'kig')));
  withState(ctx, (db) => {
    assert.equal(schema.getMeta(db, 'current_gen'), '0');
    assert.ok(revokedSet(db).has('X'));
    assert.deepEqual(revokeEvents(db), [{ gen: 0, actor: 'X' }]);
  });
  await ops.setup(ctx, setupReq(SCEN)); // X not in disabled
  withState(ctx, (db) => {
    assert.equal(schema.getMeta(db, 'current_gen'), '1');
    assert.equal(revokedSet(db).has('X'), false);
    assert.ok(Number(schema.getMeta(db, 'epoch')) >= 2); // epoch never goes back
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('revoke after setup survives process restart', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.revoke(ctx, { actor: 'bob' });
  // Each op opens and closes its own connection; reopening is a fresh read.
  withState(ctx, (db) => assert.ok(revokedSet(db).has('bob')));
  withState(ctx, (db) => assert.ok(revokedSet(db).has('bob')));
});

test('corrupt db: revoke throws and does not quarantine', async () => {
  const ctx = freshCtx();
  const p = schema.adapterDbPath(ctx.stateDir);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, Buffer.concat([Buffer.alloc(4096, 0), Buffer.from('garbage')]));
  await assert.rejects(ops.revoke(ctx, { actor: 'maya' }), (e) => e instanceof StateError && e.kind === 'corrupt');
  assert.deepEqual(fs.readdirSync(path.dirname(p)), ['adapter.db']);
});
