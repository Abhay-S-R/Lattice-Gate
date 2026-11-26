'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ops = require('../../src/adapter/ops.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { freshCtx, setupReq, withState, stateContains } = require('../helpers/state.cjs');

const A = { owners: { r1: 'maya', r2: 'bob' }, contents: { r1: 'maya body', r2: 'bob body' }, disabled: ['eve'] };
const B = { owners: { s1: 'zed' }, contents: { s1: 'zed body' }, disabled: [] };

const assets = (db) => db.prepare('SELECT asset, owner, body FROM assets ORDER BY asset').all()
  .map((r) => ({ asset: ids.dec(r.asset), owner: r.owner && ids.dec(r.owner), body: r.body && ids.dec(r.body) }));
const revoked = (db) => db.prepare('SELECT actor, source, epoch FROM revoked_actors ORDER BY actor').all()
  .map((r) => ({ actor: ids.dec(r.actor), source: r.source, epoch: r.epoch }));
const events = (db) => db.prepare('SELECT gen, kind, rule, detail FROM audit_events ORDER BY seq').all()
  .map((r) => ({ gen: r.gen, kind: r.kind, rule: r.rule, detail: r.detail && JSON.parse(r.detail) }));

test('fresh setup ready', async () => {
  const ctx = freshCtx();
  assert.deepEqual(await ops.setup(ctx, setupReq(A)), { ready: true });
  withState(ctx, (db) => {
    assert.equal(schema.getMeta(db, 'current_gen'), '1');
    assert.deepEqual(assets(db), [
      { asset: 'r1', owner: 'maya', body: 'maya body' },
      { asset: 'r2', owner: 'bob', body: 'bob body' },
    ]);
    assert.deepEqual(events(db), [{ gen: 1, kind: 'setup', rule: null, detail: { assets: 2, disabled: 1 } }]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('second setup replaces data', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(A));
  await ops.setup(ctx, setupReq(B));
  withState(ctx, (db) => {
    assert.equal(schema.getMeta(db, 'current_gen'), '2');
    assert.deepEqual(assets(db), [{ asset: 's1', owner: 'zed', body: 'zed body' }]);
    assert.deepEqual(revoked(db), []);
    assert.deepEqual(events(db).map((e) => [e.gen, e.kind]), [[1, 'setup'], [2, 'setup']]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('disabled actors stored as revoked; epoch bumps once per setup', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ ...A, disabled: ['eve', 'mallory'] }));
  withState(ctx, (db) => {
    assert.deepEqual(revoked(db), [
      { actor: 'eve', source: 'setup_disabled', epoch: 1 },
      { actor: 'mallory', source: 'setup_disabled', epoch: 1 },
    ]);
    assert.equal(schema.getMeta(db, 'epoch'), '1');
  });
  await ops.setup(ctx, setupReq(B));
  withState(ctx, (db) => assert.equal(schema.getMeta(db, 'epoch'), '2'));
});

test('asset union: owner without contents and contents without owner are NULL', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ owners: { o: 'maya' }, contents: { c: 'body' } }));
  withState(ctx, (db) => assert.deepEqual(assets(db), [
    { asset: 'c', owner: null, body: 'body' },
    { asset: 'o', owner: 'maya', body: null },
  ]));
});

test('prototype keys and hostile ids are ordinary distinct assets', async () => {
  const ctx = freshCtx();
  const owners = JSON.parse('{"__proto__":"maya","constructor":"bob","\\ud800":"x","\\ufffd":"y"}');
  const contents = JSON.parse('{"__proto__":"p","constructor":"c","\\ud800":"s","\\ufffd":"f"}');
  await ops.setup(ctx, setupReq({ owners, contents }));
  withState(ctx, (db) => {
    const got = new Map(assets(db).map((r) => [r.asset, r]));
    assert.equal(got.size, 4);
    assert.equal(got.get('__proto__').owner, 'maya');
    assert.equal(got.get('constructor').body, 'c');
    assert.equal(got.get('\ud800').body, 's');
    assert.equal(got.get('�').body, 'f');
  });
});

test('empty setup is valid', async () => {
  const ctx = freshCtx();
  assert.deepEqual(await ops.setup(ctx, setupReq()), { ready: true });
  withState(ctx, (db) => assert.deepEqual(events(db)[0].detail, { assets: 0, disabled: 0 }));
});

test('corrupt db quarantined and replaced', async () => {
  const ctx = freshCtx();
  const p = schema.adapterDbPath(ctx.stateDir);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, Buffer.concat([Buffer.alloc(4096, 0), Buffer.from('garbage')]));
  assert.deepEqual(await ops.setup(ctx, setupReq(A)), { ready: true });
  const q = fs.readdirSync(path.dirname(p)).filter((f) => /^adapter\.db\.quarantine-\d+$/.test(f));
  assert.equal(q.length, 1);
  withState(ctx, (db) => {
    assert.deepEqual(events(db).map((e) => [e.kind, e.rule]), [['setup', null], ['alert', 'A-STATE-FAULT']]);
    assert.equal(events(db)[1].detail.reason, 'quarantined');
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('wrong schema version quarantined and replaced', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(A));
  withState(ctx, (db) => db.exec('PRAGMA user_version = 99'));
  assert.deepEqual(await ops.setup(ctx, setupReq(B)), { ready: true });
  withState(ctx, (db) => {
    assert.equal(schema.getMeta(db, 'current_gen'), '1'); // fresh store
    assert.deepEqual(assets(db).map((r) => r.asset), ['s1']);
  });
});

test('marker never persisted', async () => {
  const ctx = freshCtx();
  const marker = 'MARKER-' + Math.random().toString(36).slice(2);
  // validate.cjs drops key_material; ops must ignore it even if a req carried it.
  const req = { ...setupReq(A), key_material: marker };
  await ops.setup(ctx, req);
  assert.equal(stateContains(ctx.stateDir, marker), false);
});

test('state dir created with mode 0700', { skip: process.platform === 'win32' && 'POSIX modes' }, async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(A));
  assert.equal(fs.statSync(path.join(ctx.stateDir, 'kig')).mode & 0o777, 0o700);
});
