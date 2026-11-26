'use strict';
// Crash safety (Task 1.15, review focus 3): SIGKILL an adapter holding an open
// write transaction mid-revoke. Expect: nothing acknowledged, no partial row,
// a valid chain, and the store keeps working.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { runAdapter, ROOT, ENTRY } = require('../helpers/run-adapter.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { withState } = require('../helpers/state.cjs');

const T = { timeout: 600000, skip: process.platform === 'win32' && 'needs POSIX signals' };

/** Start a revoke that hangs inside its transaction; resolve once it says so. */
function startHangingRevoke(dir, actor) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, NODE_ENV: 'test', KIG_TEST_HANG_IN_TX: '1', TRACK4_STATE_DIR: dir, TMPDIR: dir };
    delete env.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, [ENTRY], { cwd: ROOT, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => {
      err += d;
      if (err.includes('KIG_TEST_IN_TX')) resolve({ child, stdout: () => out });
    });
    child.on('error', reject);
    child.on('close', (code) => reject(new Error(`child exited early (${code}): ${err}`)));
    child.stdin.end(JSON.stringify({ op: 'revoke', actor }));
  });
}

const killed = (child) => new Promise((resolve) => {
  child.removeAllListeners('close');
  child.on('close', (code, signal) => resolve({ code, signal }));
  child.kill('SIGKILL');
});

const ok = (res) => { assert.equal(res.code, 0, res.stderr); assert.equal(res.stderr, ''); return res.json; };

test('SIGKILL inside a revoke transaction leaves no trace and the store keeps working', T, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-kill-'));
  ok(await runAdapter(dir, { op: 'setup', owners: { a: 'maya', b: 'peer' }, contents: { a: 'A', b: 'B' }, disabled: [] }));
  ok(await runAdapter(dir, { op: 'read', actor: 'maya', asset: 'a', request_id: 'r1' }));
  const before = withState({ stateDir: dir }, (db) => audit.verifyChain(db));
  assert.equal(before.ok, true);

  const { child, stdout } = await startHangingRevoke(dir, 'maya');
  const { signal } = await killed(child);
  assert.equal(signal, 'SIGKILL');
  assert.equal(stdout(), '', 'an unpersisted revoke was acknowledged');

  withState({ stateDir: dir }, (db) => {
    assert.equal(db.prepare('SELECT count(*) AS n FROM revoked_actors').get().n, 0, 'partial revoke row');
    const after = audit.verifyChain(db);
    assert.equal(after.ok, true);
    assert.equal(after.count, before.count, 'partial audit event');
    assert.ok(after.head.equals(before.head));
  });

  // The revoke never happened, so maya still reads; the next real revoke works.
  assert.deepEqual(ok(await runAdapter(dir, { op: 'read', actor: 'maya', asset: 'a', request_id: 'r2' })), { decision: 'allow', body: 'A' });
  assert.deepEqual(ok(await runAdapter(dir, { op: 'revoke', actor: 'maya' })), {});
  assert.deepEqual(ok(await runAdapter(dir, { op: 'read', actor: 'maya', asset: 'a', request_id: 'r3' })), { decision: 'deny' });
  assert.deepEqual(ok(await runAdapter(dir, { op: 'audit', request_id: 'r3' })), { request_id: 'r3', decision: 'deny' });
  withState({ stateDir: dir }, (db) => {
    assert.deepEqual(db.prepare('SELECT actor FROM revoked_actors').all().map((r) => ids.dec(r.actor)), ['maya']);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('SIGKILL inside the very first revoke (cold store) leaves a usable store', T, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-kill-'));
  const { child } = await startHangingRevoke(dir, 'x');
  await killed(child);
  // The store file exists (created before the tx), but holds no revocation.
  assert.deepEqual(ok(await runAdapter(dir, { op: 'revoke', actor: 'y' })), {});
  withState({ stateDir: dir }, (db) => {
    assert.deepEqual(db.prepare('SELECT actor FROM revoked_actors').all().map((r) => ids.dec(r.actor)), ['y']);
    assert.equal(audit.verifyChain(db).ok, true);
  });
  assert.deepEqual(ok(await runAdapter(dir, { op: 'setup', owners: { a: 'x' }, contents: { a: 'A' }, disabled: [] })), { ready: true });
  assert.deepEqual(ok(await runAdapter(dir, { op: 'read', actor: 'x', asset: 'a', request_id: 'r' })), { decision: 'allow', body: 'A' });
});

test('the hang hook is inert outside NODE_ENV=test', T, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-kill-'));
  const res = await runAdapter(dir, { op: 'revoke', actor: 'x' }, { env: { NODE_ENV: 'production', KIG_TEST_HANG_IN_TX: '1' }, timeoutMs: 60000 });
  assert.equal(res.timedOut, false);
  assert.deepEqual(ok(res), {});
});
