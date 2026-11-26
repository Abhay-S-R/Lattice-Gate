'use strict';
// Adapter contract through real processes (Task 1.14): every call is a fresh
// `node track4_service.cjs`, as the worker runs it.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { runAdapter, FAIL_LINE } = require('../helpers/run-adapter.cjs');
const p = require('../../src/crypto/provider.cjs');

const T = { timeout: 300000 }; // generous: arm64 is emulated in the judge replica
const hex = (n) => p.random(n).toString('hex');
const freshDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kig-contract-'));

/** Success shape: exit 0, stderr empty, stdout exactly one JSON object + '\n'. */
function ok(res) {
  assert.equal(res.timedOut, false, 'timed out');
  assert.equal(res.code, 0, `exit ${res.code} stderr=${JSON.stringify(res.stderr)}`);
  assert.equal(res.stderr, '');
  assert.ok(res.stdout.endsWith('\n'));
  assert.equal(res.stdout.indexOf('\n'), res.stdout.length - 1, 'exactly one line');
  assert.ok(res.json && typeof res.json === 'object' && !Array.isArray(res.json));
  return res.json;
}
const call = async (dir, req) => ok(await runAdapter(dir, req));

test('validator scenario', T, async () => {
  // Mirrors toolkit validate.py: random IDs, lost-device revoke, audit, fresh rerun.
  const [actor, peer, disabled] = [hex(16), hex(16), hex(16)];
  const [asset, other] = [hex(12), hex(12)];
  const [body, peerBody, marker] = [hex(24), hex(24), hex(24)];
  const initial = { op: 'setup', owners: { [asset]: actor, [other]: peer }, contents: { [asset]: body, [other]: peerBody }, disabled: [disabled], key_material: marker };
  const seen = [];
  const run = async (dir, req) => {
    const r = await runAdapter(dir, req);
    seen.push(r.stdout, r.stderr);
    return ok(r);
  };
  const read = (dir, who, what, rid = hex(16)) => run(dir, { op: 'read', actor: who, asset: what, request_id: rid });
  const noLeak = (res) => {
    const s = JSON.stringify(res);
    for (const v of [body, peerBody, marker]) assert.ok(!s.includes(v), 'protected value in a deny');
  };

  const dir = freshDir();
  assert.deepEqual(await run(dir, initial), { ready: true });
  assert.deepEqual(await read(dir, actor, asset), { decision: 'allow', body });
  assert.deepEqual(await read(dir, peer, other), { decision: 'allow', body: peerBody });
  const wrong = await read(dir, actor, other);
  assert.deepEqual(wrong, { decision: 'deny' });
  noLeak(wrong);
  assert.deepEqual(await run(dir, { op: 'revoke', actor }), {});
  const rid = hex(16);
  const denied = await read(dir, actor, asset, rid);
  assert.deepEqual(denied, { decision: 'deny' });
  noLeak(denied);
  assert.deepEqual(await run(dir, { op: 'audit', request_id: rid }), { request_id: rid, decision: 'deny' });
  assert.deepEqual(await read(dir, peer, other), { decision: 'allow', body: peerBody });
  assert.deepEqual(await read(dir, actor, asset), { decision: 'deny' });
  assert.deepEqual(await read(dir, disabled, asset), { decision: 'deny' });

  const dir2 = freshDir();
  assert.deepEqual(await run(dir2, initial), { ready: true });
  assert.deepEqual(await read(dir2, actor, asset), { decision: 'allow', body });

  for (const s of seen) assert.ok(!s.includes(marker), 'key_material marker in output');
});

test('stderr empty on success and stdout is one line of JSON', T, async () => {
  const dir = freshDir();
  for (const req of [
    { op: 'setup', owners: { a: 'm' }, contents: { a: 'line1\nline2' }, disabled: [] },
    { op: 'read', actor: 'm', asset: 'a', request_id: 'r' },
    { op: 'audit', request_id: 'r' },
    { op: 'revoke', actor: 'm' },
  ]) {
    const res = await runAdapter(dir, req);
    ok(res);
  }
});

test('protected_read end to end', T, async () => {
  const dir = freshDir();
  await call(dir, { op: 'setup', owners: { a: 'maya' }, contents: { a: 'ünïcode ✓ <i>' }, disabled: [] });
  const { publicKey, privateKey } = p.kemGenerate();
  const pk = (await p.kemExportRawPublic(publicKey)).toString('base64');
  const res = await call(dir, { op: 'protected_read', actor: 'maya', asset: 'a', challenge: 'chal ✓', public_key: pk });
  assert.deepEqual(Object.keys(res).sort(), ['ciphertext', 'proof']);
  const ss = p.kemDecapsulate(privateKey, Buffer.from(res.ciphertext, 'base64'));
  assert.equal(res.proof, p.hmacHex(ss, Buffer.from('chal ✓' + 'ünïcode ✓ <i>', 'utf8')));
  assert.deepEqual(await call(dir, { op: 'protected_read', actor: 'bob', asset: 'a', challenge: 'c', public_key: pk }), { decision: 'deny' });
  const urlSafe = pk.replace(/\+/g, '-').replace(/\//g, '_');
  if (urlSafe !== pk) {
    assert.deepEqual(await call(dir, { op: 'protected_read', actor: 'maya', asset: 'a', challenge: 'c', public_key: urlSafe }), { decision: 'deny' });
  }
  const ff = Buffer.alloc(1184, 0xff).toString('base64');
  assert.deepEqual(await call(dir, { op: 'protected_read', actor: 'maya', asset: 'a', challenge: 'c', public_key: ff }), { decision: 'deny' });
});

test('unknown op → unsupported_operation exit 0', T, async () => {
  const dir = freshDir();
  for (const op of ['delete', 'READ', '', '__proto__', 'toString']) {
    assert.deepEqual(await call(dir, { op }), { error: 'unsupported_operation' }, op);
  }
});

test('missing or non-string op → invalid_request exit 0', T, async () => {
  const dir = freshDir();
  for (const req of [{}, { op: 1 }, { op: null }, { op: ['read'] }]) {
    assert.deepEqual(await call(dir, req), { error: 'invalid_request' });
  }
});

test('non-object → invalid_request exit 0', T, async () => {
  const dir = freshDir();
  for (const raw of ['[]', 'null', '42', '"read"', 'true', '', '   ', '{', '{"op":"read"} {"op":"read"}', '{"op":"read",}']) {
    assert.deepEqual(await call(dir, raw), { error: 'invalid_request' }, JSON.stringify(raw));
  }
});

test('invalid utf-8 bytes → invalid_request exit 0', T, async () => {
  const dir = freshDir();
  const bad = Buffer.concat([Buffer.from('{"op":"read","actor":"'), Buffer.from([0xc3, 0x28]), Buffer.from('","asset":"a","request_id":"r"}')]);
  assert.deepEqual(await call(dir, bad), { error: 'invalid_request' });
  assert.deepEqual(await call(dir, Buffer.from([0xff, 0xfe, 0x7b, 0x7d])), { error: 'invalid_request' });
});

test('oversize stdin (4 MiB + 1) → invalid_request exit 0', T, async () => {
  const dir = freshDir();
  const head = '{"op":"setup","owners":{},"contents":{"a":"';
  const tail = '"},"disabled":[]}';
  const big = Buffer.alloc(4 * 1024 * 1024 + 1, 0x61);
  big.write(head, 0);
  big.write(tail, big.length - tail.length);
  assert.deepEqual(await call(dir, big), { error: 'invalid_request' });
  assert.deepEqual(fs.readdirSync(dir), [], 'nothing created');
  // exactly 4 MiB is accepted
  const fits = big.subarray(1);
  fits.write(tail, fits.length - tail.length);
  fits.write(head, 0);
  assert.deepEqual(await call(dir, fits), { ready: true });
});

test('invalid input responses per op (§5.3)', T, async () => {
  const dir = freshDir();
  await call(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] });
  assert.deepEqual(await call(dir, { op: 'setup', owners: [], contents: {}, disabled: [] }), { error: 'invalid_request' });
  assert.deepEqual(await call(dir, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }), { decision: 'allow', body: 'x' },
    'invalid setup left state untouched');
  assert.deepEqual(await call(dir, { op: 'revoke', actor: 5 }), { error: 'invalid_request' });
  assert.deepEqual(await call(dir, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }), { decision: 'allow', body: 'x' },
    'invalid revoke persisted nothing');
  assert.deepEqual(await call(dir, { op: 'read', actor: 7, asset: 'a', request_id: 'bad-read' }), { decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'audit', request_id: 'bad-read' }), { request_id: 'bad-read', decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'audit' }), { request_id: null, decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'audit', request_id: 3 }), { request_id: null, decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'protected_read', actor: 'm', asset: 'a', challenge: 'c', public_key: 'AAAA' }), { decision: 'deny' });
});

test('before setup: read/audit/protected_read deny and create nothing', T, async () => {
  const dir = freshDir();
  assert.deepEqual(await call(dir, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }), { decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'audit', request_id: 'r' }), { request_id: 'r', decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'read', actor: 1 }), { decision: 'deny' });
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('falls back to the OS temp dir when TRACK4_STATE_DIR is unset', T, async () => {
  const dir = freshDir();
  const env = { TMPDIR: dir, TEMP: dir, TMP: dir };
  ok(await runAdapter(null, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] }, { env }));
  assert.ok(fs.existsSync(path.join(dir, 'kig', 'adapter.db')));
  assert.deepEqual(ok(await runAdapter(null, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }, { env })), { decision: 'allow', body: 'x' });
});

const canChmod = process.platform !== 'win32' && !(process.getuid && process.getuid() === 0);

test('revoke on unwritable state dir → exit 1, empty stdout, fixed stderr line', { ...T, skip: !canChmod && 'needs a non-root POSIX user' }, async () => {
  const dir = freshDir();
  fs.chmodSync(dir, 0o500);
  try {
    const res = await runAdapter(dir, { op: 'revoke', actor: 'maya' });
    assert.equal(res.code, 1);
    assert.equal(res.stdout, '');
    assert.equal(res.stderr, FAIL_LINE);
    const s = await runAdapter(dir, { op: 'setup', owners: {}, contents: {}, disabled: [] });
    assert.equal(s.code, 1);
    assert.equal(s.stdout, '');
    assert.equal(s.stderr, FAIL_LINE);
  } finally {
    fs.chmodSync(dir, 0o700);
  }
});

function corrupt(dir) {
  const db = path.join(dir, 'kig', 'adapter.db');
  for (const s of ['-wal', '-shm']) fs.rmSync(db + s, { force: true });
  fs.writeFileSync(db, Buffer.concat([Buffer.from('garbage'), Buffer.alloc(4096, 0)]));
}

test('read on corrupt db → deny exit 0; revoke → exit 1; setup quarantines', T, async () => {
  const dir = freshDir();
  await call(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] });
  corrupt(dir);
  assert.deepEqual(await call(dir, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }), { decision: 'deny' });
  assert.deepEqual(await call(dir, { op: 'audit', request_id: 'r' }), { request_id: 'r', decision: 'deny' });
  const pk = Buffer.alloc(1184, 1).toString('base64');
  assert.deepEqual(await call(dir, { op: 'protected_read', actor: 'm', asset: 'a', challenge: 'c', public_key: pk }), { decision: 'deny' });
  const rv = await runAdapter(dir, { op: 'revoke', actor: 'm' });
  assert.equal(rv.code, 1);
  assert.equal(rv.stdout, '');
  assert.equal(rv.stderr, FAIL_LINE);
  assert.deepEqual(await call(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'y' }, disabled: [] }), { ready: true });
  assert.ok(fs.readdirSync(path.join(dir, 'kig')).some((f) => /^adapter\.db\.quarantine-\d+$/.test(f)));
  assert.deepEqual(await call(dir, { op: 'read', actor: 'm', asset: 'a', request_id: 'r' }), { decision: 'allow', body: 'y' });
});

test('no lingering handles (process exits promptly)', T, async () => {
  // Baseline: a bare node that loads the same heavy built-ins. Emulated arm64 is slow,
  // so compare against it rather than a fixed wall-clock budget.
  const t0 = Date.now();
  spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '-e', "require('node:sqlite');require('node:crypto')"]);
  const base = Date.now() - t0;
  const dir = freshDir();
  for (const req of [
    { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] },
    { op: 'read', actor: 'm', asset: 'a', request_id: 'r' },
  ]) {
    const res = await runAdapter(dir, req, { timeoutMs: base * 4 + 4000 });
    ok(res);
    assert.ok(res.ms < base * 3 + 2000, `took ${res.ms} ms (baseline ${base} ms)`);
  }
});

test('duplicate JSON keys: last wins (JSON.parse)', T, async () => {
  const dir = freshDir();
  await call(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] });
  const raw = '{"op":"read","actor":"evil","actor":"m","asset":"a","request_id":"r"}';
  assert.deepEqual(await call(dir, raw), { decision: 'allow', body: 'x' });
  const raw2 = '{"op":"read","op":"delete"}';
  assert.deepEqual(await call(dir, raw2), { error: 'unsupported_operation' });
});
