'use strict';
// Hostile identifiers and input shapes through real adapter processes
// (Task 1.15; review focus 1, 4, 5). Every call is a fresh process.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runAdapter } = require('../helpers/run-adapter.cjs');
const { allFiles } = require('../helpers/state.cjs');
const p = require('../../src/crypto/provider.cjs');

const T = { timeout: 1800000 };
const freshDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kig-neg-'));

// The Task 1.1 identifier list.
const IDS = ['\ud800', '\udc00\ud800', '�', 'a\u0000b', 'x\n{"actor":"admin"}', '../../etc/passwd',
  "';DROP TABLE t;--", '🙂', '', '__proto__', 'constructor', 'a'.repeat(2048)];
const MARKER = 'MARKER-' + p.random(12).toString('hex');
const bodyOf = (i) => `body-${i}-${MARKER.slice(7, 15)} ünïcode ✓`;

// Every stdout/stderr seen, and every deny, for the leak checks at the end.
const seen = [];
const denies = [];
const run = async (dir, req, label) => {
  const res = await runAdapter(dir, req);
  seen.push(res.stdout, res.stderr);
  assert.equal(res.timedOut, false, `${label}: timed out`);
  assert.equal(res.code, 0, `${label}: exit ${res.code}`);
  assert.equal(res.stderr, '', label);
  assert.ok(res.json && typeof res.json === 'object', `${label}: no JSON`);
  if (res.json.decision === 'deny') denies.push(res.json);
  return res.json;
};

/** Mirrors validate.py contains_protected_value: any seeded value anywhere in the JSON. */
const protectedValues = [MARKER, ...IDS.map((_, i) => bodyOf(i))];
const leaks = (json) => {
  const s = JSON.stringify(json);
  return protectedValues.filter((v) => s.includes(v) || s.includes(JSON.stringify(v).slice(1, -1)));
};

const sharedDir = freshDir();

test('hostile ids as actor, asset and request_id: setup → read → revoke → audit', T, async () => {
  const dir = sharedDir;
  // Build the request text directly: a '__proto__' key in an object literal would set the prototype.
  const pairs = (f) => '{' + IDS.map((id, i) => `${JSON.stringify(id)}:${JSON.stringify(f(id, i))}`).join(',') + '}';
  const raw = `{"op":"setup","owners":${pairs((id) => id)},"contents":${pairs((_, i) => bodyOf(i))},"disabled":[],"key_material":${JSON.stringify(MARKER)}}`;
  assert.deepEqual(await run(dir, raw, 'setup'), { ready: true });

  // Each id owns the asset with the same id; request_id is the id too.
  for (const [i, id] of IDS.entries()) {
    assert.deepEqual(await run(dir, { op: 'read', actor: id, asset: id, request_id: id }, `read ${i}`),
      { decision: 'allow', body: bodyOf(i) }, `id ${i}`);
  }
  // Distinct identities: neighbours (incl. '\ud800' vs '�', '' vs others) never match.
  for (const [i, id] of IDS.entries()) {
    const j = (i + 1) % IDS.length;
    assert.deepEqual(await run(dir, { op: 'read', actor: id, asset: IDS[j], request_id: `x${i}` }, `cross ${i}`), { decision: 'deny' });
  }
  assert.deepEqual(await run(dir, { op: 'read', actor: '�', asset: '\ud800', request_id: 'fffd' }, 'fffd'), { decision: 'deny' });
  // Audit finds each (allow), keyed by the hostile id itself.
  for (const [i, id] of IDS.entries()) {
    assert.deepEqual(await run(dir, { op: 'audit', request_id: id }, `audit ${i}`), { request_id: id, decision: 'allow' });
  }
  // Revoke every id; the same read is now denied, and audit reports the latest decision.
  for (const [i, id] of IDS.entries()) assert.deepEqual(await run(dir, { op: 'revoke', actor: id }, `revoke ${i}`), {});
  for (const [i, id] of IDS.entries()) {
    assert.deepEqual(await run(dir, { op: 'read', actor: id, asset: id, request_id: id }, `read2 ${i}`), { decision: 'deny' });
    assert.deepEqual(await run(dir, { op: 'audit', request_id: id }, `audit2 ${i}`), { request_id: id, decision: 'deny' });
  }
});

test('prototype keys in setup maps', T, async () => {
  const dir = freshDir();
  const raw = '{"op":"setup","owners":{"__proto__":"a","constructor":"b"},"contents":{"__proto__":"P body","constructor":"C body"},"disabled":["toString"]}';
  assert.deepEqual(await run(dir, raw, 'setup'), { ready: true });
  assert.deepEqual(await run(dir, { op: 'read', actor: 'a', asset: '__proto__', request_id: '1' }, 'a'), { decision: 'allow', body: 'P body' });
  assert.deepEqual(await run(dir, { op: 'read', actor: 'b', asset: 'constructor', request_id: '2' }, 'b'), { decision: 'allow', body: 'C body' });
  assert.deepEqual(await run(dir, { op: 'read', actor: 'a', asset: 'constructor', request_id: '3' }, 'a/c'), { decision: 'deny' });
  assert.deepEqual(await run(dir, { op: 'read', actor: 'a', asset: 'hasOwnProperty', request_id: '4' }, 'inherited'), { decision: 'deny' });
  assert.deepEqual(await run(dir, { op: 'read', actor: 'a', asset: 'toString', request_id: '5' }, 'toString'), { decision: 'deny' });
});

test('wrong types for every field', T, async () => {
  const dir = freshDir();
  await run(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] }, 'setup');
  const pk = Buffer.alloc(1184, 1).toString('base64');
  const base = {
    setup: { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] },
    read: { op: 'read', actor: 'm', asset: 'a', request_id: 'r' },
    revoke: { op: 'revoke', actor: 'm' },
    audit: { op: 'audit', request_id: 'r' },
    protected_read: { op: 'protected_read', actor: 'm', asset: 'a', challenge: 'c', public_key: pk },
  };
  const invalid = {
    setup: () => ({ error: 'invalid_request' }),
    revoke: () => ({ error: 'invalid_request' }),
    read: () => ({ decision: 'deny' }),
    protected_read: () => ({ decision: 'deny' }),
    audit: (req) => ({ request_id: typeof req.request_id === 'string' ? req.request_id : null, decision: 'deny' }),
  };
  for (const [op, good] of Object.entries(base)) {
    for (const field of Object.keys(good).filter((k) => k !== 'op')) {
      for (const bad of [7, op === 'setup' && field === 'disabled' ? {} : ['x']]) {
        const req = { ...good, [field]: bad };
        assert.deepEqual(await run(dir, req, `${op}.${field}`), invalid[op](req), `${op}.${field}=${JSON.stringify(bad)}`);
      }
      const missing = { ...good };
      delete missing[field];
      assert.deepEqual(await run(dir, missing, `${op} -${field}`), invalid[op](missing), `${op} missing ${field}`);
    }
  }
  // None of that changed state: the owner still reads, nobody was revoked.
  assert.deepEqual(await run(dir, base.read, 'after'), { decision: 'allow', body: 'x' });
});

test('arrays instead of objects, null request, odd JSON', T, async () => {
  const dir = freshDir();
  const cases = [
    ['[]', { error: 'invalid_request' }],
    ['null', { error: 'invalid_request' }],
    ['[{"op":"read"}]', { error: 'invalid_request' }],
    ['{"op":"setup","owners":[],"contents":[],"disabled":[]}', { error: 'invalid_request' }],
    ['{"op":"setup","owners":{"a":"m"},"contents":{"a":"x"},"disabled":{"0":"m"}}', { error: 'invalid_request' }],
    ['﻿{"op":"delete"}', { error: 'unsupported_operation' }],
    ['{"op":"read","actor":"m","asset":"a","request_id":"r","__proto__":{"actor":"x"}}', { decision: 'deny' }],
    ['[' .repeat(200000) + ']'.repeat(200000), { error: 'invalid_request' }],
    ['{"op":"read","actor":"m","asset":"a","request_id":1e999}', { decision: 'deny' }],
  ];
  for (const [raw, want] of cases) {
    assert.deepEqual(await run(dir, raw, raw.slice(0, 40)), want, raw.slice(0, 60));
  }
});

test('duplicate JSON keys use the last value', T, async () => {
  const dir = freshDir();
  await run(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] }, 'setup');
  assert.deepEqual(await run(dir, '{"op":"revoke","actor":"m","op":"read","asset":"a","request_id":"r"}', 'dup'), { decision: 'allow', body: 'x' });
});

test('url-safe, whitespace and wrong-length keys deny with exit 0 and no ciphertext', T, async () => {
  const dir = freshDir();
  await run(dir, { op: 'setup', owners: { a: 'm' }, contents: { a: 'x' }, disabled: [] }, 'setup');
  const { publicKey } = p.kemGenerate();
  const pk = (await p.kemExportRawPublic(publicKey)).toString('base64');
  const keys = [
    pk.replace(/\+/g, '-').replace(/\//g, '_') + (pk.includes('+') || pk.includes('/') ? '' : '-'),
    pk.slice(0, 64) + ' ' + pk.slice(64),
    pk + '\n',
    Buffer.alloc(1183, 1).toString('base64'),
    Buffer.alloc(1185, 1).toString('base64'),
    Buffer.alloc(1184, 0xff).toString('base64'),
  ];
  for (const [i, k] of keys.entries()) {
    assert.deepEqual(await run(dir, { op: 'protected_read', actor: 'm', asset: 'a', challenge: 'c', public_key: k }, `key ${i}`), { decision: 'deny' });
  }
});

test('no deny response leaks a seeded body or the marker', () => {
  assert.ok(denies.length > 20);
  for (const d of denies) {
    const shape = 'request_id' in d ? ['request_id', 'decision'] : ['decision']; // audit deny vs read deny
    assert.deepEqual(Object.keys(d), shape, JSON.stringify(d).slice(0, 80));
    assert.deepEqual(leaks(d), []);
  }
});

test('marker scan: stdout, stderr and every file under the state dir', () => {
  const needle = Buffer.from(MARKER, 'utf8');
  for (const s of seen) assert.ok(!s.includes(MARKER), 'marker in process output');
  const files = allFiles(sharedDir);
  assert.ok(files.some((f) => f.endsWith('adapter.db')));
  for (const f of files) assert.ok(!fs.readFileSync(f).includes(needle), `marker bytes in ${path.basename(f)}`);
});
