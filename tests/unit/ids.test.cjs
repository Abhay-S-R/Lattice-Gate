'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const ids = require('../../src/core/ids.cjs');
const limits = require('../../src/core/limits.cjs');

const HOSTILE_LIST = [
  '\ud800', '\udc00\ud800', '�', 'a\u0000b', 'x\n{"actor":"admin"}', '../../etc/passwd',
  "';DROP TABLE t;--", '🙂', '', '__proto__', 'constructor', 'a'.repeat(2048),
];

test('round trip', () => {
  for (const s of HOSTILE_LIST) assert.equal(ids.dec(ids.enc(s)), s);
});

test('distinct', () => {
  assert.notEqual(ids.enc('\ud800'), ids.enc('�'));
  assert.equal(new Set(HOSTILE_LIST.map(ids.enc)).size, HOSTILE_LIST.length);
});

test('enc output is well-formed (safe for SQLite TEXT)', () => {
  for (const s of HOSTILE_LIST) {
    const t = ids.enc(s);
    assert.ok(t.isWellFormed());
    assert.ok(!t.includes('\u0000'));
  }
});

test('isHostile', () => {
  for (const s of ['\ud800', 'a\u0000b', 'x\ny', '../a', '..\\a', 'a\u007fb', '__proto__', 'constructor', 'prototype'])
    assert.equal(ids.isHostile(s), true, JSON.stringify(s));
  for (const s of ['maya', 'r01', '🙂', '', 'a.b', '..'])
    assert.equal(ids.isHostile(s), false, JSON.stringify(s));
});

test('isId', () => {
  for (const x of [undefined, null, 1, {}, [], true]) assert.equal(ids.isId(x), false);
  assert.equal(ids.isId('a'.repeat(limits.MAX_ID_LEN)), true);
  assert.equal(ids.isId('a'.repeat(8193)), false);
  assert.equal(ids.isId(''), true);
});

test('limits values', () => {
  assert.equal(limits.MAX_STDIN_BYTES, 4 * 1024 * 1024);
  assert.equal(limits.MAX_ID_LEN, 8192);
  assert.equal(limits.MAX_CHALLENGE_LEN, 4096);
  assert.equal(limits.KEM_PK_BYTES, 1184);
  assert.equal(limits.BUSY_TIMEOUT_MS, 5000);
  assert.equal(limits.BUSY_RETRIES, 3);
  assert.equal(limits.JITTER_MIN_MS, 20);
  assert.equal(limits.JITTER_MAX_MS, 80);
  assert.equal(limits.BURST_N, 5);
  assert.equal(limits.BURST_WINDOW_MS, 60000);
  assert.equal(limits.SCHEMA_VERSION_ADAPTER, 1);
  assert.ok(limits.PROTO_KEYS.has('__proto__') && limits.PROTO_KEYS.has('valueOf'));
  assert.ok(Object.isFrozen(limits));
});
