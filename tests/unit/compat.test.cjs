'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '../..');

test('compat.run() returns only passes on this machine', async () => {
  const compat = require('../../src/cli/compat.cjs');
  const results = await compat.run();
  const names = results.map((r) => r.name);
  for (const expected of [
    'hkdf-sha256 RFC 5869 TC1',
    'ml-kem-768 raw-public encapsulate/decapsulate',
    'ml-dsa-65 sign/verify with context separation',
    'sqlite wal + strict tables',
    'sqlite 8 processes x 25 chained appends',
    'sqlite SIGKILL inside transaction leaves no partial row',
    'sqlite VACUUM INTO copy readable',
    'entry point stderr silent after warning suppression',
  ]) assert.ok(names.includes(expected), `missing check: ${expected}`);
  for (const r of results) assert.equal(r.pass, true, `${r.name}: ${r.detail || ''}`);
});

test('node kig.cjs compat prints PASS lines, exits 0, stderr empty', () => {
  const r = spawnSync(process.execPath, ['kig.cjs', 'compat'], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(r.stderr, '');
  const lines = r.stdout.trim().split('\n');
  assert.ok(lines.some((l) => l.startsWith('PASS ')));
  assert.ok(lines.every((l) => /^(PASS|INFO) /.test(l)), r.stdout);
  assert.ok(lines.some((l) => l.startsWith('INFO node v24.')));
});

test('unknown kig command exits 2 with usage on stderr', () => {
  const r = spawnSync(process.execPath, ['kig.cjs', 'no-such-command'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage/i);
});
