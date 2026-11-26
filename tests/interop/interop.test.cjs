'use strict';
// Task 1.16: run the pqcrypto interop script (25 runs) against the real adapter.
// Skips, visibly, when Python 3 with pqcrypto isn't available (it is in the
// judge replica and in CI).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPT = path.join(__dirname, 'protected_read_interop.py');
const candidates = process.platform === 'win32' ? [['python'], ['py', '-3'], ['python3']] : [['python3'], ['python']];
const python = candidates.find(([cmd, ...pre]) =>
  spawnSync(cmd, [...pre, '-c', 'import pqcrypto.kem.ml_kem_768'], { stdio: 'ignore' }).status === 0);

const skip = python ? false : 'python3 with pqcrypto==0.4.0 not found; interop NOT verified on this machine';
if (skip) process.stdout.write(`# SKIP interop: ${skip}\n`);

test('pqcrypto decapsulates protected_read: interop 25/25', { timeout: 1800000, skip }, () => {
  const [cmd, ...pre] = python;
  const r = spawnSync(cmd, [...pre, SCRIPT, '--runs', '25', '--node', process.execPath], { encoding: 'utf8', timeout: 1700000 });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
  assert.match(r.stdout, /^interop 25\/25$/m);
});
