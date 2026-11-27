'use strict';
// core/proc.cjs pidAlive: a process that has exited but not yet been reaped (a zombie)
// is NOT alive. Regression for `kig dashboard --stop` "did not exit within 5 s" when the
// dashboard's parent was blocked (CI: test runner inside spawnSync).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { pidAlive } = require('../../src/core/proc.cjs');

const block = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

test('running process is alive', async () => {
  const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { stdio: 'ignore' });
  await new Promise((r) => child.once('spawn', r));
  try { assert.equal(pidAlive(child.pid), true); } finally { child.kill('SIGKILL'); }
});

test('own process is alive; invalid and unused pids are not', () => {
  assert.equal(pidAlive(process.pid), true);
  for (const p of [0, -1, 1.5, NaN, 2147483000]) assert.equal(pidAlive(p), false, String(p));
});

test('exited-but-unreaped (zombie) process is not alive', { skip: process.platform !== 'linux' }, async () => {
  const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
  await new Promise((r) => child.once('spawn', r));
  block(1500); // child exits meanwhile; our event loop cannot reap it while blocked → zombie
  assert.equal(pidAlive(child.pid), false);
  await new Promise((r) => (child.exitCode !== null ? r() : child.once('exit', r)));
});
