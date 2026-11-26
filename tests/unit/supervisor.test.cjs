'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');

test('C9 test helper starts and stops a healthy loopback cluster', async () => {
  const home = freshHome();
  const cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(Number(new URL(cluster.cpUrl).port)) };
  try {
    const status = runKig(['status'], { env });
    assert.equal(status.code, 0, status.stderr);
    assert.match(status.stdout, /CP healthy/);
    for (const id of ['A', 'B', 'C']) assert.match(status.stdout, new RegExp(`Node ${id} healthy`));
    for (const file of ['cp.pid', 'A.pid', 'B.pid', 'C.pid']) assert.ok(fs.existsSync(path.join(home, 'run', file)), file);
  } finally {
    await cluster.stop();
  }
  const after = runKig(['status'], { env });
  assert.equal(after.code, 1);
  assert.doesNotMatch(after.stdout, /healthy/);
});

test('kig up twice preserves the running process set', async () => {
  const home = freshHome();
  const cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(Number(new URL(cluster.cpUrl).port)) };
  try {
    const before = ['cp', 'A', 'B', 'C'].map((id) => JSON.parse(fs.readFileSync(path.join(home, 'run', `${id}.pid`), 'utf8')).pid);
    const second = runKig(['up'], { env });
    assert.equal(second.code, 0, second.stderr);
    const after = ['cp', 'A', 'B', 'C'].map((id) => JSON.parse(fs.readFileSync(path.join(home, 'run', `${id}.pid`), 'utf8')).pid);
    assert.deepEqual(after, before);
  } finally { await cluster.stop(); }
});
