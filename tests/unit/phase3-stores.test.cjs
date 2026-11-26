'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { NODE_IDS, layout } = require('../../src/core/contracts.cjs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const { request } = require('../../src/device/client.cjs');

test('verify-log accepts the Phase 3 registry and every node store', async (t) => {
  const home = freshHome();
  let cluster;
  t.after(async () => {
    if (cluster) await cluster.stop();
    fs.rmSync(home, { recursive: true, force: true });
  });
  cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  const run = (args) => runKig(args, { env, timeoutMs: 30000 });

  const added = run(['account', 'add', 'verify-user']);
  assert.equal(added.code, 0, added.stderr);
  const enrolled = run(['device', 'enrol', 'verify-device', '--account', 'verify-user']);
  assert.equal(enrolled.code, 0, enrolled.stderr);
  const approved = run(['device', 'approve', 'verify-device', '--operator', '--approval-id', 'verify-first']);
  assert.equal(approved.code, 0, approved.stderr);
  const probe = await request(cluster.nodeUrls.A, layout(home).device('verify-device').dir, 'policy.probe', {
    home, version: 1, op: 'policy.probe', account: 'verify-user', device_id: 'verify-device',
    resource: 'verify-log', request_id: 'verify-log-probe', key_version: 1,
  });
  assert.equal(probe.decision, 'allow');

  const stores = [layout(home).cp.db, ...NODE_IDS.map((id) => layout(home).node(id).db)];
  for (const db of stores) {
    const result = run(['verify-log', '--db', db]);
    assert.equal(result.code, 0, `${path.basename(path.dirname(db))}: ${result.stderr || result.stdout}`);
    assert.match(result.stdout, /^OK \d+ [0-9a-f]{64}\n$/);
  }
});
