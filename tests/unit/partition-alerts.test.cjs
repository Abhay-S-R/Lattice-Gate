'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const { layout } = require('../../src/core/contracts.cjs');
const { request } = require('../../src/device/client.cjs');

const pause = (ms) => new Promise(resolve => setTimeout(resolve, ms));

test('partition expires the node lease, denies access, records an alert, then heals', async (t) => {
  const home = freshHome();
  let cluster;
  t.after(async () => {
    if (cluster) await cluster.stop();
    fs.rmSync(home, { recursive: true, force: true });
  });
  cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  const run = (args) => runKig(args, { env, timeoutMs: 30000 });
  assert.equal(run(['account', 'add', 'partition-user']).code, 0);
  assert.equal(run(['device', 'enrol', 'partition-device', '--account', 'partition-user']).code, 0);
  assert.equal(run(['device', 'approve', 'partition-device', '--operator', '--approval-id', 'partition-approval']).code, 0);

  const fields = { home, version: 1, op: 'policy.probe', account: 'partition-user', device_id: 'partition-device', resource: 'probe', key_version: 1 };
  const probe = () => request(cluster.nodeUrls.A, layout(home).device('partition-device').dir, fields.op, {
    ...fields, request_id: `partition-${Date.now()}-${Math.random()}`,
  });
  assert.equal((await probe()).decision, 'allow');

  const partitioned = run(['node', 'partition', 'A']);
  assert.equal(partitioned.code, 0, partitioned.stderr);
  assert.match(partitioned.stdout, /lease expires in at most \d+ ms/i);
  await pause(5200);
  const denied = await probe();
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.rule, 'lease_expired');

  const alerts = run(['alerts', '--json']);
  assert.equal(alerts.code, 0, alerts.stderr);
  const rows = JSON.parse(alerts.stdout);
  assert.ok(rows.some(row => row.source === 'node-A' && row.rule === 'N-STALE-NODE'));

  const healed = run(['node', 'heal', 'A']);
  assert.equal(healed.code, 0, healed.stderr);
  let allowed = false;
  const until = Date.now() + 3000;
  while (Date.now() < until) {
    if ((await probe()).decision === 'allow') { allowed = true; break; }
    await pause(25);
  }
  assert.equal(allowed, true, 'healed node pulls the current policy and grants the active device');

  const revoked = run(['revoke', '--device', 'partition-device']);
  assert.equal(revoked.code, 0, revoked.stderr);
  let revokeDenied = false;
  const revokeUntil = Date.now() + 3000;
  while (Date.now() < revokeUntil) {
    if ((await probe()).decision === 'deny') { revokeDenied = true; break; }
    await pause(25);
  }
  assert.equal(revokeDenied, true, 'revoked device is denied after policy propagation');
  assert.equal(run(['revoke', '--device', 'partition-device']).code, 1, 'CP refuses a duplicate revocation');
  const merged = run(['alerts', '--json']);
  assert.equal(merged.code, 0, merged.stderr);
  const mergedRows = JSON.parse(merged.stdout);
  assert.ok(mergedRows.some(row => row.source === 'node-A' && row.rule === 'N-REVOKED-RETRY'));
  assert.ok(mergedRows.some(row => row.source === 'control-plane' && row.rule === 'CP-REVOKE-REFUSED'));
});
