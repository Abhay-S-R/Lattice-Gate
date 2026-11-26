'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { NODE_IDS, layout, ROUTES } = require('../../src/core/contracts.cjs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const client = require('../../src/device/client.cjs');
const { openDb } = require('../../src/store/db.cjs');
const cpSchema = require('../../src/store/schema-cp.cjs');
const { call } = require('../../src/core/http.cjs');
const ids = require('../../src/core/ids.cjs');

const pause = (ms) => new Promise(resolve => setTimeout(resolve, ms));
let probeIndex = 0;
async function probeUntil(nodeUrl, home, account, deviceId, expected) {
  const end = Date.now() + 5000;
  while (Date.now() < end) {
    const response = await client.request(nodeUrl, layout(home).device(deviceId).dir, 'policy.probe', {
      home, version: 1, account, device_id: deviceId, resource: 'probe',
      request_id: `${deviceId}-${++probeIndex}`, key_version: 1,
    });
    if (response.status === 200 && response.json.decision === expected) return response.json;
    await pause(20);
  }
  throw new Error(`${deviceId} did not receive ${expected} from ${nodeUrl}`);
}

test('revoking one device reaches all nodes while its peer remains allowed', async (t) => {
  const home = freshHome();
  let cluster;
  let cpDb;
  const oldHome = process.env.KIG_HOME, oldBase = process.env.KIG_PORT_BASE;
  t.after(async () => {
    cpDb?.close();
    if (cluster) await cluster.stop();
    if (oldHome === undefined) delete process.env.KIG_HOME; else process.env.KIG_HOME = oldHome;
    if (oldBase === undefined) delete process.env.KIG_PORT_BASE; else process.env.KIG_PORT_BASE = oldBase;
    fs.rmSync(home, { recursive: true, force: true });
  });

  cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  process.env.KIG_HOME = env.KIG_HOME;
  process.env.KIG_PORT_BASE = env.KIG_PORT_BASE;
  const run = (args) => runKig(args, { env, timeoutMs: 30000 });
  assert.equal(run(['account', 'add', 'alice']).code, 0);
  assert.equal(run(['device', 'enrol', 'alice-phone', '--account', 'alice']).code, 0);
  assert.equal(run(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'first']).code, 0);
  assert.equal(run(['device', 'enrol', 'alice-peer', '--account', 'alice']).code, 0);
  assert.equal(run(['device', 'approve', 'alice-peer', '--by', 'alice-phone', '--approval-id', 'peer']).code, 0);
  assert.equal(run(['device', 'enrol', 'alice-pending', '--account', 'alice']).code, 0);
  const pending = run(['revoke', '--device', 'alice-pending']);
  assert.equal(pending.code, 1);
  assert.match(pending.stderr, /device_not_active/);

  const revokePath = ROUTES.cp.revoke.split(' ')[1];
  assert.equal((await call(`${cluster.cpUrl}${revokePath}`, 'POST', {})).status, 400);
  const missing = await call(`${cluster.cpUrl}${revokePath}`, 'POST', { device_id: 'missing-device' });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error, 'device_not_found');

  for (const id of NODE_IDS) {
    assert.equal((await probeUntil(cluster.nodeUrls[id], home, 'alice', 'alice-phone', 'allow')).decision, 'allow');
    assert.equal((await probeUntil(cluster.nodeUrls[id], home, 'alice', 'alice-peer', 'allow')).decision, 'allow');
  }

  const revoked = run(['revoke', '--device', 'alice-phone']);
  assert.equal(revoked.code, 0, revoked.stderr);
  assert.match(revoked.stdout, /REVOKED "alice-phone" epoch=\d+/);
  for (const id of NODE_IDS) {
    assert.equal((await probeUntil(cluster.nodeUrls[id], home, 'alice', 'alice-phone', 'deny')).rule, 'device_revoked');
    assert.equal((await probeUntil(cluster.nodeUrls[id], home, 'alice', 'alice-peer', 'allow')).decision, 'allow');
  }

  cpDb = openDb(layout(home).cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
  const epoch = Number(require('../../src/store/schema-base.cjs').getMeta(cpDb, 'epoch'));
  const ackDeadline = Date.now() + 3000;
  while (Date.now() < ackDeadline && NODE_IDS.some(id => !cpDb.prepare('SELECT 1 FROM node_acks WHERE node_id=? AND epoch=?').get(id, epoch))) await pause(20);
  for (const id of NODE_IDS) assert.ok(cpDb.prepare('SELECT 1 FROM node_acks WHERE node_id=? AND epoch=?').get(id, epoch), `${id} acked epoch ${epoch}`);
  assert.equal(cpDb.prepare('SELECT status FROM devices WHERE device_id=?').get(ids.enc('alice-phone')).status, 'revoked');
  assert.equal(cpDb.prepare("SELECT count(*) AS n FROM audit_events WHERE kind='device_revoked' AND asset=?").get(ids.enc('alice-phone')).n, 1);
  const duplicate = run(['revoke', '--device', 'alice-phone']);
  assert.equal(duplicate.code, 1);
  assert.match(duplicate.stderr, /device_already_revoked/);
  assert.equal(Number(require('../../src/store/schema-base.cjs').getMeta(cpDb, 'epoch')), epoch);
  assert.equal(cpDb.prepare("SELECT count(*) AS n FROM audit_events WHERE kind='device_revoked' AND asset=?").get(ids.enc('alice-phone')).n, 1);
});
