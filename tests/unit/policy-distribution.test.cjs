'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb } = require('../../src/store/db.cjs');
const cpSchema = require('../../src/store/schema-cp.cjs');
const nodeSchema = require('../../src/store/schema-node.cjs');
const { layout, ports, url, ROUTES, SNAPSHOT, ENROL, NODE_IDS } = require('../../src/core/contracts.cjs');
const ids = require('../../src/core/ids.cjs');
const provider = require('../../src/crypto/provider.cjs');
const { encode } = require('../../src/core/encoding.cjs');
const { freshHome } = require('../helpers/kig-home.cjs');
const { startCluster } = require('../helpers/kig-home.cjs');
const { createKeys } = require('../../src/cp/keys.cjs');

function makeStores() {
  const home = freshHome();
  const L = layout(home);
  fs.mkdirSync(path.dirname(L.cp.db), { recursive: true });
  fs.mkdirSync(path.dirname(L.node('A').db), { recursive: true });
  createKeys(L);
  const cp = openDb(L.cp.db, { create: true, version: cpSchema.VERSION, init: cpSchema.init });
  const node = openDb(L.node('A').db, { create: true, version: nodeSchema.VERSION, init: nodeSchema.init });
  return { home, L, cp, node };
}

function insertDevice(db, { device, account, status, sign, kem }) {
  db.prepare("INSERT INTO accounts(account,created_ms,status) VALUES(?,0,'active')").run(ids.enc(account));
  db.prepare('INSERT INTO devices(device_id,account,sign_pk,kem_pk,status,key_version,created_ms) VALUES(?,?,?,?,?,1,0)')
    .run(ids.enc(device), ids.enc(account), provider.exportPublic(sign.publicKey), Buffer.from(kem), status);
}

function closeStores(f) {
  f.cp.close(); f.node.close(); fs.rmSync(f.home, { recursive: true, force: true });
}

test('buildSnapshot contains sorted device hashes, revocations, files, and grants', () => {
  const f = makeStores();
  try {
    const sign = provider.sigGenerate();
    insertDevice(f.cp, { device: 'z-phone', account: 'alice', status: 'active', sign, kem: Buffer.from('kem-z') });
    insertDevice(f.cp, { device: 'a-phone', account: 'bob', status: 'revoked', sign, kem: Buffer.from('kem-a') });
    f.cp.prepare('INSERT INTO files(file_id,owner_account,active_version,created_ms) VALUES(?,?,?,0)')
      .run(ids.enc('brief'), ids.enc('alice'), 3);
    f.cp.prepare('INSERT INTO grants(file_id,account,created_ms) VALUES(?,?,0)')
      .run(ids.enc('brief'), ids.enc('bob'));

    const { buildSnapshot } = require('../../src/cp/snapshot.cjs');
    const snapshot = buildSnapshot(f.cp);
    assert.equal(snapshot.epoch, 1);
    assert.equal(snapshot.lease_ms, SNAPSHOT.leaseMs);
    assert.deepEqual(snapshot.devices.map(d => d.device_id), ['a-phone', 'z-phone']);
    assert.equal(snapshot.devices[0].sign_pk_sha256, provider.sha256(provider.exportPublic(sign.publicKey)).toString('hex'));
    assert.equal(snapshot.devices[0].kem_pk_sha256, provider.sha256(Buffer.from('kem-a')).toString('hex'));
    assert.deepEqual(snapshot.revoked_devices, ['a-phone']);
    assert.deepEqual(snapshot.files, [{ file_id: 'brief', active_version: 3, cutoff: null }]);
    assert.deepEqual(snapshot.grants, [{ file_id: 'brief', account: 'bob' }]);
  } finally { closeStores(f); }
});

test('applySnapshot verifies signature and atomically rejects stale epochs', () => {
  const f = makeStores();
  try {
    const keys = provider.sigGenerate();
    const { signSnapshot } = require('../../src/cp/snapshot.cjs');
    const { applySnapshot, current } = require('../../src/node/policy.cjs');
    const snapshot = { epoch: 1, issued_at_ms: Date.now(), lease_ms: 5000, devices: [], revoked_devices: [], files: [], grants: [] };
    const signed = signSnapshot(snapshot, keys.privateKey);
    assert.deepEqual(applySnapshot(f.node, signed, keys.publicKey), { applied: true, reason: 'applied' });
    assert.deepEqual(applySnapshot(f.node, signed, keys.publicKey), { applied: false, reason: 'stale_epoch' });
    assert.equal(current(f.node).applied_epoch, 1);

    const tampered = { ...signed, snapshot: { ...snapshot, epoch: 2 } };
    assert.deepEqual(applySnapshot(f.node, tampered, keys.publicKey), { applied: false, reason: 'bad_signature' });
    assert.equal(current(f.node).applied_epoch, 1);
  } finally { closeStores(f); }
});

test('lease expires by monotonic time and remains invalid until a fresh head', () => {
  const f = makeStores();
  try {
    const keys = provider.sigGenerate();
    const { signSnapshot } = require('../../src/cp/snapshot.cjs');
    const { applySnapshot, current } = require('../../src/node/policy.cjs');
    const snapshot = { epoch: 1, issued_at_ms: Date.now(), lease_ms: 5000, devices: [], revoked_devices: [], files: [], grants: [] };
    assert.equal(applySnapshot(f.node, signSnapshot(snapshot, keys.privateKey), keys.publicKey).applied, true);
    assert.equal(current(f.node).lease_valid, true);
    f.node.prepare("UPDATE lease SET v='0' WHERE k='lease_until_mono_ns'").run();
    assert.equal(current(f.node).lease_valid, false);
    const denied = require('../../src/node/auth.cjs').authenticate(f.node, {
      op: 'file.read', device_id: 'alice-phone', resource: 'brief', request_id: 'expired-lease', nonce: '', key_version: 1,
    });
    assert.deepEqual({ ok: denied.ok, rule: denied.rule }, { ok: false, rule: 'lease_expired' });
  } finally { closeStores(f); }
});

test('node pulls a policy missed while offline and accepts only its fresh signed head', async (t) => {
  const f = makeStores();
  const base = 20000 + Math.floor(Math.random() * 20000);
  const env = { KIG_HOME: f.home, KIG_PORT_BASE: String(base), KIG_NODE_ID: 'A' };
  const previous = { home: process.env.KIG_HOME, ports: process.env.KIG_PORT_BASE };
  process.env.KIG_HOME = env.KIG_HOME;
  process.env.KIG_PORT_BASE = env.KIG_PORT_BASE;
  let cpServer, nodeServer;
  t.after(async () => {
    if (nodeServer) await new Promise(resolve => nodeServer.close(resolve));
    if (cpServer) await new Promise(resolve => cpServer.close(resolve));
    if (previous.home === undefined) delete process.env.KIG_HOME; else process.env.KIG_HOME = previous.home;
    if (previous.ports === undefined) delete process.env.KIG_PORT_BASE; else process.env.KIG_PORT_BASE = previous.ports;
    closeStores(f);
  });

  cpServer = require('../../src/cp/server.cjs').start({ env });
  // Publish while node A is offline. Its later poll must recover this epoch.
  const { publish } = require('../../src/cp/snapshot.cjs');
  const epoch = publish(f.cp);
  nodeServer = require('../../src/node/server.cjs').start({ env });
  const { current } = require('../../src/node/policy.cjs');
  const until = Date.now() + 5000;
  while (Date.now() < until && current(f.node).applied_epoch < epoch) {
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(current(f.node).applied_epoch, epoch);
  assert.equal(current(f.node).lease_valid, true);

  const { call } = require('../../src/core/http.cjs');
  const nonce = provider.random(SNAPSHOT.headNonceBytes);
  const head = await call(`${url(ports(env).cp)}${ROUTES.cp.policyHead.split(' ')[1]}?nonce=${nonce.toString('hex')}`, 'GET');
  assert.equal(head.status, 200);
  assert.equal(head.json.epoch, epoch);
  const headBytes = encode(SNAPSHOT.headLabel, [head.json.epoch, nonce]);
  assert.equal(provider.verify(provider.importPublic(fs.readFileSync(f.L.cp.keys.policy.pub)), SNAPSHOT.context, headBytes, Buffer.from(head.json.sig, 'base64')), true);
  const cpPub = provider.importPublic(fs.readFileSync(f.L.cp.keys.policy.pub));
  const replay = await require('../../src/node/policy.cjs').acceptHead(f.node, head.json, Buffer.alloc(SNAPSHOT.headNonceBytes, 0), cpPub);
  assert.equal(replay.accepted, false);
  assert.equal(replay.reason, 'nonce_mismatch');
  const staleNonce = provider.random(SNAPSHOT.headNonceBytes);
  const staleEpoch = epoch - 1;
  const staleHead = {
    epoch: staleEpoch, nonce: staleNonce.toString('hex'),
    sig: provider.sign(provider.importPrivate(fs.readFileSync(f.L.cp.keys.policy.key)), SNAPSHOT.context,
      encode(SNAPSHOT.headLabel, [staleEpoch, staleNonce])).toString('base64'),
  };
  const beforeStaleHead = require('../../src/node/lease.cjs').get(f.node, 'lease_until_mono_ns');
  assert.deepEqual(require('../../src/node/policy.cjs').acceptHead(f.node, staleHead, staleNonce, cpPub), { accepted: false, reason: 'stale_head' });
  assert.equal(require('../../src/node/lease.cjs').get(f.node, 'lease_until_mono_ns'), beforeStaleHead);

  const nextEpoch = publish(f.cp);
  const secondUntil = Date.now() + 5000;
  while (Date.now() < secondUntil && current(f.node).applied_epoch < nextEpoch) {
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.equal(current(f.node).applied_epoch, nextEpoch);
  const ackUntil = Date.now() + 2000;
  while (Date.now() < ackUntil && !f.cp.prepare('SELECT 1 FROM node_acks WHERE node_id=? AND epoch=?').get('A', nextEpoch)) {
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.ok(f.cp.prepare('SELECT 1 FROM node_acks WHERE node_id=? AND epoch=?').get('A', nextEpoch));
  assert.equal(fs.statSync(f.L.node('A').key.private).mode & 0o777, 0o600);
});

test('registry approval publishes a signed policy to all three nodes', async (t) => {
  const home = freshHome();
  let cluster;
  const oldHome = process.env.KIG_HOME, oldPorts = process.env.KIG_PORT_BASE;
  const nodeDbs = [];
  let cpDb;
  t.after(async () => {
    for (const db of [...nodeDbs, cpDb].filter(Boolean)) db.close();
    if (cluster) await cluster.stop();
    if (oldHome === undefined) delete process.env.KIG_HOME; else process.env.KIG_HOME = oldHome;
    if (oldPorts === undefined) delete process.env.KIG_PORT_BASE; else process.env.KIG_PORT_BASE = oldPorts;
    fs.rmSync(home, { recursive: true, force: true });
  });

  cluster = await startCluster(home);
  process.env.KIG_HOME = home;
  process.env.KIG_PORT_BASE = String(new URL(cluster.cpUrl).port);
  const L = layout(home);
  cpDb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
  for (const id of NODE_IDS) nodeDbs.push(openDb(L.node(id).db, { create: false, version: nodeSchema.VERSION, init: nodeSchema.init }));

  const registry = require('../../src/cp/registry.cjs');
  registry.addAccount(cpDb, 'alice');
  const signPair = provider.sigGenerate();
  const kemPair = provider.kemGenerate();
  const signPk = provider.exportPublic(signPair.publicKey);
  const kemPk = provider.exportPublic(kemPair.publicKey);
  const proof = provider.sign(signPair.privateKey, ENROL.context, encode(ENROL.label, ['alice', 'alice-phone', signPk, kemPk]));
  registry.enrol(cpDb, { account: 'alice', device_id: 'alice-phone', sign_pk: signPk, kem_pk: kemPk, proof });
  registry.approve(cpDb, { device_id: 'alice-phone', operator: true, approval_id: 'first-device' });
  const epoch = Number(require('../../src/store/schema-base.cjs').getMeta(cpDb, 'epoch'));

  const deadline = Date.now() + 5000;
  const { current } = require('../../src/node/policy.cjs');
  while (Date.now() < deadline && nodeDbs.some(db => current(db).applied_epoch < epoch)) {
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  for (const db of nodeDbs) {
    const state = current(db);
    assert.equal(state.applied_epoch, epoch);
    assert.equal(state.lease_valid, true);
    assert.deepEqual(state.snapshot.devices.map(d => d.device_id), ['alice-phone']);
  }
});
