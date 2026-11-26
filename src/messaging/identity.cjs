'use strict';
const provider = require('../crypto/provider.cjs');
const keystore = require('../device/keystore.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const snapshotApi = require('../cp/snapshot.cjs');
const contracts = require('../core/contracts.cjs');

function signedSnapshot(home, pinnedPolicy) {
  if (!Buffer.isBuffer(pinnedPolicy) || pinnedPolicy.length === 0) throw new Error('policy_key_not_pinned');
  const db = openDb(contracts.layout(home).cp.db, { create: false, version: schema.VERSION, init: schema.init });
  try {
    const signed = snapshotApi.latest(db);
    if (!signed || !signed.snapshot) throw new Error('policy_snapshot_missing');
    const pub = provider.importPublic(pinnedPolicy);
    if (!provider.verify(pub, contracts.SNAPSHOT.context, snapshotApi.signatureBytes(signed.snapshot), signed.sig)) {
      throw new Error('policy_snapshot_invalid');
    }
    const { getMeta } = require('../store/schema-base.cjs');
    if (Number(getMeta(db, 'epoch')) !== signed.snapshot.epoch) throw new Error('policy_snapshot_stale');
    return signed.snapshot;
  } finally { db.close(); }
}

function load(home, deviceId) {
  const keys = keystore.load(home, deviceId);
  const snapshot = signedSnapshot(home, keys.pinnedPolicy);
  const device = snapshot.devices.find((row) => row.device_id === deviceId);
  if (!device || device.status !== 'active') throw new Error('device_not_active');
  const db = openDb(contracts.layout(home).cp.db, { create: false, version: schema.VERSION, init: schema.init });
  try {
    const row = require('../cp/registry.cjs').getDevice(db, deviceId);
    if (!row || row.status !== 'active' || row.account !== device.account ||
        provider.sha256(row.sign_pk).toString('hex') !== device.sign_pk_sha256 ||
        provider.sha256(row.kem_pk).toString('hex') !== device.kem_pk_sha256 ||
        !provider.exportPublic(keys.signPublic).equals(row.sign_pk) || !provider.exportPublic(keys.kemPublic).equals(row.kem_pk)) {
      throw new Error('device_key_binding_invalid');
    }
    return { home, deviceId, account: device.account, epoch: snapshot.epoch, snapshot,
      sign_pk: Buffer.from(row.sign_pk), kem_pk: Buffer.from(row.kem_pk), keys };
  } finally { db.close(); }
}

function assertPairActive(home, localDevice, peerDevice) {
  const local = load(home, localDevice);
  const peer = load(home, peerDevice);
  if (!local.keys.pinnedPolicy.equals(peer.keys.pinnedPolicy)) throw new Error('policy_pin_mismatch');
  if (local.epoch !== peer.epoch) throw new Error('policy_snapshot_mismatch');
  return { local, peer, epoch: local.epoch };
}

module.exports = { signedSnapshot, load, assertPairActive };
