'use strict';
const fs = require('node:fs');
const { tx } = require('../store/db.cjs');
const { getMeta, setMeta } = require('../store/schema-base.cjs');
const { layout, ports, url, NODE_IDS, SNAPSHOT } = require('../core/contracts.cjs');
const { encode } = require('../core/encoding.cjs');
const provider = require('../crypto/provider.cjs');
const registry = require('./registry.cjs');
const { call } = require('../core/http.cjs');
const POLICY_PUSH_PATH = '/v1/policy';

const signatureBytes = (snapshot) => encode(SNAPSHOT.label, [
  snapshot.epoch, snapshot.issued_at_ms, snapshot.lease_ms,
  JSON.stringify(snapshot.devices), JSON.stringify(snapshot.revoked_devices),
  JSON.stringify(snapshot.files), JSON.stringify(snapshot.grants),
]);

function buildSnapshot(cpDb) {
  const epoch = Number(getMeta(cpDb, 'epoch')) + 1;
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('invalid_policy_epoch');
  const devices = registry.listDevices(cpDb)
    .filter((d) => d.status === 'active' || d.status === 'revoked')
    .map((d) => ({
      device_id: d.device_id, account: d.account,
      sign_pk_sha256: provider.sha256(d.sign_pk).toString('hex'),
      kem_pk_sha256: provider.sha256(d.kem_pk).toString('hex'), status: d.status,
    })).sort((a, b) => a.device_id.localeCompare(b.device_id));
  return {
    epoch,
    issued_at_ms: Date.now(), lease_ms: SNAPSHOT.leaseMs,
    devices, revoked_devices: devices.filter((d) => d.status === 'revoked').map((d) => d.device_id),
    files: registry.listFiles(cpDb).map((f) => ({ file_id: f.file_id, active_version: f.active_version, cutoff: null })),
    grants: registry.listGrants(cpDb),
  };
}

function signSnapshot(snapshot, privateKey) {
  const sig = provider.sign(privateKey, SNAPSHOT.context, signatureBytes(snapshot));
  return { snapshot, sig };
}

function latest(cpDb) {
  const row = cpDb.prepare('SELECT epoch,body,sig FROM snapshots ORDER BY epoch DESC LIMIT 1').get();
  return row ? { snapshot: JSON.parse(row.body), sig: Buffer.from(row.sig) } : null;
}

function recordAck(cpDb, ack, env = process.env) {
  if (!ack || !NODE_IDS.includes(ack.node_id) || !Number.isSafeInteger(ack.epoch) || typeof ack.sig !== 'string') return false;
  const file = layout(require('../core/contracts.cjs').kigHome(env)).node(ack.node_id).key.pub;
  let valid = false;
  try {
    if (!fs.existsSync(file)) return false;
    const pub = provider.importPublic(fs.readFileSync(file));
    valid = provider.verify(pub, SNAPSHOT.context, encode(SNAPSHOT.ackLabel, [ack.node_id, ack.epoch]), Buffer.from(ack.sig, 'base64'));
  } catch { return false; }
  if (!valid) return false;
  if (!cpDb.prepare('SELECT 1 FROM snapshots WHERE epoch=?').get(ack.epoch)) return false;
  tx(cpDb, () => cpDb.prepare('INSERT INTO node_acks(node_id,epoch,acked_ms,sig) VALUES(?,?,?,?) ON CONFLICT(node_id,epoch) DO UPDATE SET acked_ms=excluded.acked_ms,sig=excluded.sig')
    .run(ack.node_id, ack.epoch, Date.now(), Buffer.from(ack.sig, 'base64')));
  return true;
}

function publish(cpDb) {
  const env = process.env;
  const L = layout(require('../core/contracts.cjs').kigHome(env));
  const privateKey = provider.importPrivate(fs.readFileSync(L.cp.keys.policy.key));
  let signed;
  tx(cpDb, () => {
    const snapshot = buildSnapshot(cpDb);
    signed = signSnapshot(snapshot, privateKey);
    cpDb.prepare('INSERT INTO snapshots(epoch,body,sig,created_ms) VALUES(?,?,?,?)')
      .run(snapshot.epoch, JSON.stringify(snapshot), signed.sig, Date.now());
    setMeta(cpDb, 'epoch', snapshot.epoch);
  });
  const ps = ports(env);
  for (const id of NODE_IDS) {
    const node = url(ps[id]);
    call(`${node}${POLICY_PUSH_PATH}`, 'POST', {
      snapshot: signed.snapshot, sig: signed.sig.toString('base64'),
    }).catch(() => {});
  }
  return signed.snapshot.epoch;
}

module.exports = { buildSnapshot, signSnapshot, publish, latest, recordAck, signatureBytes };
