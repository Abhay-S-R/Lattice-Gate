'use strict';
const fs = require('node:fs');
const { tx } = require('../store/db.cjs');
const { getMeta, setMeta } = require('../store/schema-base.cjs');
const { layout, ports, url, NODE_IDS, SNAPSHOT } = require('../core/contracts.cjs');
const ids = require('../core/ids.cjs');
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
    files: registry.listFiles(cpDb).map((f) => ({ file_id: f.file_id, active_version: f.active_version, cutoff: cutoffFor(cpDb, f.file_id) })),
    grants: registry.listGrants(cpDb),
  };
}

/** Phase 4 cutoff for a file (§10.1): the latest committed rotation's old version, or null. */
function cutoffFor(cpDb, fileId) {
  const row = cpDb.prepare('SELECT old_version, from_epoch, grace_ms FROM file_cutoffs WHERE file_id=?').get(ids.enc(fileId));
  return row ? { old_version: row.old_version, from_epoch: row.from_epoch, grace_ms: row.grace_ms } : null;
}

function signSnapshot(snapshot, privateKey) {
  const sig = provider.sign(privateKey, SNAPSHOT.context, signatureBytes(snapshot));
  return { snapshot, sig };
}

function latest(cpDb) {
  const row = cpDb.prepare('SELECT epoch,body,sig FROM snapshots ORDER BY epoch DESC LIMIT 1').get();
  return row ? { snapshot: JSON.parse(row.body), sig: Buffer.from(row.sig) } : null;
}

function recordAck(cpDb, ack, env = process.env, arrivedMonoNs = process.hrtime.bigint().toString()) {
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
  // M4 adds a host-monotonic receipt time for benchmark measurements. Upgrade
  // existing M3 homes lazily; the previous nullable history remains readable.
  if (!cpDb.prepare('PRAGMA table_info(node_acks)').all().some((column) => column.name === 'acked_mono_ns')) {
    tx(cpDb, () => cpDb.exec('ALTER TABLE node_acks ADD COLUMN acked_mono_ns TEXT'));
  }
  tx(cpDb, () => cpDb.prepare('INSERT INTO node_acks(node_id,epoch,acked_ms,acked_mono_ns,sig) VALUES(?,?,?,?,?) ON CONFLICT(node_id,epoch) DO UPDATE SET acked_ms=excluded.acked_ms,acked_mono_ns=excluded.acked_mono_ns,sig=excluded.sig')
    .run(ack.node_id, ack.epoch, Date.now(), String(arrivedMonoNs), Buffer.from(ack.sig, 'base64')));
  return true;
}

function policyKey(env = process.env) {
  return provider.importPrivate(fs.readFileSync(layout(require('../core/contracts.cjs').kigHome(env)).cp.keys.policy.key));
}

/**
 * Build, sign and store the next snapshot and advance the epoch. Must run inside the caller's
 * transaction (Phase 4 COMMIT: the epoch change commits together with the rotation, P4-D3).
 */
function commitInTx(cpDb, privateKey) {
  if (!cpDb.isTransaction) throw new Error('commitInTx must run inside a transaction');
  const snapshot = buildSnapshot(cpDb);
  const signed = signSnapshot(snapshot, privateKey);
  cpDb.prepare('INSERT INTO snapshots(epoch,body,sig,created_ms) VALUES(?,?,?,?)')
    .run(snapshot.epoch, JSON.stringify(snapshot), signed.sig, Date.now());
  setMeta(cpDb, 'epoch', snapshot.epoch);
  return signed;
}

/** POST a signed snapshot to one node; resolves to the node's answer, rejects if unreachable. */
function pushTo(id, signed, env = process.env, { timeoutMs } = {}) {
  return call(`${url(ports(env)[id])}${POLICY_PUSH_PATH}`, 'POST', {
    snapshot: signed.snapshot, sig: Buffer.isBuffer(signed.sig) ? signed.sig.toString('base64') : signed.sig,
  }, timeoutMs ? { timeoutMs } : {});
}

function publish(cpDb, { env = process.env } = {}) {
  const privateKey = policyKey(env);
  const signed = tx(cpDb, () => commitInTx(cpDb, privateKey));
  for (const id of NODE_IDS) pushTo(id, signed, env).catch(() => {});
  return signed.snapshot.epoch;
}

/** Highest epoch each node has acknowledged (Phase 4 DISTRIBUTE waits for every node ≥ E). */
function ackedEpochs(cpDb) {
  const out = Object.fromEntries(NODE_IDS.map((id) => [id, 0]));
  for (const r of cpDb.prepare('SELECT node_id, max(epoch) AS e FROM node_acks GROUP BY node_id').all()) {
    if (NODE_IDS.includes(r.node_id)) out[r.node_id] = Number(r.e);
  }
  return out;
}

module.exports = { buildSnapshot, signSnapshot, publish, latest, recordAck, signatureBytes, commitInTx, pushTo, policyKey, ackedEpochs, cutoffFor };
