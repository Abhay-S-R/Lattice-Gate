'use strict';
// Lost device: revoke, then re-key every file the device could read (features P1-03; architecture §11).
// Runs inside the control plane so the rotations can be crash-injected like any other (P4-D1).
//
// What this does and does not claim: once every node applied the revocation the lost device gets no
// new content and no new transfers, and the old envelopes it holds cannot open the new versions.
// Plaintext or keys it copied before the loss cannot be recalled.
const { tx } = require('../store/db.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const { NODE_IDS } = require('../core/contracts.cjs');
const registry = require('./registry.cjs');
const { revoke } = require('./revoke.cjs');
const rotation = require('./rotate.cjs');

class LostError extends Error {
  constructor(code) { super(code); this.name = 'LostError'; this.code = code; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Per-node time from the CP commit of the revocation to that node's signed ack (CP monotonic clock). */
async function ackLatency(db, epoch, committedMonoNs, timeoutMs = 5000) {
  const t0 = BigInt(committedMonoNs);
  const out = Object.fromEntries(NODE_IDS.map((id) => [id, null]));
  const end = Date.now() + timeoutMs;
  for (;;) {
    for (const id of NODE_IDS) {
      if (out[id] !== null) continue;
      const row = db.prepare('SELECT min(CAST(acked_mono_ns AS INTEGER)) AS t FROM node_acks WHERE node_id=? AND epoch>=?').get(id, epoch);
      if (row && row.t !== null) out[id] = Number(BigInt(row.t) - t0) / 1e6;
    }
    if (NODE_IDS.every((id) => out[id] !== null) || Date.now() >= end) return out;
    await sleep(5);
  }
}

async function lost(db, deviceId, { env = process.env } = {}) {
  if (!ids.isId(deviceId)) throw new LostError('invalid_device_id');
  const device = registry.getDevice(db, deviceId);
  if (!device) throw new LostError('device_not_found');
  if (device.status === 'pending') throw new LostError('device_not_active');
  let revocation = { already_revoked: true };
  if (device.status === 'active') {
    const r = revoke(db, deviceId, { env });
    revocation = { already_revoked: false, epoch: r.epoch, ack_latency_ms: await ackLatency(db, r.epoch, r.committed_mono_ns) };
  }
  tx(db, () => audit.append(db, { gen: 0, kind: 'device_lost', op: 'device.lost', actor: 'operator', asset: deviceId, decision: 'allow',
    rule: 'lost_device', detail: { already_revoked: revocation.already_revoked } }));
  const fileIds = db.prepare('SELECT f.file_id FROM files f JOIN grants g ON g.file_id=f.file_id WHERE g.account=? AND f.active_version>=1 ORDER BY f.file_id')
    .all(ids.enc(device.account)).map((r) => ids.dec(r.file_id));
  const rotations = [];
  for (const fileId of fileIds) {
    try { rotations.push(await rotation.rotate(db, fileId, { env })); } catch (e) {
      if (!(e instanceof rotation.RotationError)) throw e;
      rotations.push({ file_id: fileId, status: 'aborted', reason: e.code });
    }
  }
  return { device_id: deviceId, account: device.account, revocation, rotations };
}

module.exports = { lost, LostError, ackLatency };
