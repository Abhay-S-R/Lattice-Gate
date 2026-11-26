'use strict';
const { tx } = require('../store/db.cjs');
const { SNAPSHOT } = require('../core/contracts.cjs');
const { encode } = require('../core/encoding.cjs');
const provider = require('../crypto/provider.cjs');
const lease = require('./lease.cjs');

function toPublicKey(key) { return Buffer.isBuffer(key) || key instanceof Uint8Array ? provider.importPublic(key) : key; }
function signedBytes(snapshot) {
  return encode(SNAPSHOT.label, [snapshot.epoch, snapshot.issued_at_ms, snapshot.lease_ms,
    JSON.stringify(snapshot.devices), JSON.stringify(snapshot.revoked_devices), JSON.stringify(snapshot.files), JSON.stringify(snapshot.grants)]);
}
function wellFormed(s) {
  if (!(s && Number.isSafeInteger(s.epoch) && s.epoch > 0 && Number.isSafeInteger(s.issued_at_ms) &&
    Number.isSafeInteger(s.lease_ms) && s.lease_ms > 0 && Array.isArray(s.devices) && Array.isArray(s.revoked_devices) &&
    Array.isArray(s.files) && Array.isArray(s.grants) && s.devices.every(d => d && typeof d.device_id === 'string' &&
      typeof d.account === 'string' && /^[0-9a-f]{64}$/.test(d.sign_pk_sha256) && /^[0-9a-f]{64}$/.test(d.kem_pk_sha256) &&
      (d.status === 'active' || d.status === 'revoked')) &&
    s.files.every(f => f && typeof f.file_id === 'string' && Number.isSafeInteger(f.active_version) && f.active_version >= 0 && f.cutoff === null) &&
    s.grants.every(g => g && typeof g.file_id === 'string' && typeof g.account === 'string'))) return false;
  const deviceIds = s.devices.map(d => d.device_id);
  const revoked = s.devices.filter(d => d.status === 'revoked').map(d => d.device_id);
  return new Set(deviceIds).size === deviceIds.length && new Set(s.revoked_devices).size === s.revoked_devices.length &&
    revoked.length === s.revoked_devices.length && revoked.every((id, i) => id === s.revoked_devices[i]) &&
    [...s.revoked_devices].sort().every((id, i) => id === s.revoked_devices[i]);
}
function appliedEpoch(db) { return Number(lease.get(db, 'applied_epoch') || 0); }
function applySnapshot(db, signed, cpPub) {
  let valid = false;
  try {
    if (signed && signed.snapshot && signed.sig) {
      valid = provider.verify(toPublicKey(cpPub), SNAPSHOT.context, signedBytes(signed.snapshot),
        Buffer.isBuffer(signed.sig) ? signed.sig : Buffer.from(signed.sig, 'base64'));
    }
  } catch { valid = false; }
  if (!valid) return { applied: false, reason: 'bad_signature' };
  if (!wellFormed(signed.snapshot)) return { applied: false, reason: 'invalid_snapshot' };
  if (signed.snapshot.epoch <= appliedEpoch(db)) return { applied: false, reason: 'stale_epoch' };
  try {
    tx(db, () => {
      if (signed.snapshot.epoch <= appliedEpoch(db)) throw Object.assign(new Error('stale'), { code: 'STALE' });
      const nowMono = process.hrtime.bigint().toString();
      db.prepare('INSERT INTO policy(epoch,body,sig,applied_ms,applied_mono_ns) VALUES(?,?,?,?,?)')
        .run(signed.snapshot.epoch, JSON.stringify(signed.snapshot), Buffer.isBuffer(signed.sig) ? signed.sig : Buffer.from(signed.sig, 'base64'), Date.now(), nowMono);
      lease.set(db, 'applied_epoch', signed.snapshot.epoch);
      lease.refresh(db, signed.snapshot.lease_ms);
    });
  } catch (e) {
    if (e.code === 'STALE') return { applied: false, reason: 'stale_epoch' };
    return { applied: false, reason: 'apply_failed' };
  }
  return { applied: true, reason: 'applied' };
}
function current(db) {
  try {
    const epoch = appliedEpoch(db);
    const row = epoch ? db.prepare('SELECT body FROM policy WHERE epoch=?').get(epoch) : null;
    const snapshot = row ? JSON.parse(row.body) : null;
    return { snapshot, applied_epoch: epoch, lease_valid: !!snapshot && lease.leaseValid(db) };
  } catch { return { snapshot: null, applied_epoch: 0, lease_valid: false }; }
}
function acceptHead(db, head, expectedNonce, cpPub) {
  const expected = Buffer.isBuffer(expectedNonce) ? expectedNonce : Buffer.from(expectedNonce || '', 'hex');
  const nonce = Buffer.from(typeof head?.nonce === 'string' ? head.nonce : '', 'hex');
  if (expected.length !== SNAPSHOT.headNonceBytes || nonce.length !== SNAPSHOT.headNonceBytes || !nonce.equals(expected)) {
    return { accepted: false, reason: 'nonce_mismatch' };
  }
  let valid = false;
  try {
    valid = Number.isSafeInteger(head.epoch) && head.epoch >= 0 && provider.verify(toPublicKey(cpPub), SNAPSHOT.context,
      encode(SNAPSHOT.headLabel, [head.epoch, nonce]), Buffer.from(head.sig, 'base64'));
  } catch { valid = false; }
  if (!valid) return { accepted: false, reason: 'bad_signature' };
  if (head.epoch < appliedEpoch(db)) return { accepted: false, reason: 'stale_head' };
  const snapshot = current(db).snapshot;
  tx(db, () => {
    lease.refresh(db, snapshot?.lease_ms || SNAPSHOT.leaseMs);
    lease.set(db, 'last_head_epoch', head.epoch);
  });
  return { accepted: true, epoch: head.epoch };
}
module.exports = { applySnapshot, current, acceptHead, appliedEpoch, signedBytes };
