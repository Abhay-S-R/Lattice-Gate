'use strict';
// Node-side policy state (architecture §10.2, §12.2, §12.3; docs/plans/phase-4.md P4-D7, P4-D13).
//
// applySnapshot, in order: pinned-key signature → well-formed → not stale (epoch > applied in the store
// and ≥ the node's high-water mark) → one transaction that stores the snapshot, sets applied_epoch,
// refreshes the lease, records each new cutoff with this node's monotonic time and terminates open
// transfers of devices that are no longer active. After the commit the high-water file is raised.
//
// High-water file: `<node.db>.epoch`, written atomically after every applied snapshot. A node whose
// store is behind it (an old node.db copied back into place) fails closed until it applies a snapshot
// at least that new, and refuses anything older. Limit: an attacker who controls the whole node
// directory can roll back both files; that is out of scope (threat model).
const fs = require('node:fs');
const { tx } = require('../store/db.cjs');
const { SNAPSHOT, ROTATION } = require('../core/contracts.cjs');
const { encode } = require('../core/encoding.cjs');
const ids = require('../core/ids.cjs');
const provider = require('../crypto/provider.cjs');
const lease = require('./lease.cjs');
const { ensurePhase4 } = require('../store/schema-node.cjs');

function toPublicKey(key) { return Buffer.isBuffer(key) || key instanceof Uint8Array ? provider.importPublic(key) : key; }
function signedBytes(snapshot) {
  return encode(SNAPSHOT.label, [snapshot.epoch, snapshot.issued_at_ms, snapshot.lease_ms,
    JSON.stringify(snapshot.devices), JSON.stringify(snapshot.revoked_devices), JSON.stringify(snapshot.files), JSON.stringify(snapshot.grants)]);
}
const CUTOFF_KEYS = 'from_epoch,grace_ms,old_version';
function validCutoff(c, file, epoch) {
  if (c === null) return true;
  if (!c || typeof c !== 'object' || Array.isArray(c) || Object.keys(c).sort().join(',') !== CUTOFF_KEYS) return false;
  return Number.isSafeInteger(c.old_version) && c.old_version >= 1 && c.old_version < file.active_version &&
    Number.isSafeInteger(c.from_epoch) && c.from_epoch >= 1 && c.from_epoch <= epoch &&
    Number.isSafeInteger(c.grace_ms) && c.grace_ms > 0 && c.grace_ms <= ROTATION.maxGraceMs;
}
function wellFormed(s) {
  if (!(s && Number.isSafeInteger(s.epoch) && s.epoch > 0 && Number.isSafeInteger(s.issued_at_ms) &&
    Number.isSafeInteger(s.lease_ms) && s.lease_ms > 0 && Array.isArray(s.devices) && Array.isArray(s.revoked_devices) &&
    Array.isArray(s.files) && Array.isArray(s.grants) && s.devices.every(d => d && typeof d.device_id === 'string' &&
      typeof d.account === 'string' && /^[0-9a-f]{64}$/.test(d.sign_pk_sha256) && /^[0-9a-f]{64}$/.test(d.kem_pk_sha256) &&
      (d.status === 'active' || d.status === 'revoked')) &&
    s.files.every(f => f && typeof f.file_id === 'string' && Number.isSafeInteger(f.active_version) && f.active_version >= 0 &&
      validCutoff(f.cutoff, f, s.epoch)) &&
    s.grants.every(g => g && typeof g.file_id === 'string' && typeof g.account === 'string'))) return false;
  const deviceIds = s.devices.map(d => d.device_id);
  const fileIds = s.files.map(f => f.file_id);
  const revoked = s.devices.filter(d => d.status === 'revoked').map(d => d.device_id);
  return new Set(deviceIds).size === deviceIds.length && new Set(fileIds).size === fileIds.length &&
    new Set(s.revoked_devices).size === s.revoked_devices.length &&
    revoked.length === s.revoked_devices.length && revoked.every((id, i) => id === s.revoked_devices[i]) &&
    [...s.revoked_devices].sort().every((id, i) => id === s.revoked_devices[i]);
}
function appliedEpoch(db) { return Number(lease.get(db, 'applied_epoch') || 0); }

// ---- high-water mark ----
const hwmPaths = new WeakMap();
/** `<main db file>.epoch`, or null for an in-memory store. */
function highWaterPath(db) {
  if (hwmPaths.has(db)) return hwmPaths.get(db);
  let p = null;
  try {
    const main = db.prepare('PRAGMA database_list').all().find((r) => r.name === 'main');
    p = main && typeof main.file === 'string' && main.file ? `${main.file}.epoch` : null;
  } catch { p = null; }
  hwmPaths.set(db, p);
  return p;
}
/** @returns {{ value: number, corrupt: boolean }} a corrupt mark is treated as "unknown": fail closed until the next apply. */
function readHighWater(db) {
  const p = highWaterPath(db);
  if (!p) return { value: 0, corrupt: false };
  let text;
  try { text = fs.readFileSync(p, 'utf8'); } catch (e) { return e && e.code === 'ENOENT' ? { value: 0, corrupt: false } : { value: 0, corrupt: true }; }
  if (!/^\d{1,15}\n?$/.test(text)) return { value: 0, corrupt: true };
  const value = Number(text.trim());
  return Number.isSafeInteger(value) ? { value, corrupt: false } : { value: 0, corrupt: true };
}
function writeHighWater(db, epoch) {
  const p = highWaterPath(db);
  if (!p) return;
  const prior = readHighWater(db);
  if (!prior.corrupt && prior.value >= epoch) return;
  const tmp = `${p}.tmp-${process.pid}`;
  const fd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeSync(fd, `${epoch}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, p);
}

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
  const s = signed.snapshot;
  ensurePhase4(db); // cutoffs and transfers, on stores created before Phase 4
  if (s.epoch <= appliedEpoch(db) || s.epoch < readHighWater(db).value) return { applied: false, reason: 'stale_epoch' };
  try {
    tx(db, () => {
      if (s.epoch <= appliedEpoch(db)) throw Object.assign(new Error('stale'), { code: 'STALE' });
      const nowMono = process.hrtime.bigint().toString();
      const nowMs = Date.now();
      db.prepare('INSERT INTO policy(epoch,body,sig,applied_ms,applied_mono_ns) VALUES(?,?,?,?,?)')
        .run(s.epoch, JSON.stringify(s), Buffer.isBuffer(signed.sig) ? signed.sig : Buffer.from(signed.sig, 'base64'), nowMs, nowMono);
      lease.set(db, 'applied_epoch', s.epoch);
      lease.refresh(db, s.lease_ms);
      // D-06: the cutoff starts when THIS node applies it; a later snapshot repeating it never resets the clock.
      const cut = db.prepare('INSERT OR IGNORE INTO cutoffs(file_id,old_version,from_epoch,grace_ms,applied_mono_ns,applied_ms) VALUES(?,?,?,?,?,?)');
      for (const f of s.files) if (f.cutoff) cut.run(ids.enc(f.file_id), f.cutoff.old_version, f.cutoff.from_epoch, f.cutoff.grace_ms, nowMono, nowMs);
      // §10.2 step 3: transfers of devices that are not active in this snapshot end now.
      const active = new Set(s.devices.filter((d) => d.status === 'active').map((d) => d.device_id));
      const end = db.prepare("UPDATE transfers SET state='terminated', reason='device_revoked' WHERE transfer_id=? AND state='open'");
      for (const t of db.prepare("SELECT transfer_id, device_id FROM transfers WHERE state='open'").all()) {
        if (!active.has(ids.dec(t.device_id))) end.run(t.transfer_id);
      }
    });
  } catch (e) {
    if (e.code === 'STALE') return { applied: false, reason: 'stale_epoch' };
    return { applied: false, reason: 'apply_failed' };
  }
  // Raised only after the store committed, so the mark never runs ahead of a durable snapshot.
  try { writeHighWater(db, s.epoch); } catch { /* the store's applied_epoch still blocks replays */ }
  return { applied: true, reason: 'applied' };
}
function current(db) {
  try {
    const epoch = appliedEpoch(db);
    const row = epoch ? db.prepare('SELECT body FROM policy WHERE epoch=?').get(epoch) : null;
    const snapshot = row ? JSON.parse(row.body) : null;
    const hw = readHighWater(db);
    const behind = hw.corrupt || epoch < hw.value;
    return { snapshot, applied_epoch: epoch, high_water: hw.value, lease_valid: !!snapshot && !behind && lease.leaseValid(db) };
  } catch { return { snapshot: null, applied_epoch: 0, high_water: 0, lease_valid: false }; }
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
  if (head.epoch < Math.max(appliedEpoch(db), readHighWater(db).value)) return { accepted: false, reason: 'stale_head' };
  const snapshot = current(db).snapshot;
  tx(db, () => {
    lease.refresh(db, snapshot?.lease_ms || SNAPSHOT.leaseMs);
    lease.set(db, 'last_head_epoch', head.epoch);
  });
  return { accepted: true, epoch: head.epoch };
}
module.exports = { applySnapshot, current, acceptHead, appliedEpoch, signedBytes, wellFormed, readHighWater, highWaterPath };
