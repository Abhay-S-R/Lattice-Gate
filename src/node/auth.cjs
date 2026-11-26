'use strict';
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { REQUEST, RULES } = require('../core/contracts.cjs');
const { tx } = require('../store/db.cjs');
const audit = require('../core/audit.cjs');
const monotonicNs = () => process.hrtime.bigint().toString();
function challenge(db, { ttlMs = REQUEST.challengeTtlMs } = {}) {
  const nonce = provider.random(REQUEST.nonceBytes);
  const createdMs = Date.now();
  const expiresMs = createdMs + ttlMs;
  tx(db, () => {
    // Keep expired challenges for one TTL so requests can receive nonce_expired
    // instead of becoming indistinguishable from never-issued nonces.
    db.prepare('DELETE FROM challenges WHERE expires_ms<=?').run(createdMs - REQUEST.challengeTtlMs);
    db.prepare('DELETE FROM used_nonces WHERE used_ms<=?').run(createdMs - REQUEST.challengeTtlMs);
    db.prepare('INSERT INTO challenges(nonce,created_mono_ns,expires_ms) VALUES(?,?,?)').run(nonce, monotonicNs(), expiresMs);
  });
  return { nonce: nonce.toString('base64'), expires_ms: expiresMs };
}
function policyState(db, supplied) {
  if (supplied) return supplied;
  try { return require('./policy.cjs').current(db); } catch { return { snapshot: null, applied_epoch: 0, lease_valid: false }; }
}
function findDevice(snapshot, id) { return snapshot && snapshot.devices && snapshot.devices.find(d => d.device_id === id) || null; }
function authenticate(db, req, options = {}) {
  if (!req || typeof req !== 'object' || Array.isArray(req)) return { ok: false, device: null, rule: RULES.badSignature };
  const state = policyState(db, options.policy);
  let rule = null, device = null;
  const nonce = Buffer.isBuffer(req.nonce) ? req.nonce : Buffer.from(typeof req.nonce === 'string' ? req.nonce : '', 'base64');
  const fields = Object.fromEntries(REQUEST.fields.map(k => [k, k === 'nonce' ? nonce : req[k]]));
  const snapDevice = findDevice(state.snapshot, req.device_id);
  const encNonce = nonce;
  tx(db, () => {
    if (!state.lease_valid) rule = RULES.leaseExpired;
    else if (!snapDevice) rule = RULES.unknownDevice;
    else if (snapDevice.status !== 'active' || (state.snapshot.revoked_devices || []).includes(req.device_id)) rule = RULES.deviceRevoked;
    else {
      const ch = nonce.length === REQUEST.nonceBytes ? db.prepare('SELECT expires_ms FROM challenges WHERE nonce=?').get(encNonce) : null;
      const used = nonce.length === REQUEST.nonceBytes && db.prepare('SELECT 1 FROM used_nonces WHERE nonce=?').get(encNonce);
      if (!ch) rule = used ? RULES.nonceReused : RULES.nonceUnknown;
      else if (ch.expires_ms <= Date.now()) { db.prepare('DELETE FROM challenges WHERE nonce=?').run(encNonce); rule = RULES.nonceExpired; }
      else {
        db.prepare('DELETE FROM challenges WHERE nonce=?').run(encNonce);
        db.prepare('INSERT INTO used_nonces(nonce,used_ms) VALUES(?,?)').run(encNonce, Date.now());
        let good = false;
        try {
          const pubDer = req.sign_pk ? Buffer.from(req.sign_pk, 'base64') : null;
          const hash = pubDer && provider.sha256(pubDer).toString('hex');
          good = req.version === REQUEST.version && req.account === snapDevice.account && !!pubDer &&
            hash === snapDevice.sign_pk_sha256 &&
            provider.verify(provider.importPublic(pubDer), REQUEST.context, encode(REQUEST.label, REQUEST.fields.map(k => fields[k])), Buffer.from(req.sig || '', 'base64'));
        } catch { good = false; }
        if (!good) rule = RULES.badSignature;
        else {
          device = { ...snapDevice, key_version: Number(req.key_version) };
          const file = state.snapshot.files?.find(f => f.file_id === req.resource);
          if (Number.isSafeInteger(file?.active_version) && Number(req.key_version) !== file.active_version) rule = RULES.oldKeyVersion;
          if (!rule && req.op === 'file.read' && !(state.snapshot.grants || []).some(g => g.file_id === req.resource && g.account === snapDevice.account)) rule = RULES.notGranted;
        }
      }
    }
    if (rule) audit.append(db, { gen: 0, kind: 'access', op: typeof req.op === 'string' ? req.op : 'auth', request_id: typeof req.request_id === 'string' ? req.request_id : null, actor: typeof req.device_id === 'string' ? req.device_id : null, asset: typeof req.resource === 'string' ? req.resource : null, decision: 'deny', rule });
    else audit.append(db, { gen: 0, kind: 'access', op: req.op, request_id: req.request_id, actor: req.device_id, asset: req.resource, decision: 'allow', rule: RULES.allowed });
  });
  return rule ? { ok: false, device: null, rule } : { ok: true, device, rule: RULES.allowed };
}
module.exports = { challenge, authenticate, transcript: (fields) => encode(REQUEST.label, REQUEST.fields.map(k => fields[k])) };
