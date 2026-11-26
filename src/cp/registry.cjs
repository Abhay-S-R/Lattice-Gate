'use strict';
const { tx } = require('../store/db.cjs');
const audit = require('../core/audit.cjs');
const ids = require('../core/ids.cjs');
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { ENROL } = require('../core/contracts.cjs');
const { setMeta } = require('../store/schema-base.cjs');
const now = () => Date.now();
function maybePublish(db) { try { return require('./snapshot.cjs').publish(db); } catch (e) { if (e.code === 'MODULE_NOT_FOUND') return Number(require('../store/schema-base.cjs').getMeta(db, 'epoch')) + 1; throw e; } }
function addAccount(db, account) {
  if (!ids.isId(account)) throw new TypeError('invalid account');
  tx(db, () => { db.prepare("INSERT INTO accounts(account,created_ms,status) VALUES(?,?,'active')").run(ids.enc(account), now()); audit.append(db, { gen: 0, kind: 'account_added', op: 'account.add', actor: account, decision: 'allow', rule: 'account_created' }); });
  maybePublish(db);
  return account;
}
function listDevices(db) { return db.prepare('SELECT device_id,account,sign_pk,kem_pk,status,key_version FROM devices ORDER BY device_id').all().map(r => ({ device_id: ids.dec(r.device_id), account: ids.dec(r.account), sign_pk: Buffer.from(r.sign_pk), kem_pk: Buffer.from(r.kem_pk), status: r.status, key_version: r.key_version })); }
function getDevice(db, deviceId) { const r = db.prepare('SELECT device_id,account,sign_pk,kem_pk,status,key_version FROM devices WHERE device_id=?').get(ids.enc(deviceId)); return r ? { device_id: ids.dec(r.device_id), account: ids.dec(r.account), sign_pk: Buffer.from(r.sign_pk), kem_pk: Buffer.from(r.kem_pk), status: r.status, key_version: r.key_version } : null; }
function listGrants(db) { return db.prepare('SELECT file_id,account FROM grants ORDER BY file_id,account').all().map(r => ({ file_id: ids.dec(r.file_id), account: ids.dec(r.account) })); }
function listFiles(db) { return db.prepare('SELECT file_id,active_version FROM files ORDER BY file_id').all().map(r => ({ file_id: ids.dec(r.file_id), active_version: r.active_version, cutoff: null })); }
function enrol(db, { account, device_id, sign_pk, kem_pk, proof }) {
  const payload = encode(ENROL.label, [account, device_id, sign_pk, kem_pk]);
  const pub = provider.importPublic(sign_pk);
  if (!provider.verify(pub, ENROL.context, payload, proof)) throw new Error('proof_of_possession');
  const encodedDevice = ids.enc(device_id);
  const created = tx(db, () => {
    if (!db.prepare('SELECT 1 FROM accounts WHERE account=? AND status=?').get(ids.enc(account), 'active')) throw new Error('unknown_account');
    if (db.prepare('SELECT 1 FROM devices WHERE device_id=?').get(encodedDevice)) throw new Error('device_exists');
    db.prepare("INSERT INTO devices(device_id,account,sign_pk,kem_pk,status,key_version,created_ms) VALUES(?,?,?,?,'pending',1,?)").run(encodedDevice, ids.enc(account), sign_pk, kem_pk, now());
    audit.append(db, { gen: 0, kind: 'device_enrol_requested', op: 'device.enrol', actor: account, asset: device_id, decision: 'allow', rule: 'pending_approval' });
    return getDevice(db, device_id);
  });
  maybePublish(db);
  return created;
}
function approvalPayload(deviceId, approver, approvalId) { return encode('kig/v1/enrol-approval', [deviceId, approver, approvalId]); }
function approve(db, { device_id, approver_device = null, operator = false, approval_id, proof = null }) {
  if (typeof approval_id !== 'string' || !approval_id) throw new Error('approval_required');
  const device = getDevice(db, device_id); if (!device || device.status !== 'pending') throw new Error('device_not_pending');
  let approver = null;
  if (!operator) {
    if (!approver_device || approver_device === device_id) throw new Error('invalid_approver');
    approver = getDevice(db, approver_device);
    if (!approver || approver.status !== 'active' || approver.account !== device.account) throw new Error('approver_not_active');
    if (!proof || !provider.verify(provider.importPublic(approver.sign_pk), ENROL.context, approvalPayload(device_id, approver_device, approval_id), proof)) throw new Error('bad_approval_signature');
  }
  tx(db, () => {
    const currentDevice = db.prepare('SELECT account,status FROM devices WHERE device_id=?').get(ids.enc(device_id));
    if (!currentDevice || currentDevice.status !== 'pending' || ids.dec(currentDevice.account) !== device.account) throw new Error('device_not_pending');
    if (!operator) {
      const currentApprover = db.prepare('SELECT account,status FROM devices WHERE device_id=?').get(ids.enc(approver_device));
      if (!currentApprover || currentApprover.status !== 'active' || ids.dec(currentApprover.account) !== device.account) throw new Error('approver_not_active');
    }
    const prior = db.prepare("SELECT count(*) AS n FROM devices WHERE account=? AND status='active'").get(ids.enc(device.account)).n;
    if (prior === 0 && !operator) throw new Error('first_device_requires_operator');
    if (db.prepare("SELECT 1 FROM approvals WHERE approval_id=?").get(ids.enc(approval_id))) throw new Error('approval_reused');
    db.prepare('INSERT INTO approvals(approval_id,device_id,approver_device,operator,proof,created_ms) VALUES(?,?,?,?,?,?)').run(ids.enc(approval_id), ids.enc(device_id), approver_device && ids.enc(approver_device), operator ? 1 : 0, proof, now());
    const updated = db.prepare("UPDATE devices SET status='active' WHERE device_id=? AND status='pending'").run(ids.enc(device_id));
    if (Number(updated.changes) !== 1) throw new Error('device_not_pending');
    audit.append(db, { gen: 0, kind: 'device_enrolled', op: 'device.approve', actor: operator ? 'operator' : approver_device, asset: device_id, decision: 'allow', rule: 'device_active' });
  });
  maybePublish(db);
  return getDevice(db, device_id);
}
module.exports = { addAccount, enrol, approve, listDevices, listGrants, listFiles, getDevice, approvalPayload, maybePublish };
