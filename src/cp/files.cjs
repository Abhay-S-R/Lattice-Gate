'use strict';
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { tx } = require('../store/db.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const wrap = require('../core/wrap.cjs');
const registry = require('./registry.cjs');
const { WRAP } = require('../core/contracts.cjs');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const nodeSchema = require('../store/schema-node.cjs');
function fileAad(fileId, version) { return encode(WRAP.fileAadLabel, [fileId, version, 'kig/v1/file']); }
function envelopeFields(fileId, version, account, deviceId) { return [fileId, version, account, deviceId, 'kig/v1/envelope']; }
function makeEnvelopes(db, fileId, version, dek, accounts) {
  const rows = registry.listDevices(db).filter(d => d.status === 'active' && accounts.includes(d.account));
  const put = db.prepare('INSERT OR REPLACE INTO envelopes(file_id,version,device_id,envelope) VALUES(?,?,?,?)');
  for (const d of rows) put.run(ids.enc(fileId), version, ids.enc(d.device_id), JSON.stringify(wrap.serialize(wrap.kemWrap(d.kem_pk, dek, envelopeFields(fileId, version, d.account, d.device_id)))));
  return rows.length;
}
function distribute(db, fileId, version, home = contracts.kigHome()) {
  const f = db.prepare('SELECT nonce,ciphertext FROM file_versions WHERE file_id=? AND version=?').get(ids.enc(fileId), version);
  if (!f) throw new Error('file_version_missing');
  const envs = db.prepare('SELECT device_id,envelope FROM envelopes WHERE file_id=? AND version=?').all(ids.enc(fileId), version);
  for (const id of contracts.NODE_IDS) {
    const n = contracts.layout(home).node(id);
    const nd = openDb(n.db, { create: false, version: nodeSchema.VERSION, init: nodeSchema.init });
    try {
      txNode(nd, () => {
        nd.prepare('INSERT OR REPLACE INTO ciphertexts(file_id,version,nonce,ciphertext) VALUES(?,?,?,?)').run(ids.enc(fileId), version, f.nonce, f.ciphertext);
        nd.prepare('DELETE FROM node_envelopes WHERE file_id=? AND version=?').run(ids.enc(fileId), version);
        const ins = nd.prepare('INSERT INTO node_envelopes(file_id,version,device_id,envelope) VALUES(?,?,?,?)');
        for (const e of envs) ins.run(ids.enc(fileId), version, e.device_id, e.envelope);
      });
    } finally { nd.close(); }
  }
}
function txNode(db, fn) { return require('../store/db.cjs').tx(db, fn); }
function publish(db, { file_id, owner_device, plaintext, home = contracts.kigHome() }) {
  let dek;
  try {
    if (typeof file_id !== 'string' || !Buffer.isBuffer(plaintext)) throw new TypeError('invalid file publish request');
    const owner = registry.getDevice(db, owner_device);
    if (!owner || owner.status !== 'active') throw new Error('owner_device_inactive');
    dek = provider.random(32);
    const nonce = provider.random(12), version = 1;
    const ciphertext = provider.aeadSeal(dek, nonce, fileAad(file_id, version), plaintext);
    const layout = contracts.layout(home);
    const masterPriv = provider.importPrivate(require('node:fs').readFileSync(layout.cp.keys.masterKem.key));
    const masterPub = provider.publicFromPrivate(masterPriv);
    const custodian = wrap.serialize(wrap.kemWrap(masterPub, dek, [file_id, version, 'cp']));
    tx(db, () => {
      db.prepare('INSERT INTO files(file_id,owner_account,active_version,created_ms) VALUES(?,?,?,?)').run(ids.enc(file_id), ids.enc(owner.account), version, Date.now());
      db.prepare('INSERT INTO grants(file_id,account,created_ms) VALUES(?,?,?)').run(ids.enc(file_id), ids.enc(owner.account), Date.now());
      db.prepare("INSERT INTO file_versions(file_id,version,nonce,ciphertext,status,created_ms) VALUES(?,?,?,?,'active',?)").run(ids.enc(file_id), version, nonce, ciphertext, Date.now());
      db.prepare('INSERT INTO custodian_wraps(file_id,version,wrap) VALUES(?,?,?)').run(ids.enc(file_id), version, JSON.stringify(custodian));
      makeEnvelopes(db, file_id, version, dek, [owner.account]);
      audit.append(db, { gen: 0, kind: 'file_published', op: 'file.publish', actor: owner_device, asset: file_id, decision: 'allow', rule: 'file_encrypted' });
    });
    distribute(db, file_id, version, home);
    registry.maybePublish(db);
    return { file_id, version, ciphertext_bytes: ciphertext.length };
  } finally { dek?.fill(0); if (Buffer.isBuffer(plaintext)) plaintext.fill(0); }
}
function share(db, { file_id, account, home = contracts.kigHome() }) {
  const file = db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc(file_id));
  if (!file) throw new Error('file_unknown');
  const acct = db.prepare("SELECT 1 FROM accounts WHERE account=? AND status='active'").get(ids.enc(account));
  if (!acct) throw new Error('account_unknown');
  const l = require('../core/contracts.cjs').layout(home);
  const master = provider.importPrivate(require('node:fs').readFileSync(l.cp.keys.masterKem.key));
  const row = db.prepare('SELECT wrap FROM custodian_wraps WHERE file_id=? AND version=?').get(ids.enc(file_id), file.active_version);
  const dek = wrap.kemUnwrap(master, JSON.parse(row.wrap), [file_id, file.active_version, 'cp']);
  try {
    tx(db, () => {
      db.prepare('INSERT OR IGNORE INTO grants(file_id,account,created_ms) VALUES(?,?,?)').run(ids.enc(file_id), ids.enc(account), Date.now());
      makeEnvelopes(db, file_id, file.active_version, dek, [account]);
      audit.append(db, { gen: 0, kind: 'file_shared', op: 'share', actor: account, asset: file_id, decision: 'allow', rule: 'grant_added' });
    });
  } finally { dek.fill(0); }
  distribute(db, file_id, file.active_version, home);
  registry.maybePublish(db);
  return { file_id, account };
}
/**
 * Phase 4 (docs/plans/phase-4.md P4-D10): after a device is approved, issue it an envelope for the
 * ACTIVE version of every file granted to its account. Only an active device is provisioned. If a
 * rotation commits concurrently, its own COMMIT check (P4-D11) already guaranteed this device an
 * envelope for the new version, so a version that moved on is skipped here.
 * @returns {{file_id:string, version:number}[]}
 */
function provisionDevice(db, deviceId, home = contracts.kigHome()) {
  const device = registry.getDevice(db, deviceId);
  if (!device || device.status !== 'active') throw new Error('device_not_active');
  const rows = db.prepare('SELECT f.file_id, f.active_version FROM files f JOIN grants g ON g.file_id=f.file_id WHERE g.account=? AND f.active_version>=1 ORDER BY f.file_id')
    .all(ids.enc(device.account));
  if (!rows.length) return [];
  const master = provider.importPrivate(require('node:fs').readFileSync(contracts.layout(home).cp.keys.masterKem.key));
  const issued = [];
  for (const r of rows) {
    const fileId = ids.dec(r.file_id), version = r.active_version;
    const cust = db.prepare('SELECT wrap FROM custodian_wraps WHERE file_id=? AND version=?').get(r.file_id, version);
    if (!cust) throw new Error('custodian_wrap_missing');
    const dek = wrap.kemUnwrap(master, JSON.parse(cust.wrap), [fileId, version, 'cp']);
    let done = false;
    try {
      done = tx(db, () => {
        const now = db.prepare('SELECT active_version FROM files WHERE file_id=?').get(r.file_id);
        const still = db.prepare("SELECT 1 FROM devices WHERE device_id=? AND status='active'").get(ids.enc(deviceId));
        if (!now || now.active_version !== version || !still) return false;
        db.prepare('INSERT OR REPLACE INTO envelopes(file_id,version,device_id,envelope) VALUES(?,?,?,?)')
          .run(r.file_id, version, ids.enc(deviceId), JSON.stringify(wrap.serialize(wrap.kemWrap(device.kem_pk, dek, envelopeFields(fileId, version, device.account, deviceId)))));
        audit.append(db, { gen: 0, kind: 'envelope_issued', op: 'device.provision', actor: deviceId, asset: fileId, decision: 'allow', rule: 'envelope_issued', detail: { version } });
        return true;
      });
    } finally { dek.fill(0); }
    if (done) { distribute(db, fileId, version, home); issued.push({ file_id: fileId, version }); }
  }
  return issued;
}
module.exports = { publish, share, makeEnvelopes, distribute, fileAad, envelopeFields, provisionDevice };
