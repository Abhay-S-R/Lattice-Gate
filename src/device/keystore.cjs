'use strict';
const fs = require('node:fs');
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-device.cjs');
const provider = require('../crypto/provider.cjs');
function openDeviceDb(home, deviceId, create = true) {
  const l = contracts.layout(home); const d = l.device(deviceId);
  fs.mkdirSync(d.dir, { recursive: true, mode: 0o700 });
  const db = openDb(d.db, { create, version: schema.VERSION, init: schema.init });
  if (create) fs.chmodSync(d.db, 0o600);
  return db;
}
function create(home, deviceId) {
  const db = openDeviceDb(home, deviceId, true);
  try {
    if (db.prepare('SELECT 1 FROM keys WHERE name=?').get('sign_private')) throw new Error('device keys already exist');
    const signing = provider.sigGenerate(), kem = provider.kemGenerate();
    const ins = db.prepare('INSERT INTO keys(name,value) VALUES(?,?)');
    ins.run('sign_private', provider.exportPrivate(signing.privateKey)); ins.run('sign_public', provider.exportPublic(signing.publicKey));
    ins.run('kem_private', provider.exportPrivate(kem.privateKey)); ins.run('kem_public', provider.exportPublic(kem.publicKey));
    fs.chmodSync(contracts.layout(home).device(deviceId).dir, 0o700);
    return { signPublic: provider.exportPublic(signing.publicKey), kemPublic: provider.exportPublic(kem.publicKey) };
  } finally { db.close(); }
}
function load(home, deviceId) {
  const db = openDeviceDb(home, deviceId, false);
  try {
    const rows = Object.create(null);
    for (const r of db.prepare('SELECT name,value FROM keys').all()) rows[r.name] = Buffer.from(r.value);
    if (!rows.sign_private || !rows.kem_private || !rows.sign_public || !rows.kem_public) throw new Error('device keystore incomplete');
    const pin = db.prepare("SELECT value FROM pinned WHERE name='cp_policy'").get();
    return { signPrivate: provider.importPrivate(rows.sign_private), signPublic: provider.importPublic(rows.sign_public), kemPrivate: provider.importPrivate(rows.kem_private), kemPublic: provider.importPublic(rows.kem_public), pinnedPolicy: pin ? Buffer.from(pin.value) : null };
  } finally { db.close(); }
}
function pinPolicy(home, deviceId, publicDer) {
  const db = openDeviceDb(home, deviceId);
  try { db.prepare("INSERT INTO pinned(name,value) VALUES('cp_policy',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value").run(publicDer); } finally { db.close(); }
}
module.exports = { create, load, pinPolicy, openDeviceDb };
