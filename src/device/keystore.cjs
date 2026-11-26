'use strict';
const fs = require('node:fs');
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb, tx } = require('../store/db.cjs');
const schema = require('../store/schema-device.cjs');
const provider = require('../crypto/provider.cjs');
function openDeviceDb(home, deviceId, create = true) {
  const l = contracts.layout(home); const d = l.device(deviceId);
  if (create) fs.mkdirSync(d.dir, { recursive: true, mode: 0o700 });
  const db = openDb(d.db, { create, version: schema.VERSION, init: schema.init });
  if (create) fs.chmodSync(d.db, 0o600);
  return db;
}
function create(home, deviceId) {
  const db = openDeviceDb(home, deviceId, true);
  try {
    const keys = tx(db, () => {
      const rows = Object.create(null);
      for (const row of db.prepare('SELECT name,value FROM keys').all()) rows[row.name] = Buffer.from(row.value);
      const names = ['sign_private', 'sign_public', 'kem_private', 'kem_public'];
      if (names.some((name) => rows[name])) {
        if (names.some((name) => !rows[name])) throw new Error('device keystore incomplete');
        return { signPublic: rows.sign_public, kemPublic: rows.kem_public };
      }
      const signing = provider.sigGenerate(), kem = provider.kemGenerate();
      const generated = {
        sign_private: provider.exportPrivate(signing.privateKey),
        sign_public: provider.exportPublic(signing.publicKey),
        kem_private: provider.exportPrivate(kem.privateKey),
        kem_public: provider.exportPublic(kem.publicKey),
      };
      const ins = db.prepare('INSERT INTO keys(name,value) VALUES(?,?)');
      for (const [name, value] of Object.entries(generated)) ins.run(name, value);
      return { signPublic: generated.sign_public, kemPublic: generated.kem_public };
    });
    fs.chmodSync(contracts.layout(home).device(deviceId).dir, 0o700);
    return keys;
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
  try {
    const existing = db.prepare("SELECT value FROM pinned WHERE name='cp_policy'").get();
    if (existing) {
      if (!Buffer.from(existing.value).equals(publicDer)) throw new Error('policy key pin mismatch');
      return;
    }
    db.prepare("INSERT INTO pinned(name,value) VALUES('cp_policy',?)").run(publicDer);
  } finally { db.close(); }
}
module.exports = { create, load, pinPolicy, openDeviceDb };
