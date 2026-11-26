'use strict';
const { initBase } = require('./schema-base.cjs');
const { SCHEMA_VERSION_ADAPTER } = require('../core/limits.cjs');
const DDL = `
CREATE TABLE challenges(nonce BLOB PRIMARY KEY, created_mono_ns TEXT NOT NULL, expires_ms INTEGER NOT NULL) STRICT;
CREATE TABLE used_nonces(nonce BLOB PRIMARY KEY, used_ms INTEGER NOT NULL) STRICT;
CREATE TABLE ciphertexts(file_id TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(file_id,version)) STRICT;
CREATE TABLE node_envelopes(file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(file_id,version,device_id)) STRICT;
/* ---- A: policy and lease tables ---- */
CREATE TABLE policy(epoch INTEGER PRIMARY KEY, body TEXT NOT NULL, sig BLOB NOT NULL, applied_ms INTEGER NOT NULL, applied_mono_ns TEXT NOT NULL) STRICT;
CREATE TABLE lease(k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;
`;
/* ---- Phase 4: cutoffs (node-local grace) and chunked transfers ---- */
const P4_DDL = `
CREATE TABLE IF NOT EXISTS cutoffs(file_id TEXT NOT NULL, old_version INTEGER NOT NULL, from_epoch INTEGER NOT NULL, grace_ms INTEGER NOT NULL, applied_mono_ns TEXT NOT NULL, applied_ms INTEGER NOT NULL, PRIMARY KEY(file_id,old_version)) STRICT;
CREATE TABLE IF NOT EXISTS transfers(transfer_id TEXT PRIMARY KEY, file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, account TEXT NOT NULL, created_mono_ns TEXT NOT NULL, created_ms INTEGER NOT NULL, chunk_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','terminated')), reason TEXT) STRICT;
CREATE INDEX IF NOT EXISTS transfers_by_device ON transfers(device_id,state);
`;

// Phase 4 tables are added in place, never by bumping the schema version (same approach as Phase 3's
// lazy node_acks column and Phase 6's ensureMessaging): a store created before Phase 4 upgrades the
// first time Phase 4 code opens it. CREATE ... IF NOT EXISTS is idempotent, so concurrent processes are safe.
const P4_TABLES = ["cutoffs","transfers","transfers_by_device"];
const upgraded = new WeakSet();
function ensurePhase4(db) {
  if (upgraded.has(db)) return;
  const have = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type IN ('table','index')").all().map((r) => r.name));
  if (!P4_TABLES.every((t) => have.has(t))) {
    if (db.isTransaction) db.exec(P4_DDL);
    else require('./db.cjs').tx(db, () => db.exec(P4_DDL));
  }
  upgraded.add(db);
}
function init(db) { initBase(db); db.exec(DDL); db.exec(P4_DDL); }
module.exports = { VERSION: SCHEMA_VERSION_ADAPTER, init, DDL, P4_DDL, ensurePhase4 };
