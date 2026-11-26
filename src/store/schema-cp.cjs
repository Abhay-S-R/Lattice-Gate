'use strict';
const { initBase } = require('./schema-base.cjs');
const { SCHEMA_VERSION_ADAPTER } = require('../core/limits.cjs');

const DDL = `
CREATE TABLE accounts(account TEXT PRIMARY KEY, created_ms INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','disabled'))) STRICT;
CREATE TABLE devices(device_id TEXT PRIMARY KEY, account TEXT NOT NULL, sign_pk BLOB NOT NULL, kem_pk BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')), key_version INTEGER NOT NULL DEFAULT 1, created_ms INTEGER NOT NULL, FOREIGN KEY(account) REFERENCES accounts(account)) STRICT;
CREATE INDEX devices_by_account ON devices(account,status);
CREATE TABLE approvals(approval_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, approver_device TEXT, operator INTEGER NOT NULL, proof BLOB, created_ms INTEGER NOT NULL, FOREIGN KEY(device_id) REFERENCES devices(device_id)) STRICT;
CREATE TABLE files(file_id TEXT PRIMARY KEY, owner_account TEXT NOT NULL, active_version INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL, FOREIGN KEY(owner_account) REFERENCES accounts(account)) STRICT;
CREATE TABLE file_versions(file_id TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','retired','staged')), created_ms INTEGER NOT NULL, PRIMARY KEY(file_id,version), FOREIGN KEY(file_id) REFERENCES files(file_id)) STRICT;
CREATE TABLE grants(file_id TEXT NOT NULL, account TEXT NOT NULL, created_ms INTEGER NOT NULL, PRIMARY KEY(file_id,account), FOREIGN KEY(file_id) REFERENCES files(file_id), FOREIGN KEY(account) REFERENCES accounts(account)) STRICT;
CREATE TABLE envelopes(file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(file_id,version,device_id), FOREIGN KEY(file_id,version) REFERENCES file_versions(file_id,version), FOREIGN KEY(device_id) REFERENCES devices(device_id)) STRICT;
CREATE TABLE custodian_wraps(file_id TEXT NOT NULL, version INTEGER NOT NULL, wrap TEXT NOT NULL, PRIMARY KEY(file_id,version), FOREIGN KEY(file_id,version) REFERENCES file_versions(file_id,version)) STRICT;
`;
/* ---- A: control-plane tables ---- */
const A_DDL = `
CREATE TABLE snapshots(epoch INTEGER PRIMARY KEY, body TEXT NOT NULL, sig BLOB NOT NULL, created_ms INTEGER NOT NULL) STRICT;
CREATE TABLE node_acks(node_id TEXT NOT NULL, epoch INTEGER NOT NULL, acked_ms INTEGER NOT NULL, acked_mono_ns TEXT NOT NULL, sig BLOB NOT NULL, PRIMARY KEY(node_id,epoch)) STRICT;
`;
/* ---- Phase 4: rotation journal, staged acks, cutoffs (docs/plans/phase-4.md §3) ---- */
const P4_DDL = `
CREATE TABLE IF NOT EXISTS rotation_journal(rotation_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('PREPARE','REWRAP','STAGE','COMMIT','DISTRIBUTE','COMPLETE','ABORTED')), file_id TEXT NOT NULL, from_version INTEGER NOT NULL, to_version INTEGER NOT NULL, epoch INTEGER, reason TEXT, ts_ms INTEGER NOT NULL, PRIMARY KEY(rotation_id,phase), FOREIGN KEY(file_id) REFERENCES files(file_id)) STRICT;
CREATE INDEX IF NOT EXISTS rotation_journal_by_file ON rotation_journal(file_id,to_version);
CREATE TABLE IF NOT EXISTS rotation_stage_acks(rotation_id TEXT NOT NULL, node_id TEXT NOT NULL, digest BLOB NOT NULL, sig BLOB NOT NULL, acked_ms INTEGER NOT NULL, PRIMARY KEY(rotation_id,node_id)) STRICT;
CREATE TABLE IF NOT EXISTS file_cutoffs(file_id TEXT PRIMARY KEY, old_version INTEGER NOT NULL, from_epoch INTEGER NOT NULL, grace_ms INTEGER NOT NULL, committed_ms INTEGER NOT NULL, FOREIGN KEY(file_id) REFERENCES files(file_id)) STRICT;
`;

// Phase 4 tables are added in place, never by bumping the schema version (same approach as Phase 3's
// lazy node_acks column and Phase 6's ensureMessaging): a store created before Phase 4 upgrades the
// first time Phase 4 code opens it. CREATE ... IF NOT EXISTS is idempotent, so concurrent processes are safe.
const P4_TABLES = ["rotation_journal","rotation_journal_by_file","rotation_stage_acks","file_cutoffs"];
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
function init(db) { initBase(db); db.exec(DDL); db.exec(A_DDL); db.exec(P4_DDL); }
module.exports = { VERSION: SCHEMA_VERSION_ADAPTER, init, DDL, A_DDL, P4_DDL, ensurePhase4 };
