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
function init(db) { initBase(db); db.exec(DDL); /* ---- A: control-plane tables ---- */ }
module.exports = { VERSION: SCHEMA_VERSION_ADAPTER, init, DDL };
