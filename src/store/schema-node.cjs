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
function init(db) { initBase(db); db.exec(DDL); }
module.exports = { VERSION: SCHEMA_VERSION_ADAPTER, init, DDL };
