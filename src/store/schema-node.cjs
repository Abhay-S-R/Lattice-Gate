'use strict';
const { initBase } = require('./schema-base.cjs');
const { STORE_VERSIONS } = require('../core/contracts.cjs');
const DDL = `
CREATE TABLE challenges(nonce BLOB PRIMARY KEY, created_mono_ns TEXT NOT NULL, expires_ms INTEGER NOT NULL) STRICT;
CREATE TABLE used_nonces(nonce BLOB PRIMARY KEY, used_ms INTEGER NOT NULL) STRICT;
CREATE TABLE ciphertexts(file_id TEXT NOT NULL, version INTEGER NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(file_id,version)) STRICT;
CREATE TABLE node_envelopes(file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, envelope TEXT NOT NULL, PRIMARY KEY(file_id,version,device_id)) STRICT;
/* ---- A: policy and lease tables ---- */
CREATE TABLE policy(epoch INTEGER PRIMARY KEY, body TEXT NOT NULL, sig BLOB NOT NULL, applied_ms INTEGER NOT NULL, applied_mono_ns TEXT NOT NULL) STRICT;
CREATE TABLE lease(k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;
/* ---- Phase 4: cutoffs (node-local grace) and chunked transfers ---- */
CREATE TABLE cutoffs(file_id TEXT NOT NULL, old_version INTEGER NOT NULL, from_epoch INTEGER NOT NULL, grace_ms INTEGER NOT NULL, applied_mono_ns TEXT NOT NULL, applied_ms INTEGER NOT NULL, PRIMARY KEY(file_id,old_version)) STRICT;
CREATE TABLE transfers(transfer_id TEXT PRIMARY KEY, file_id TEXT NOT NULL, version INTEGER NOT NULL, device_id TEXT NOT NULL, account TEXT NOT NULL, created_mono_ns TEXT NOT NULL, created_ms INTEGER NOT NULL, chunk_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','terminated')), reason TEXT) STRICT;
CREATE INDEX transfers_by_device ON transfers(device_id,state);
`;
function init(db) { initBase(db); db.exec(DDL); }
module.exports = { VERSION: STORE_VERSIONS.node, init, DDL };
