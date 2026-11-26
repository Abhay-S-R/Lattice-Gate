'use strict';
// Adapter database schema v1 (architecture §5.4).
// All client strings in these tables are D-04 encoded (ids.enc).
const path = require('node:path');
const { random } = require('../crypto/provider.cjs');
const { SCHEMA_VERSION_ADAPTER } = require('../core/limits.cjs');
const { StateError } = require('./db.cjs');

const VERSION = SCHEMA_VERSION_ADAPTER;

const DDL = `
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;

CREATE TABLE assets (
  asset  TEXT PRIMARY KEY,
  owner  TEXT,
  body   TEXT
) STRICT;

CREATE TABLE revoked_actors (
  actor  TEXT PRIMARY KEY,
  source TEXT NOT NULL CHECK (source IN ('setup_disabled','revoke')),
  epoch  INTEGER NOT NULL
) STRICT;

CREATE TABLE audit_events (
  seq        INTEGER PRIMARY KEY,
  gen        INTEGER NOT NULL,
  ts_ms      INTEGER NOT NULL,
  kind       TEXT NOT NULL,
  op         TEXT,
  request_id TEXT,
  actor      TEXT,
  asset      TEXT,
  decision   TEXT CHECK (decision IN ('allow','deny') OR decision IS NULL),
  rule       TEXT,
  detail     TEXT,
  prev_hash  BLOB NOT NULL,
  hash       BLOB NOT NULL
) STRICT;
CREATE INDEX audit_by_req   ON audit_events(gen, request_id, seq);
CREATE INDEX audit_by_actor ON audit_events(gen, actor, ts_ms);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
`;

/**
 * Create schema v1. Called by openDb inside its creation transaction.
 * @param {import('node:sqlite').DatabaseSync} db
 */
function init(db) {
  db.exec(DDL);
  const put = db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)');
  put.run('db_id', random(16).toString('hex'));
  put.run('current_gen', '0');
  put.run('epoch', '0');
}

/** @returns {string} throws StateError('corrupt') if the key is absent */
function getMeta(db, k) {
  const row = db.prepare('SELECT v FROM meta WHERE k = ?').get(k);
  if (!row) throw new StateError('corrupt', new Error(`meta key missing: ${k}`));
  return row.v;
}

function setMeta(db, k, v) {
  db.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').run(k, String(v));
}

/** @param {string} stateDir */
const adapterDbPath = (stateDir) => path.join(stateDir, 'kig', 'adapter.db');

module.exports = { VERSION, init, getMeta, setMeta, adapterDbPath };
