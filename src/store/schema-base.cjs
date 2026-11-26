'use strict';
// Phase 3 store base. Keep this DDL byte-for-byte aligned with schema-adapter.cjs.
const { random } = require('../crypto/provider.cjs');

const BASE_DDL = `
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;
CREATE TABLE audit_events (
  seq INTEGER PRIMARY KEY, gen INTEGER NOT NULL, ts_ms INTEGER NOT NULL,
  kind TEXT NOT NULL, op TEXT, request_id TEXT, actor TEXT, asset TEXT,
  decision TEXT CHECK (decision IN ('allow','deny') OR decision IS NULL),
  rule TEXT, detail TEXT, prev_hash BLOB NOT NULL, hash BLOB NOT NULL
) STRICT;
CREATE INDEX audit_by_req ON audit_events(gen, request_id, seq);
CREATE INDEX audit_by_actor ON audit_events(gen, actor, ts_ms);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
`;

function initBase(db) {
  db.exec(BASE_DDL);
  const put = db.prepare('INSERT INTO meta(k,v) VALUES(?,?)');
  put.run('db_id', random(16).toString('hex'));
  put.run('current_gen', '0');
  put.run('epoch', '0');
}
function getMeta(db, key) {
  const row = db.prepare('SELECT v FROM meta WHERE k=?').get(key);
  if (!row) throw new Error(`meta key missing: ${key}`);
  return row.v;
}
function setMeta(db, key, value) {
  db.prepare('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(key, String(value));
}
module.exports = { BASE_DDL, initBase, getMeta, setMeta };
