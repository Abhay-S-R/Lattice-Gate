'use strict';
const { initBase } = require('./schema-base.cjs');
const { STORE_VERSIONS } = require('../core/contracts.cjs');
const MESSAGING_DDL = `CREATE TABLE IF NOT EXISTS message_sessions(
  session_id TEXT PRIMARY KEY, peer_device TEXT NOT NULL, epoch INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','active','closed')),
  accepted_messages INTEGER NOT NULL DEFAULT 0 CHECK(accepted_messages BETWEEN 0 AND 65536),
  created_ms INTEGER NOT NULL, closed_ms INTEGER
) STRICT;
CREATE TABLE IF NOT EXISTS message_replay_windows(
  session_id TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('i2r','r2i')),
  max_seq TEXT NOT NULL, bitmap TEXT NOT NULL, PRIMARY KEY(session_id,direction),
  FOREIGN KEY(session_id) REFERENCES message_sessions(session_id)
) STRICT;
CREATE TABLE IF NOT EXISTS message_replay_ids(
  session_id TEXT NOT NULL, direction TEXT NOT NULL CHECK(direction IN ('i2r','r2i')),
  msg_id TEXT NOT NULL, seq TEXT NOT NULL, PRIMARY KEY(session_id,direction,msg_id),
  FOREIGN KEY(session_id) REFERENCES message_sessions(session_id)
) STRICT;
CREATE INDEX IF NOT EXISTS message_replay_ids_by_seq ON message_replay_ids(session_id,direction,seq);`;
const DDL = `CREATE TABLE keys(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE pinned(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
${MESSAGING_DDL}`;
function init(db) { initBase(db); db.exec(DDL); }
function ensureMessaging(db) {
  const present = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('message_sessions','message_replay_windows','message_replay_ids')").all().map((r) => r.name));
  if (present.size !== 3) db.exec(MESSAGING_DDL);
  const index = db.prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name='message_replay_ids_by_seq'").get();
  if (!index) db.exec('CREATE INDEX IF NOT EXISTS message_replay_ids_by_seq ON message_replay_ids(session_id,direction,seq)');
}
module.exports = { VERSION: STORE_VERSIONS.device, init, DDL, MESSAGING_DDL, ensureMessaging };
