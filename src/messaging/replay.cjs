'use strict';
const { tx } = require('../store/db.cjs');
const keystore = require('../device/keystore.cjs');

const WINDOW = 64n;
const MASK = (1n << WINDOW) - 1n;
const MAX_SESSION_MESSAGES = 65536;
const MAX_PERSISTED_SESSIONS = 4096;
const SESSION_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const PENDING_SESSION_TTL_MS = 30000;

function withDeviceDb(home, deviceId, fn) {
  const db = keystore.openDeviceDb(home, deviceId, false);
  try { return fn(db); } finally { db.close(); }
}

function register(home, deviceId, sessionId, peerDevice, epoch, status) {
  if (!/^[0-9a-f]{32}$/.test(sessionId) || typeof peerDevice !== 'string' || !Number.isSafeInteger(epoch) || epoch < 1 ||
      !['pending', 'active'].includes(status)) throw new Error('invalid_session_record');
  return withDeviceDb(home, deviceId, (db) => tx(db, () => {
    const now = Date.now();
    db.prepare("UPDATE message_sessions SET status='closed',closed_ms=? WHERE status='pending' AND created_ms<?")
      .run(now, now - PENDING_SESSION_TTL_MS);
    const expired = db.prepare("SELECT session_id FROM message_sessions WHERE status='closed' AND closed_ms<?")
      .all(now - SESSION_RETENTION_MS).map((r) => r.session_id);
    for (const old of expired) {
      db.prepare('DELETE FROM message_replay_ids WHERE session_id=?').run(old);
      db.prepare('DELETE FROM message_replay_windows WHERE session_id=?').run(old);
      db.prepare('DELETE FROM message_sessions WHERE session_id=?').run(old);
    }
    if (db.prepare('SELECT 1 FROM message_sessions WHERE session_id=?').get(sessionId)) throw new Error('session_id_reused');
    if (Number(db.prepare('SELECT count(*) AS n FROM message_sessions').get().n) >= MAX_PERSISTED_SESSIONS) throw new Error('session_store_limit');
    db.prepare('INSERT INTO message_sessions(session_id,peer_device,epoch,status,created_ms) VALUES(?,?,?,?,?)')
      .run(sessionId, peerDevice, epoch, status, now);
    return true;
  }));
}

function activate(home, deviceId, sessionId) {
  if (!/^[0-9a-f]{32}$/.test(sessionId)) throw new Error('invalid_session_id');
  return withDeviceDb(home, deviceId, (db) => tx(db, () => {
    const result = db.prepare("UPDATE message_sessions SET status='active' WHERE session_id=? AND status='pending'").run(sessionId);
    if (Number(result.changes) !== 1) throw new Error('session_not_pending');
    return true;
  }));
}

function close(home, deviceId, sessionId) {
  if (!/^[0-9a-f]{32}$/.test(sessionId)) throw new Error('invalid_session_id');
  return withDeviceDb(home, deviceId, (db) => tx(db, () => {
    const result = db.prepare("UPDATE message_sessions SET status='closed',closed_ms=? WHERE session_id=? AND status IN ('pending','active')")
      .run(Date.now(), sessionId);
    if (Number(result.changes) !== 1) throw new Error('session_not_open');
    return true;
  }));
}

function isActive(home, deviceId, sessionId, peerDevice, epoch) {
  if (!/^[0-9a-f]{32}$/.test(sessionId)) return false;
  return withDeviceDb(home, deviceId, (db) => {
    const row = db.prepare('SELECT peer_device,epoch,status FROM message_sessions WHERE session_id=?').get(sessionId);
    return !!row && row.status === 'active' && row.peer_device === peerDevice && row.epoch === epoch;
  });
}

function consume(home, deviceId, { sessionId, peerDevice, epoch, direction, msgId, seq }) {
  if (!['i2r', 'r2i'].includes(direction) || !/^[0-9a-f]{32}:[0-9]{1,3}$/.test(msgId) ||
      typeof seq !== 'bigint' || seq < 0n || seq > 0xffffffffffffffffn) throw new Error('invalid_replay_state');
  return withDeviceDb(home, deviceId, (db) => tx(db, () => {
    const session = db.prepare('SELECT peer_device,epoch,status,accepted_messages FROM message_sessions WHERE session_id=?').get(sessionId);
    if (!session || session.status !== 'active' || session.peer_device !== peerDevice || session.epoch !== epoch) throw new Error('session_closed');
    if (Number(session.accepted_messages) >= MAX_SESSION_MESSAGES) throw new Error('session_message_limit');
    if (db.prepare('SELECT 1 FROM message_replay_ids WHERE session_id=? AND direction=? AND msg_id=?').get(sessionId, direction, msgId)) {
      throw new Error('duplicate_message');
    }
    const row = db.prepare('SELECT max_seq,bitmap FROM message_replay_windows WHERE session_id=? AND direction=?').get(sessionId, direction);
    let maxSeq = -1n, bitmap = 0n;
    if (row) { maxSeq = BigInt(row.max_seq); bitmap = BigInt(`0x${row.bitmap}`); }
    if (maxSeq < 0n || seq > maxSeq) {
      const shift = maxSeq < 0n ? WINDOW : seq - maxSeq;
      bitmap = shift >= WINDOW ? 1n : ((bitmap << shift) | 1n) & MASK;
      maxSeq = seq;
    } else {
      const distance = maxSeq - seq;
      if (distance >= WINDOW) throw new Error('sequence_too_old');
      const bit = 1n << distance;
      if ((bitmap & bit) !== 0n) throw new Error('sequence_reused');
      bitmap |= bit;
    }
    db.prepare('INSERT INTO message_replay_ids(session_id,direction,msg_id,seq) VALUES(?,?,?,?)')
      .run(sessionId, direction, msgId, seq.toString());
    db.prepare(`INSERT INTO message_replay_windows(session_id,direction,max_seq,bitmap) VALUES(?,?,?,?)
      ON CONFLICT(session_id,direction) DO UPDATE SET max_seq=excluded.max_seq,bitmap=excluded.bitmap`)
      .run(sessionId, direction, maxSeq.toString(), bitmap.toString(16));
    db.prepare('UPDATE message_sessions SET accepted_messages=accepted_messages+1 WHERE session_id=?').run(sessionId);
    return true;
  }));
}

module.exports = { WINDOW: Number(WINDOW), MAX_SESSION_MESSAGES, MAX_PERSISTED_SESSIONS, SESSION_RETENTION_MS, PENDING_SESSION_TTL_MS, register, activate, close, isActive, consume };
