'use strict';
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const identity = require('./identity.cjs');
const replay = require('./replay.cjs');
const handshake = require('./handshake.cjs');

const MAX_SEQ = 0xffffffffffffffffn;
const MAX_CHUNKS = 256;
function header(session, fields) {
  return encode('kig/v1/record', [handshake.VERSION, handshake.SUITE, session.sessionId,
    fields.sender_account, fields.sender_device, fields.recipient_account, fields.recipient_device,
    fields.epoch, fields.msg_id,
    BigInt(fields.seq), fields.chunk_idx, fields.chunk_total]);
}
function parseSeq(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) throw new Error('invalid_sequence');
  const seq = BigInt(value);
  if (seq > MAX_SEQ) throw new Error('invalid_sequence');
  return seq;
}
function checkSession(session) {
  if (!session || !session.established || session.closed || !['initiator', 'responder'].includes(session.role) ||
      !Buffer.isBuffer(session.sendKey) || !Buffer.isBuffer(session.receiveKey)) {
    throw new Error('session_not_active');
  }
}
function checkChunk(idx, total) {
  if (!Number.isSafeInteger(idx) || !Number.isSafeInteger(total) || total < 1 || total > MAX_CHUNKS || idx < 0 || idx >= total) {
    throw new Error('invalid_chunk_metadata');
  }
}
function nonce(direction, seq) {
  const value = Buffer.alloc(12);
  value.writeUInt32BE(direction === 'i2r' ? 1 : 2, 0);
  value.writeBigUInt64BE(seq, 4);
  return value;
}

function seal(session, message, options = {}) {
  checkSession(session);
  const pair = identity.assertPairActive(session.home, session.deviceId, session.peerDevice);
  if (pair.epoch !== session.epoch) throw new Error('stale_session_epoch');
  const plaintext = Buffer.isBuffer(message) ? Buffer.from(message) : Buffer.from(String(message), 'utf8');
  try {
    if (plaintext.length > 16 * 1024) throw new Error('chunk_too_large');
    const msgId = options.msg_id || provider.random(16).toString('hex');
    if (typeof msgId !== 'string' || !/^[0-9a-f]{32}$/.test(msgId)) throw new Error('invalid_message_id');
    const idx = options.chunk_idx ?? 0, total = options.chunk_total ?? 1;
    checkChunk(idx, total);
    if (session.sendSeq > MAX_SEQ || session.sendSeq >= BigInt(replay.MAX_SESSION_MESSAGES)) throw new Error('sequence_exhausted');
    const seq = session.sendSeq++;
    const fields = {
      sender_account: session.account, sender_device: session.deviceId,
      recipient_account: session.peerAccount, recipient_device: session.peerDevice,
      epoch: session.epoch, msg_id: msgId, seq: seq.toString(), chunk_idx: idx, chunk_total: total,
    };
    const direction = session.role === 'initiator' ? 'i2r' : 'r2i';
    return {
      version: handshake.VERSION, suite: handshake.SUITE, session_id: session.sessionId,
      ...fields, ciphertext: provider.aeadSeal(session.sendKey, nonce(direction, seq), header(session, fields), plaintext).toString('base64'),
    };
  } finally { plaintext.fill(0); }
}

function open(session, record, receiverDevice = session?.deviceId) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('invalid_record');
  if (typeof receiverDevice !== 'string' || record.recipient_device !== receiverDevice) throw new Error('wrong_recipient');
  checkSession(session);
  if (receiverDevice !== session.deviceId || record.version !== handshake.VERSION || record.suite !== handshake.SUITE ||
      record.session_id !== session.sessionId || record.sender_device !== session.peerDevice ||
      record.recipient_device !== session.deviceId || record.sender_account !== session.peerAccount ||
      record.recipient_account !== session.account || record.epoch !== session.epoch) throw new Error('record_context_mismatch');
  checkChunk(record.chunk_idx, record.chunk_total);
  if (typeof record.msg_id !== 'string' || !/^[0-9a-f]{32}$/.test(record.msg_id)) throw new Error('invalid_message_id');
  const seq = parseSeq(record.seq);
  const pair = identity.assertPairActive(session.home, session.deviceId, session.peerDevice);
  if (pair.epoch !== session.epoch) throw new Error('stale_session_epoch');
  const direction = session.role === 'responder' ? 'i2r' : 'r2i';
  const encoded = typeof record.ciphertext === 'string' && record.ciphertext.length <= 22000 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(record.ciphertext)
    ? Buffer.from(record.ciphertext, 'base64') : null;
  if (!encoded || encoded.length > 16 * 1024 + 16 || encoded.toString('base64') !== record.ciphertext) throw new Error('invalid_ciphertext');
  const fields = {
    sender_account: record.sender_account, sender_device: record.sender_device,
    recipient_account: record.recipient_account, recipient_device: record.recipient_device,
    epoch: record.epoch, msg_id: record.msg_id, seq: record.seq,
    chunk_idx: record.chunk_idx, chunk_total: record.chunk_total,
  };
  const plaintext = provider.aeadOpen(session.receiveKey, nonce(direction, seq), header(session, fields), encoded);
  try {
    replay.consume(session.home, session.deviceId, {
      sessionId: session.sessionId, peerDevice: session.peerDevice, epoch: session.epoch,
      direction, msgId: `${record.msg_id}:${record.chunk_idx}`, seq,
    });
    return plaintext;
  } catch (e) { plaintext.fill(0); throw e; }
}

module.exports = { seal, open, nonce, header, MAX_CHUNKS };
