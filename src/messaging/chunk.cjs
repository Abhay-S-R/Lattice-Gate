'use strict';
const provider = require('../crypto/provider.cjs');

const CHUNK_BYTES = 16 * 1024;
const MAX_CHUNKS = 256;
const MAX_MESSAGE_BYTES = 4 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 8 * 1024 * 1024;
const REASSEMBLY_TIMEOUT_MS = 5000;
const MAX_TRACKED_MESSAGES = 4096;

function split(message, { msg_id = provider.random(16).toString('hex') } = {}) {
  const body = Buffer.isBuffer(message) ? Buffer.from(message) : Buffer.from(String(message), 'utf8');
  try {
    if (body.length > MAX_MESSAGE_BYTES) throw new RangeError('message_too_large');
    if (typeof msg_id !== 'string' || !/^[0-9a-f]{32}$/.test(msg_id)) throw new TypeError('invalid_message_id');
    const total = Math.max(1, Math.ceil(body.length / CHUNK_BYTES));
    if (total > MAX_CHUNKS) throw new RangeError('too_many_chunks');
    const chunks = [];
    for (let i = 0; i < total; i++) {
      chunks.push({ msg_id, chunk_idx: i, chunk_total: total,
        plaintext: Buffer.from(body.subarray(i * CHUNK_BYTES, Math.min(body.length, (i + 1) * CHUNK_BYTES))) });
    }
    return chunks;
  } finally { body.fill(0); }
}

class Reassembler {
  constructor(limits = {}) {
    this.chunkBytes = limits.chunkBytes ?? CHUNK_BYTES;
    this.maxChunks = limits.maxChunks ?? MAX_CHUNKS;
    this.maxMessageBytes = limits.maxMessageBytes ?? MAX_MESSAGE_BYTES;
    this.maxBufferedBytes = limits.maxBufferedBytes ?? MAX_BUFFERED_BYTES;
    this.timeoutMs = limits.timeoutMs ?? REASSEMBLY_TIMEOUT_MS;
    for (const [name, value] of Object.entries({ chunkBytes: this.chunkBytes, maxChunks: this.maxChunks,
      maxMessageBytes: this.maxMessageBytes, maxBufferedBytes: this.maxBufferedBytes, timeoutMs: this.timeoutMs })) {
      if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`invalid_${name}`);
    }
    if (this.chunkBytes > CHUNK_BYTES || this.maxChunks > MAX_CHUNKS || this.maxMessageBytes > MAX_MESSAGE_BYTES ||
        this.maxBufferedBytes > MAX_BUFFERED_BYTES || this.timeoutMs > REASSEMBLY_TIMEOUT_MS) throw new RangeError('reassembly_limits_exceed_protocol');
    this.pending = new Map();
    this.completed = new Set();
    this.bufferedBytes = 0;
  }

  discard(key) {
    const item = this.pending.get(key);
    if (!item) return;
    for (const part of item.parts.values()) part.fill(0);
    this.bufferedBytes -= item.bytes;
    this.pending.delete(key);
  }

  expire(now = Date.now()) {
    const failures = [];
    for (const [key, item] of this.pending) {
      if (now - item.startedAt >= this.timeoutMs) {
        failures.push({ state: 'failed', msg_id: item.msgId, reason: 'reassembly_timeout' });
        this.discard(key);
      }
    }
    return failures;
  }

  add(record, plaintext, now = Date.now()) {
    const expired = this.expire(now);
    const result = (value) => expired.length ? { ...value, expired } : value;
    if (!record || typeof record.session_id !== 'string' || !/^[0-9a-f]{32}$/.test(record.session_id) || typeof record.msg_id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(record.msg_id) || !Number.isSafeInteger(record.chunk_idx) ||
        !Number.isSafeInteger(record.chunk_total) || record.chunk_total < 1 || record.chunk_total > this.maxChunks ||
        record.chunk_idx < 0 || record.chunk_idx >= record.chunk_total || !Buffer.isBuffer(plaintext) || plaintext.length > this.chunkBytes) {
      plaintext?.fill?.(0);
      return result({ state: 'failed', msg_id: record?.msg_id, reason: 'invalid_chunk' });
    }
    const key = `${record.session_id}:${record.msg_id}`;
    if (this.completed.has(key)) { plaintext.fill(0); return result({ state: 'failed', msg_id: record.msg_id, reason: 'duplicate_message' }); }
    if (!this.pending.has(key)) {
      if (this.pending.size >= MAX_TRACKED_MESSAGES) { plaintext.fill(0); return result({ state: 'failed', msg_id: record.msg_id, reason: 'message_limit' }); }
      this.pending.set(key, { sessionId: record.session_id, msgId: record.msg_id, total: record.chunk_total,
        startedAt: now, parts: new Map(), bytes: 0 });
    }
    const item = this.pending.get(key);
    if (item.total !== record.chunk_total || item.parts.has(record.chunk_idx)) {
      plaintext.fill(0); this.discard(key);
      return result({ state: 'failed', msg_id: record.msg_id, reason: item.total !== record.chunk_total ? 'chunk_total_mismatch' : 'duplicate_chunk' });
    }
    if (item.bytes + plaintext.length > this.maxMessageBytes || this.bufferedBytes + plaintext.length > this.maxBufferedBytes) {
      plaintext.fill(0); this.discard(key);
      return result({ state: 'failed', msg_id: record.msg_id, reason: 'buffer_limit' });
    }
    item.parts.set(record.chunk_idx, plaintext);
    item.bytes += plaintext.length;
    this.bufferedBytes += plaintext.length;
    if (item.parts.size !== item.total) return result({ state: 'pending', msg_id: record.msg_id, received: item.parts.size, total: item.total });
    const message = Buffer.concat(Array.from({ length: item.total }, (_, i) => item.parts.get(i)));
    this.discard(key);
    this.completed.add(key);
    if (this.completed.size > MAX_TRACKED_MESSAGES) this.completed.delete(this.completed.values().next().value);
    return result({ state: 'delivered', msg_id: record.msg_id, message, reason: null });
  }
}

module.exports = { CHUNK_BYTES, MAX_CHUNKS, MAX_MESSAGE_BYTES, MAX_BUFFERED_BYTES, REASSEMBLY_TIMEOUT_MS, split, Reassembler };
