'use strict';
// @ts-check
// Signed audit checkpoints and the external anchor (features P1-08, architecture §14.2–14.3).
//
// A checkpoint commits to the chain head at one sequence number:
//   { store_id, seq, head_hash, checkpoint_id, prev_checkpoint_id, sig }
//   sig = ML-DSA-65(key, ctx 'kig/v1/checkpoint',
//                   encode('kig/v1/checkpoint', [store_id, seq, head_hash, checkpoint_id, prev_checkpoint_id]))
// The anchor is a JSON file kept OUTSIDE the store:
//   { version: 1, store_id, public_key: base64 SPKI, checkpoints: [...] }
// It is what makes deletion of the newest records (truncation) and wholesale
// rewrites with recomputed hashes detectable. Trust in the anchor's public key is
// the operator's (whoever can replace the anchor file can replace the key).
const fs = require('node:fs');
const path = require('node:path');
const { encode } = require('./encoding.cjs');
const audit = require('./audit.cjs');
const provider = require('../crypto/provider.cjs');
const { getMeta } = require('../store/schema-adapter.cjs');

const LABEL = 'kig/v1/checkpoint';
const HEX32 = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{32}$/;

class AnchorError extends Error {
  constructor(message) { super(message); this.name = 'AnchorError'; }
}

const payload = (cp) => encode(LABEL, [
  cp.store_id, cp.seq, Buffer.from(cp.head_hash, 'hex'), cp.checkpoint_id, cp.prev_checkpoint_id,
]);

const storeId = (db) => getMeta(db, 'db_id');

/**
 * Sign the current head of a valid chain.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {import('node:crypto').KeyObject} privateKey ML-DSA-65
 * @param {string|null} prevId previous checkpoint_id in the anchor, or null
 */
function signCheckpoint(db, privateKey, prevId) {
  const v = audit.verifyChain(db);
  if (!v.ok) throw new AnchorError(`chain broken at seq ${v.seq} (${v.reason}); not signing`);
  const cp = {
    store_id: storeId(db),
    seq: v.count,
    head_hash: v.head.toString('hex'),
    checkpoint_id: provider.random(16).toString('hex'),
    prev_checkpoint_id: prevId,
  };
  return { ...cp, sig: provider.sign(privateKey, provider.CONTEXTS.checkpoint, payload(cp)).toString('base64') };
}

/** Parse and shape-check an anchor file. Throws AnchorError. */
function readAnchor(file) {
  let a;
  try { a = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { throw new AnchorError('anchor file unreadable or not JSON'); }
  const okCp = (c) => c && typeof c === 'object' && typeof c.store_id === 'string' && Number.isSafeInteger(c.seq) && c.seq >= 0
    && typeof c.head_hash === 'string' && HEX32.test(c.head_hash) && typeof c.checkpoint_id === 'string' && ID.test(c.checkpoint_id)
    && (c.prev_checkpoint_id === null || (typeof c.prev_checkpoint_id === 'string' && ID.test(c.prev_checkpoint_id)))
    && typeof c.sig === 'string';
  if (!a || a.version !== 1 || typeof a.store_id !== 'string' || typeof a.public_key !== 'string'
      || !Array.isArray(a.checkpoints) || !a.checkpoints.every(okCp)) {
    throw new AnchorError('anchor file has an unexpected format');
  }
  return a;
}

/** Write the anchor atomically (temp file + rename in the same directory). */
function writeAnchor(file, anchor) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(anchor, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

/**
 * Check a store against an anchor.
 * Order: anchor integrity (signatures, links, store) → chain → truncation → head match.
 * @returns {{ ok: true, count: number, head: Buffer, checkpoints: number } |
 *           { ok: false, seq: number, reason: 'invalid_checkpoint'|'content_edit'|'missing_or_reordered'|'truncated'|'checkpoint_mismatch' }}
 */
function verifyAgainstAnchor(db, anchor) {
  const bad = (seq) => ({ ok: /** @type {const} */ (false), seq, reason: /** @type {const} */ ('invalid_checkpoint') });
  let pub;
  try { pub = provider.importPublic(Buffer.from(anchor.public_key, 'base64')); } catch { return bad(0); }
  const sid = storeId(db);
  if (anchor.store_id !== sid) return bad(0);

  let prevId = null, prevSeq = -1;
  for (const cp of anchor.checkpoints) {
    if (cp.store_id !== sid || cp.prev_checkpoint_id !== prevId || cp.seq < prevSeq) return bad(cp.seq);
    if (!provider.verify(pub, provider.CONTEXTS.checkpoint, payload(cp), Buffer.from(cp.sig, 'base64'))) return bad(cp.seq);
    prevId = cp.checkpoint_id;
    prevSeq = cp.seq;
  }

  const v = audit.verifyChain(db, { collect: anchor.checkpoints.map((c) => c.seq) });
  if (!v.ok) return v;
  for (const cp of anchor.checkpoints) {
    if (cp.seq > v.count) return { ok: false, seq: v.count + 1, reason: 'truncated' };
    const h = v.hashes.get(cp.seq);
    if (!h || h.toString('hex') !== cp.head_hash) return { ok: false, seq: cp.seq, reason: 'checkpoint_mismatch' };
  }
  return { ok: true, count: v.count, head: v.head, checkpoints: anchor.checkpoints.length };
}

module.exports = { signCheckpoint, readAnchor, writeAnchor, verifyAgainstAnchor, AnchorError, storeId };
