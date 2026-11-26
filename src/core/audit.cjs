'use strict';
// Hash-chained, append-only audit log (architecture §4.4, §14.1).
//
//   genesis = SHA-256(encode('kig/v1/genesis', [db_id]))
//   hash_n  = SHA-256(hash_{n-1} ‖ encode('kig/v1/event',
//               [seq, gen, ts_ms, kind, op, request_id, actor, asset, decision, rule, detailJson]))
//
// request_id, actor and asset are client strings: stored D-04 encoded (ids.enc).
// kind, op, decision and rule are fixed vocabulary and stored as-is.
const { encode } = require('./encoding.cjs');
const { sha256 } = require('../crypto/provider.cjs');
const ids = require('./ids.cjs');
const { getMeta } = require('../store/schema-adapter.cjs');

const EVENT_LABEL = 'kig/v1/event';
const GENESIS_LABEL = 'kig/v1/genesis';

const toBuf = (b) => (Buffer.isBuffer(b) ? b : Buffer.from(b));
const encOrNull = (s) => (s == null ? null : ids.enc(s));
const decOrNull = (t) => (t == null ? null : ids.dec(t));

function genesis(db) {
  return sha256(encode(GENESIS_LABEL, [getMeta(db, 'db_id')]));
}

/** Hash over decoded (raw) field values; null for absent fields. */
function eventHash(prev, f) {
  return sha256(Buffer.concat([prev, encode(EVENT_LABEL, [
    f.seq, f.gen, f.ts_ms, f.kind, f.op, f.request_id, f.actor, f.asset, f.decision, f.rule, f.detail,
  ])]));
}

function optString(v, name) {
  if (v == null) return null;
  if (typeof v !== 'string') throw new TypeError(`audit event ${name} must be a string`);
  return v;
}

/**
 * Append one event. Must be called inside tx(db, …) so the event commits
 * atomically with the decision it records.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{ gen: number, kind: string, op?: string, request_id?: string, actor?: string,
 *           asset?: string, decision?: 'allow'|'deny', rule?: string, detail?: object }} ev
 * @returns {{ seq: number, hash: Buffer }}
 */
function append(db, ev) {
  if (!db.isTransaction) throw new Error('audit.append must run inside a transaction');
  if (!Number.isSafeInteger(ev.gen)) throw new TypeError('audit event gen must be an integer');
  if (typeof ev.kind !== 'string') throw new TypeError('audit event kind must be a string');

  const f = {
    gen: ev.gen,
    ts_ms: Date.now(),
    kind: ev.kind,
    op: optString(ev.op, 'op'),
    request_id: optString(ev.request_id, 'request_id'),
    actor: optString(ev.actor, 'actor'),
    asset: optString(ev.asset, 'asset'),
    decision: optString(ev.decision, 'decision'),
    rule: optString(ev.rule, 'rule'),
    detail: ev.detail == null ? null : JSON.stringify(ev.detail),
  };

  const last = db.prepare('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1').get();
  const prev = last ? toBuf(last.hash) : genesis(db);
  f.seq = last ? last.seq + 1 : 1;
  const hash = eventHash(prev, f);

  db.prepare(`INSERT INTO audit_events
    (seq, gen, ts_ms, kind, op, request_id, actor, asset, decision, rule, detail, prev_hash, hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    f.seq, f.gen, f.ts_ms, f.kind, f.op,
    encOrNull(f.request_id), encOrNull(f.actor), encOrNull(f.asset),
    f.decision, f.rule, f.detail, prev, hash);

  return { seq: f.seq, hash };
}

/**
 * Walk the whole chain from genesis.
 * opts.collect: sequence numbers whose hash to return in `hashes` (seq 0 = genesis),
 * used to compare against signed checkpoints (core/checkpoint.cjs).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{ collect?: Iterable<number> }} [opts]
 * @returns {{ ok: true, count: number, head: Buffer, hashes: Map<number, Buffer> } |
 *           { ok: false, seq: number, reason: 'content_edit'|'missing_or_reordered' }}
 */
function verifyChain(db, opts = {}) {
  const want = new Set(opts.collect || []);
  /** @type {Map<number, Buffer>} */
  const hashes = new Map();
  let prev = genesis(db);
  if (want.has(0)) hashes.set(0, prev);
  let expected = 1;
  for (const row of db.prepare('SELECT * FROM audit_events ORDER BY seq').iterate()) {
    if (row.seq !== expected || !toBuf(row.prev_hash).equals(prev)) {
      return { ok: false, seq: expected, reason: 'missing_or_reordered' };
    }
    let h;
    try {
      h = eventHash(prev, {
        seq: row.seq, gen: row.gen, ts_ms: row.ts_ms, kind: row.kind, op: row.op,
        request_id: decOrNull(row.request_id), actor: decOrNull(row.actor), asset: decOrNull(row.asset),
        decision: row.decision, rule: row.rule, detail: row.detail,
      });
    } catch {
      return { ok: false, seq: row.seq, reason: 'content_edit' };
    }
    if (!h.equals(toBuf(row.hash))) return { ok: false, seq: row.seq, reason: 'content_edit' };
    prev = h;
    if (want.has(row.seq)) hashes.set(row.seq, h);
    expected++;
  }
  return { ok: true, count: expected - 1, head: prev, hashes };
}

/**
 * Decision of the most recent access event with this request ID in this generation.
 * @returns {'allow'|'deny'|null}
 */
function latestAccessDecision(db, gen, requestId) {
  const row = db.prepare(`SELECT decision FROM audit_events
    WHERE gen = ? AND request_id = ? AND kind = 'access'
    ORDER BY seq DESC LIMIT 1`).get(gen, ids.enc(requestId));
  return row ? row.decision : null;
}

/** Access denies for this actor in this generation with ts_ms >= sinceMs. */
function countRecentDenies(db, gen, actor, sinceMs) {
  return db.prepare(`SELECT count(*) AS n FROM audit_events
    WHERE gen = ? AND actor = ? AND kind = 'access' AND decision = 'deny' AND ts_ms >= ?`)
    .get(gen, ids.enc(actor), sinceMs).n;
}

module.exports = { append, verifyChain, latestAccessDecision, countRecentDenies };
