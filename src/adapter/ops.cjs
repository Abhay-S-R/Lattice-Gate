'use strict';
// The five adapter operations (architecture §5.5).
//
// Ownership (docs/split_phase1.md): setup, revoke, audit → A; read, protectedRead → B.
// Keep one exported function per op, in this order. Edit only the ops you own.
//
// Each op receives a req already checked by validate.cjs, and ctx = { stateDir }.
// Ops throw on failure; index.cjs (Task 1.14) maps errors to responses and exit codes
// per the D-13 table (architecture §5.6).
const fs = require('node:fs');
const path = require('node:path');
const { openDb, tx, quarantine, StateError } = require('../store/db.cjs');
const schema = require('../store/schema-adapter.cjs');
const audit = require('../core/audit.cjs');
const ids = require('../core/ids.cjs');
const { authorizeOwnerRead } = require('../core/policy.cjs');
const provider = require('../crypto/provider.cjs');
const alerts = require('../core/alerts.cjs');
const { hostileIds } = require('./validate.cjs');

// ---------------------------------------------------------------- shared helpers

/** Open <stateDir>/kig/adapter.db. create=false never creates the file or the directory. */
function openAdapterDb(stateDir, create) {
  if (create) fs.mkdirSync(path.join(stateDir, 'kig'), { recursive: true, mode: 0o700 });
  return openDb(schema.adapterDbPath(stateDir), { create, version: schema.VERSION, init: schema.init });
}

const currentGen = (db) => Number(schema.getMeta(db, 'current_gen'));

/** epoch += 1 (monotonic across generations); returns the new value. */
function bumpEpoch(db) {
  const epoch = Number(schema.getMeta(db, 'epoch')) + 1;
  schema.setMeta(db, 'epoch', String(epoch));
  return epoch;
}

const isUnusable = (e) => e instanceof StateError && (e.kind === 'corrupt' || e.kind === 'schema');

/** Run fn(db) and always close the DB. */
function using(db, fn) {
  try { return fn(db); } finally { db.close(); }
}

// ---------------------------------------------------------------- setup (A, Task 1.8)

/**
 * Start a new generation from the supplied data (D-01): replaces assets and the
 * revoked set; the audit log and epoch carry on. Throws only if state can't be persisted.
 * @param {{ stateDir: string }} ctx
 * @param {{ owners: Map<string,string>, contents: Map<string,string>, disabled: Set<string> }} req
 * @returns {Promise<{ ready: true }>}
 */
async function setup(ctx, req) {
  const dbPath = schema.adapterDbPath(ctx.stateDir);
  let quarantined = false;
  let db;
  try {
    db = openAdapterDb(ctx.stateDir, true);
  } catch (e) {
    if (!isUnusable(e)) throw e;
    quarantine(dbPath);
    quarantined = true;
    db = openAdapterDb(ctx.stateDir, true);
  }

  using(db, () => tx(db, () => {
    const gen = currentGen(db) + 1;
    schema.setMeta(db, 'current_gen', String(gen));
    db.exec('DELETE FROM assets');
    db.exec('DELETE FROM revoked_actors');

    const insAsset = db.prepare('INSERT INTO assets (asset, owner, body) VALUES (?, ?, ?)');
    const assetIds = new Set([...req.owners.keys(), ...req.contents.keys()]);
    for (const asset of assetIds) {
      insAsset.run(
        ids.enc(asset),
        req.owners.has(asset) ? ids.enc(req.owners.get(asset)) : null,
        req.contents.has(asset) ? ids.enc(req.contents.get(asset)) : null,
      );
    }

    const epoch = bumpEpoch(db);
    const insRevoked = db.prepare(`INSERT INTO revoked_actors (actor, source, epoch)
      VALUES (?, 'setup_disabled', ?) ON CONFLICT (actor) DO NOTHING`);
    for (const actor of req.disabled) insRevoked.run(ids.enc(actor), epoch);

    audit.append(db, { gen, kind: 'setup', detail: { assets: assetIds.size, disabled: req.disabled.size } });
    alerts.record(db, gen, { op: 'setup' }, { op: 'setup', hostile: hostileIds(req) });
    if (quarantined) {
      audit.append(db, {
        gen, kind: 'alert', rule: 'A-STATE-FAULT', detail: { severity: 'high', reason: 'quarantined' },
      });
    }
  }));
  return { ready: true };
}

// ---------------------------------------------------------------- read (B, Task 1.9)

const DENY = Object.freeze({ decision: 'deny' });

/**
 * Alerts for an access event that was just appended (Task 1.13). Never throws
 * and never affects the decision (alerts.record uses a SAVEPOINT).
 * @param {any} db @param {number} gen
 * @param {{ op: string, request_id?: string|null, actor: string, asset: string }} ev
 * @param {any} req validated req (for hostile IDs)
 * @param {{ decision?: 'allow'|'deny', rule?: string, invalidKey?: boolean, invalidInput?: boolean }} c
 */
function accessAlerts(db, gen, ev, req, c) {
  alerts.record(db, gen, ev, { op: ev.op, actor: ev.actor, asset: ev.asset, hostile: hostileIds(req), ...c });
}

/**
 * Open the store for a read-type op. Returns null when there is no store yet
 * (nothing created). Other state errors propagate (index.cjs answers deny).
 * @param {{ stateDir: string }} ctx
 */
function openExisting(ctx) {
  try {
    return openAdapterDb(ctx.stateDir, false);
  } catch (e) {
    if (e instanceof StateError && e.kind === 'missing') return null;
    throw e;
  }
}

/**
 * Owner read (architecture §5.5). One tx: authorize, record the decision, alerts.
 * No store or generation 0 (no setup yet) → deny without a write.
 * @param {{ stateDir: string }} ctx
 * @param {{ actor: string, asset: string, request_id: string }} req
 * @returns {Promise<{ decision: 'allow', body: string } | { decision: 'deny' }>}
 */
async function read(ctx, req) {
  const db = openExisting(ctx);
  if (!db) return { ...DENY };
  return using(db, () => tx(db, () => {
    const gen = currentGen(db);
    if (gen === 0) return { ...DENY };
    const a = authorizeOwnerRead(db, req.actor, req.asset);
    const ev = { gen, kind: 'access', op: 'read', request_id: req.request_id, actor: req.actor, asset: req.asset };
    audit.append(db, { ...ev, decision: a.decision, rule: a.rule });
    accessAlerts(db, gen, ev, req, { decision: a.decision, rule: a.rule });
    return a.decision === 'allow' ? { decision: 'allow', body: a.body } : { ...DENY };
  }));
}

// ---------------------------------------------------------------- revoke (A, Task 1.10)

/**
 * Persist a revocation. Creates the store (generation 0) if none exists yet, so a
 * revocation is never lost. Idempotent per actor; epoch bumps on every call.
 * Throws if the change can't be persisted: an unpersisted revoke must never be acknowledged.
 * A corrupt store is not quarantined here (only setup does that); the error propagates.
 * @param {{ stateDir: string }} ctx
 * @param {{ actor: string }} req
 * @returns {Promise<{}>}
 */
async function revoke(ctx, req) {
  const db = openAdapterDb(ctx.stateDir, true);
  using(db, () => tx(db, () => {
    const gen = currentGen(db);
    const epoch = bumpEpoch(db);
    db.prepare(`INSERT INTO revoked_actors (actor, source, epoch)
      VALUES (?, 'revoke', ?) ON CONFLICT (actor) DO NOTHING`).run(ids.enc(req.actor), epoch);
    audit.append(db, { gen, kind: 'revoke', actor: req.actor });
    alerts.record(db, gen, { op: 'revoke', actor: req.actor }, { op: 'revoke', hostile: hostileIds(req) });
  }));
  return {};
}

// ---------------------------------------------------------------- audit (A, Task 1.11)

/**
 * Latest access decision for request_id in the current generation (D-02); unknown → deny (D-03).
 * No store yet → deny without creating anything. Other state errors propagate
 * (index.cjs answers with the deny shape).
 * @param {{ stateDir: string }} ctx
 * @param {{ request_id: string }} req
 * @returns {Promise<{ request_id: string, decision: 'allow'|'deny' }>}
 */
async function auditOp(ctx, req) {
  let db;
  try {
    db = openAdapterDb(ctx.stateDir, false);
  } catch (e) {
    if (e instanceof StateError && e.kind === 'missing') return { request_id: req.request_id, decision: 'deny' };
    throw e;
  }
  const found = using(db, () => tx(db, () => {
    const gen = currentGen(db);
    const decision = audit.latestAccessDecision(db, gen, req.request_id);
    audit.append(db, {
      gen, kind: 'audit_query', request_id: req.request_id, rule: decision ? 'hit' : 'audit_lookup_miss',
    });
    alerts.record(db, gen, { op: 'audit', request_id: req.request_id }, { op: 'audit', hostile: hostileIds(req) });
    return decision;
  }));
  return { request_id: req.request_id, decision: found ?? 'deny' };
}

// ---------------------------------------------------------------- protected_read (B, Task 1.12)

/**
 * Protected read (architecture §5.5, P0-07). Order is fixed: authorize, then
 * encapsulate to the caller's ML-KEM-768 key, then prove knowledge of the body.
 *
 * ML-KEM encapsulation is async (WebCrypto), so it can't run inside the
 * synchronous tx helper. Two short transactions instead:
 *   tx #1  authorize; a deny is recorded here and returned.
 *   (out)  encapsulate; proof = hex HMAC-SHA-256(sharedKey, UTF-8(challenge + body)).
 *   tx #2  re-authorize and record. If the decision changed in between (e.g. a
 *          revoke landed), record and return that deny. If tx #2 fails, return
 *          deny: an allow is never returned unless it was recorded.
 * The shared secret is wiped and never stored, logged or returned.
 * @param {{ stateDir: string }} ctx
 * @param {{ actor: string, asset: string, challenge: string, publicKey: Buffer, request_id: string|null }} req
 * @returns {Promise<{ ciphertext: string, proof: string } | { decision: 'deny' }>}
 */
async function protectedRead(ctx, req) {
  const db = openExisting(ctx);
  if (!db) return { ...DENY };
  try {
    const ev = { kind: 'access', op: 'protected_read', request_id: req.request_id ?? undefined, actor: req.actor, asset: req.asset };

    // tx #1: authorize; record a deny right away.
    const first = tx(db, () => {
      const gen = currentGen(db);
      if (gen === 0) return null;
      const a = authorizeOwnerRead(db, req.actor, req.asset);
      if (a.decision === 'deny') {
        audit.append(db, { ...ev, gen, decision: 'deny', rule: a.rule });
        accessAlerts(db, gen, ev, req, { decision: 'deny', rule: a.rule });
      }
      return a;
    });
    if (!first || first.decision === 'deny') return { ...DENY };

    // Outside any transaction: encapsulate and compute the proof.
    let ciphertext, proof;
    try {
      const kem = await provider.kemEncapsulateRaw(req.publicKey);
      try {
        proof = provider.hmacHex(kem.sharedKey, Buffer.from(req.challenge + first.body, 'utf8'));
      } finally {
        kem.sharedKey.fill(0);
      }
      ciphertext = kem.ciphertext.toString('base64');
    } catch (e) {
      if (!(e instanceof provider.InvalidKeyError)) throw e;
      tx(db, () => {
        const gen = currentGen(db);
        audit.append(db, { ...ev, gen, decision: 'deny', rule: 'invalid_public_key' });
        accessAlerts(db, gen, ev, req, { decision: 'deny', rule: 'invalid_public_key', invalidKey: true });
      });
      return { ...DENY };
    }

    // tx #2: re-authorize and record the final decision.
    let allowed;
    try {
      allowed = tx(db, () => {
        const gen = currentGen(db);
        const a = gen === 0 ? null : authorizeOwnerRead(db, req.actor, req.asset);
        const ok = a !== null && a.decision === 'allow' && a.body === first.body;
        const decision = ok ? 'allow' : 'deny';
        const rule = ok ? 'owner_allowed' : (a?.rule ?? 'no_state');
        audit.append(db, { ...ev, gen, decision, rule });
        accessAlerts(db, gen, ev, req, { decision, rule });
        return ok;
      });
    } catch {
      return { ...DENY };
    }
    return allowed ? { ciphertext, proof } : { ...DENY };
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------- invalid input (B, Tasks 1.13/1.14)

/**
 * Record a request that failed validation (§5.3, §5.7), best effort, only where
 * a store already exists (nothing is created). read/protected_read get a deny
 * access event with rule invalid_request, so `audit` can answer for its
 * request_id; every op except setup ("state untouched") gets A-INVALID-INPUT.
 * Only fields that are valid identifiers are passed in.
 * @param {{ stateDir: string }} ctx
 * @param {string} op
 * @param {{ request_id?: string, actor?: string, asset?: string }} f
 */
async function recordInvalid(ctx, op, f) {
  if (op === 'setup') return;
  const db = openExisting(ctx);
  if (!db) return;
  using(db, () => tx(db, () => {
    const gen = currentGen(db);
    const ev = { op, request_id: f.request_id, actor: f.actor, asset: f.asset };
    const c = { op, actor: f.actor, asset: f.asset, invalidInput: true, hostile: hostileIds(f) };
    if (op === 'read' || op === 'protected_read') {
      audit.append(db, { ...ev, gen, kind: 'access', decision: 'deny', rule: 'invalid_request' });
      alerts.record(db, gen, ev, { ...c, decision: 'deny', rule: 'invalid_request' });
    } else {
      alerts.record(db, gen, ev, c);
    }
  }));
}

module.exports = {
  setup, read, revoke, audit: auditOp, protectedRead,
  recordInvalid, openAdapterDb, currentGen, bumpEpoch, using,
};
