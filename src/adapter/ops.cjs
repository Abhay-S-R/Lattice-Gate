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
    if (quarantined) {
      audit.append(db, {
        gen, kind: 'alert', rule: 'A-STATE-FAULT', detail: { severity: 'high', reason: 'quarantined' },
      });
    }
  }));
  return { ready: true };
}

// ---------------------------------------------------------------- read (B, Task 1.9)

async function read(ctx, req) { // eslint-disable-line no-unused-vars
  throw new Error('not implemented');
}

// ---------------------------------------------------------------- revoke (A, Task 1.10)

async function revoke(ctx, req) { // eslint-disable-line no-unused-vars
  throw new Error('not implemented');
}

// ---------------------------------------------------------------- audit (A, Task 1.11)

async function auditOp(ctx, req) { // eslint-disable-line no-unused-vars
  throw new Error('not implemented');
}

// ---------------------------------------------------------------- protected_read (B, Task 1.12)

async function protectedRead(ctx, req) { // eslint-disable-line no-unused-vars
  throw new Error('not implemented');
}

module.exports = { setup, read, revoke, audit: auditOp, protectedRead, openAdapterDb, currentGen, bumpEpoch, using };
