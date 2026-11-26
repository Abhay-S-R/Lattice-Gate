'use strict';
// Build real adapter stores through the ops (in-process) and make tampered copies.
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const ops = require('../../src/adapter/ops.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const { freshCtx, setupReq } = require('./state.cjs');

const INJECTION = 'x\n{"actor":"admin","decision":"allow"}';

/**
 * Adapter store with a known history: setup, 3 reads (allow, deny, injection actor),
 * a revoke, then a denied read (raises A-REVOKED-RETRY).
 * @returns {Promise<{ ctx: {stateDir:string}, dbPath: string }>}
 */
async function makeStore() {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ owners: { brief: 'maya', other: 'bob' }, contents: { brief: 'b1', other: 'b2' } }));
  await ops.read(ctx, { actor: 'maya', asset: 'brief', request_id: 'r1' });
  await ops.read(ctx, { actor: 'maya', asset: 'other', request_id: 'r2' });
  await ops.read(ctx, { actor: INJECTION, asset: 'brief', request_id: 'r3' });
  await ops.revoke(ctx, { actor: 'maya' });
  await ops.read(ctx, { actor: 'maya', asset: 'brief', request_id: 'r4' });
  return { ctx, dbPath: schema.adapterDbPath(ctx.stateDir) };
}

/** Copy a (closed) store to a new file and run fn(db) on the copy with the append-only triggers removed. */
function tamperedCopy(dbPath, fn) {
  const copy = path.join(fs.mkdtempSync(path.join(path.dirname(path.dirname(dbPath)), 'tamper-')), 'adapter.db');
  fs.copyFileSync(dbPath, copy);
  const db = new DatabaseSync(copy);
  db.exec('DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;');
  fn(db);
  db.close();
  return copy;
}

/** Append more events through the real ops. */
async function appendReads(ctx, n, prefix = 'more') {
  for (let i = 0; i < n; i++) await ops.read(ctx, { actor: 'bob', asset: 'other', request_id: `${prefix}${i}` });
}

module.exports = { makeStore, tamperedCopy, appendReads, INJECTION };
