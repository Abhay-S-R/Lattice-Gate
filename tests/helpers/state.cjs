'use strict';
// Test helpers for in-process op tests (no child process).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb } = require('../../src/store/db.cjs');
const schema = require('../../src/store/schema-adapter.cjs');

/** Fresh empty state dir; ctx for ops. */
function freshCtx() {
  return { stateDir: fs.mkdtempSync(path.join(os.tmpdir(), 'kig-op-')) };
}

/** Build a validated setup req (the shape validate.cjs produces) from plain JSON-like input. */
function setupReq({ owners = {}, contents = {}, disabled = [] } = {}) {
  return {
    owners: new Map(Object.entries(owners)),
    contents: new Map(Object.entries(contents)),
    disabled: new Set(disabled),
  };
}

/** Open the adapter DB of a ctx for inspection (must already exist). */
function openState(ctx) {
  return openDb(schema.adapterDbPath(ctx.stateDir), { create: false, version: schema.VERSION, init: schema.init });
}

/** Run fn(db) on the adapter DB and close it. */
function withState(ctx, fn) {
  const db = openState(ctx);
  try { return fn(db); } finally { db.close(); }
}

/** Every file under dir, recursively. */
function allFiles(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) allFiles(p, out); else out.push(p);
  }
  return out;
}

/** True if any file under dir contains needle (Buffer or string, byte search). */
function stateContains(dir, needle) {
  const n = Buffer.isBuffer(needle) ? needle : Buffer.from(needle, 'utf8');
  return allFiles(dir).some((f) => fs.readFileSync(f).includes(n));
}

module.exports = { freshCtx, setupReq, openState, withState, allFiles, stateContains };
