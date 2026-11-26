'use strict';
// SQLite helper shared by every store (architecture §4.3).
// - open with busy timeout, pragmas, schema version check
// - retry the open and the first statement on busy/locked with jitter (cold-start race, P0-03)
// - BEGIN IMMEDIATE transactions so concurrent processes serialise and the audit chain stays linear
// - quarantine (rename, never delete) unusable files
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');
const { BUSY_TIMEOUT_MS, BUSY_RETRIES, JITTER_MIN_MS, JITTER_MAX_MS } = require('../core/limits.cjs');

class StateError extends Error {
  /** @param {'missing'|'corrupt'|'locked'|'schema'} kind @param {unknown} [cause] */
  constructor(kind, cause) {
    super(`state ${kind}`, cause === undefined ? undefined : { cause });
    this.name = 'StateError';
    this.kind = kind;
  }
}

const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;

/** @param {any} err */
function isBusy(err) {
  if (!err || typeof err !== 'object') return false;
  if (typeof err.errcode === 'number') {
    const primary = err.errcode & 0xff;
    return primary === SQLITE_BUSY || primary === SQLITE_LOCKED;
  }
  return /database is locked|database table is locked|SQLITE_BUSY/i.test(String(err.message));
}

const SLEEP_CELL = new Int32Array(new SharedArrayBuffer(4));
function jitterSleep() {
  const ms = JITTER_MIN_MS + Math.floor(Math.random() * (JITTER_MAX_MS - JITTER_MIN_MS + 1));
  Atomics.wait(SLEEP_CELL, 0, 0, ms);
}

/**
 * Run fn, retrying BUSY_RETRIES times on busy/locked errors, then StateError('locked').
 * Non-busy errors are passed to onOther (which must throw).
 */
function withBusyRetry(fn, onOther) {
  for (let attempt = 0; ; attempt++) {
    try {
      return fn();
    } catch (e) {
      if (e instanceof StateError) throw e;
      if (!isBusy(e)) return onOther(e);
      if (attempt >= BUSY_RETRIES) throw new StateError('locked', e);
      jitterSleep();
    }
  }
}

const userVersion = (db) => db.prepare('PRAGMA user_version').get().user_version;

/**
 * @param {string} path
 * @param {{ create: boolean, version: number, init: (db: DatabaseSync) => void }} o
 * @returns {DatabaseSync}
 */
function openDb(path, { create, version, init }) {
  if (!Number.isSafeInteger(version) || version < 1) throw new TypeError('version must be a positive integer');
  // DatabaseSync silently creates missing files, so check first.
  if (!create && !fs.existsSync(path)) throw new StateError('missing');

  return withBusyRetry(() => {
    let db;
    try {
      db = new DatabaseSync(path, { timeout: BUSY_TIMEOUT_MS });
      db.exec('PRAGMA synchronous = FULL');
      db.exec('PRAGMA foreign_keys = ON');
      if (create) {
        // Result is 'wal', or 'delete' where WAL is unavailable; both are acceptable.
        db.prepare('PRAGMA journal_mode = WAL').get();
        tx(db, () => {
          const uv = userVersion(db);
          if (uv === 0) {
            init(db);
            db.exec(`PRAGMA user_version = ${version}`);
          } else if (uv !== version) {
            throw new StateError('schema');
          }
        });
      } else {
        const uv = userVersion(db);
        // A file another process created but has not initialised yet holds no state.
        if (uv === 0) throw new StateError('missing');
        if (uv !== version) throw new StateError('schema');
      }
      return db;
    } catch (e) {
      try { db?.close(); } catch { /* ignore */ }
      throw e;
    }
  }, (e) => { throw new StateError('corrupt', e); });
}

/**
 * Open an existing store read-only, for offline inspection (kig verify-log, alerts, checkpoint).
 * Never creates the file; never writes. Any schema version is accepted (callers check what they need).
 * @param {string} path
 * @returns {DatabaseSync}
 */
function openReadOnly(path) {
  if (!fs.existsSync(path)) throw new StateError('missing');
  return withBusyRetry(() => {
    let db;
    try {
      db = new DatabaseSync(path, { readOnly: true, timeout: BUSY_TIMEOUT_MS });
      if (userVersion(db) === 0) throw new StateError('missing');
      return db;
    } catch (e) {
      try { db?.close(); } catch { /* ignore */ }
      throw e;
    }
  }, (e) => { throw new StateError('corrupt', e); });
}

/**
 * BEGIN IMMEDIATE → fn() → COMMIT; any throw → ROLLBACK and rethrow.
 * fn must be synchronous. Busy at BEGIN is retried; after BUSY_RETRIES → StateError('locked').
 * @template T
 * @param {DatabaseSync} db
 * @param {() => T} fn
 * @returns {T}
 */
function tx(db, fn) {
  withBusyRetry(() => db.exec('BEGIN IMMEDIATE'), (e) => { throw e; });
  try {
    const result = fn();
    if (result && typeof result.then === 'function') throw new TypeError('tx fn must be synchronous');
    db.exec('COMMIT');
    return result;
  } catch (e) {
    if (db.isTransaction) {
      try { db.exec('ROLLBACK'); } catch { /* connection unusable; caller fails closed */ }
    }
    throw e;
  }
}

/**
 * Rename <path>, <path>-wal and <path>-shm to <path>.quarantine-<ms>[-wal|-shm].
 * The database must be closed. Never deletes; never overwrites an earlier quarantine.
 * @param {string} path
 * @returns {string} the new main path
 */
function quarantine(path) {
  let stamp = Date.now();
  while (fs.existsSync(`${path}.quarantine-${stamp}`)) stamp++;
  const target = `${path}.quarantine-${stamp}`;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(path + suffix)) fs.renameSync(path + suffix, target + suffix);
  }
  return target;
}

module.exports = { StateError, openDb, openReadOnly, tx, quarantine, isBusy };
