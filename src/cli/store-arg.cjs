'use strict';
// @ts-check
// Shared `--db <file>` / `--adapter <stateDir>` handling for offline CLI commands.
const path = require('node:path');
const { openReadOnly, StateError } = require('../store/db.cjs');
const schema = require('../store/schema-adapter.cjs');
const { UsageError, CommandError } = require('./main.cjs');

const STORE_OPTIONS = {
  db: { type: 'string' },
  adapter: { type: 'string' },
};

/** @param {{ db?: string, adapter?: string }} values @returns {string} */
function storePath(values) {
  if (values.db && values.adapter) throw new UsageError('give either --db or --adapter, not both');
  if (values.db) return path.resolve(values.db);
  if (values.adapter) return schema.adapterDbPath(path.resolve(values.adapter));
  throw new UsageError('missing --db <file> or --adapter <stateDir>');
}

/**
 * Open the store read-only, mapping state errors to one-line command errors.
 * @param {string} file
 */
function openStore(file) {
  try {
    return openReadOnly(file);
  } catch (e) {
    if (e instanceof StateError && e.kind === 'missing') throw new CommandError(`no audit store at ${file}`);
    if (e instanceof StateError && e.kind === 'locked') throw new CommandError('store is locked; try again');
    throw new CommandError('store is not a readable KIG database');
  }
}

/** Run fn(db) on a read-only store; maps SQLite errors (e.g. missing tables) to a command error. */
function withStore(file, fn) {
  const db = openStore(file);
  try {
    return fn(db);
  } catch (e) {
    if (e instanceof UsageError || e instanceof CommandError) throw e;
    throw new CommandError('store is not a readable KIG audit store');
  } finally {
    db.close();
  }
}

module.exports = { STORE_OPTIONS, storePath, withStore };
