'use strict';
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const registry = require('../cp/registry.cjs');
const { UsageError, CommandError } = require('./main.cjs');
module.exports = { name: 'account', describe: 'manage accounts', usage: 'usage: node kig.cjs account add <account> [--home <dir>]', options: { home: { type: 'string' } }, run({ values, positionals, io }) {
  if (positionals.length !== 2 || positionals[0] !== 'add') throw new UsageError('expected add <account>');
  const home = path.resolve(values.home || contracts.kigHome()); const l = contracts.layout(home);
  const db = openDb(l.cp.db, { create: false, version: schema.VERSION, init: schema.init });
  try { registry.addAccount(db, positionals[1]); } catch (e) { throw new CommandError(e.message === 'invalid account' ? e.message : 'account could not be added'); } finally { db.close(); }
  io.out(`ACCOUNT ${positionals[1]}\n`); return 0;
} };
