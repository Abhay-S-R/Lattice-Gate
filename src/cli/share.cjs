'use strict';
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const files = require('../cp/files.cjs');
const { UsageError, CommandError } = require('./main.cjs');
module.exports = { name: 'share', describe: 'grant an account access to an encrypted file', usage: 'usage: node kig.cjs share <file> --with <account>', options: { home: { type: 'string' }, with: { type: 'string' } }, run({ values, positionals, io }) {
  if (positionals.length !== 1 || !values.with) throw new UsageError('expected <file> --with <account>');
  const home = path.resolve(values.home || contracts.kigHome()); const l = contracts.layout(home);
  const db = openDb(l.cp.db, { create: false, version: schema.VERSION, init: schema.init });
  try { files.share(db, { file_id: positionals[0], account: values.with, home }); } catch (e) { throw new CommandError(`share failed (${e.message})`); } finally { db.close(); }
  io.out(`SHARED ${positionals[0]} with ${values.with}\n`); return 0;
} };
