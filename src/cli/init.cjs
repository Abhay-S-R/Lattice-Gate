'use strict';
const fs = require('node:fs');
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const schemas = { cp: require('../store/schema-cp.cjs'), node: require('../store/schema-node.cjs'), device: require('../store/schema-device.cjs') };
const { createKeys } = require('../cp/keys.cjs');
const { UsageError, CommandError } = require('./main.cjs');
function initHome(home, { force = false } = {}) {
  const l = contracts.layout(path.resolve(home));
  if (l.root === path.parse(l.root).root) throw new CommandError('refusing to use a filesystem root as KIG_HOME');
  const relativeCwd = path.relative(l.root, process.cwd());
  if (relativeCwd === '' || (!relativeCwd.startsWith(`..${path.sep}`) && relativeCwd !== '..' && !path.isAbsolute(relativeCwd))) {
    throw new CommandError('KIG_HOME cannot be the current directory or one of its parents');
  }
  if (fs.existsSync(l.cp.db) && !force) throw new CommandError(`KIG_HOME already initialized (use --force): ${l.root}`);
  if (force && fs.existsSync(l.root)) fs.rmSync(l.root, { recursive: true, force: true });
  fs.mkdirSync(l.root, { recursive: true, mode: 0o700 });
  for (const d of [path.dirname(l.cp.db), path.dirname(l.node('A').db), path.dirname(l.node('B').db), path.dirname(l.node('C').db), path.dirname(l.operator.recoveryKey.key), path.dirname(l.anchor.cpPolicyPub), path.dirname(l.run.pid('cp'))]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  createKeys(l);
  const cp = openDb(l.cp.db, { create: true, version: schemas.cp.VERSION, init: schemas.cp.init }); cp.close();
  for (const id of contracts.NODE_IDS) { const n = l.node(id); fs.mkdirSync(n.dir, { recursive: true, mode: 0o700 }); const db = openDb(n.db, { create: true, version: schemas.node.VERSION, init: schemas.node.init }); db.close(); }
  return l;
}
module.exports = { name: 'init', describe: 'initialize the KIG home and trust keys', usage: 'usage: node kig.cjs init [--home <dir>] [--force]', options: { home: { type: 'string' }, force: { type: 'boolean' } }, run({ values, positionals, io }) {
  if (positionals.length) throw new UsageError('unexpected argument');
  const home = path.resolve(values.home || contracts.kigHome());
  const l = initHome(home, { force: values.force });
  io.out(`INITIALIZED ${l.root}\n`); return 0;
} };
