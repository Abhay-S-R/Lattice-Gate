'use strict';
// @ts-check
// `kig verify-log`: offline audit-chain verification (features P1-08, architecture §14.3).
// Prints `OK <count> <headhex>` (exit 0) or `BROKEN seq=<n> <reason>` (exit 1), where reason is
//   content_edit | missing_or_reordered                      (chain alone)
//   invalid_checkpoint | truncated | checkpoint_mismatch     (with --anchor)
// Without an anchor, deletion of the newest records cannot be detected (stated limit).
const path = require('node:path');
const audit = require('../core/audit.cjs');
const cp = require('../core/checkpoint.cjs');
const { STORE_OPTIONS, storePath, withStore } = require('./store-arg.cjs');
const { CommandError } = require('./main.cjs');

module.exports = {
  name: 'verify-log',
  describe: 'verify an audit log offline; reports the first broken record',
  usage: 'usage: node kig.cjs verify-log (--db <file> | --adapter <stateDir>) [--anchor <file>]',
  options: { ...STORE_OPTIONS, anchor: { type: 'string' } },
  async run({ values, io }) {
    const file = storePath(values);
    let anchor = null;
    if (values.anchor) {
      try { anchor = cp.readAnchor(path.resolve(values.anchor)); } catch (e) { throw new CommandError(e.message); }
    }
    const r = withStore(file, (db) => (anchor ? cp.verifyAgainstAnchor(db, anchor) : audit.verifyChain(db)));
    if (r.ok) { io.out(`OK ${r.count} ${r.head.toString('hex')}\n`); return 0; }
    io.out(`BROKEN seq=${r.seq} ${r.reason}\n`);
    return 1;
  },
};
