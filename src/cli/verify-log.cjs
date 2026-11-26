'use strict';
// @ts-check
// `kig verify-log`: offline audit-chain verification (features P1-08, architecture §14.3).
// Prints `OK <count> <headhex>` (exit 0) or `BROKEN seq=<n> <reason>` (exit 1).
const audit = require('../core/audit.cjs');
const { STORE_OPTIONS, storePath, withStore } = require('./store-arg.cjs');

module.exports = {
  name: 'verify-log',
  describe: 'verify an audit log offline; reports the first broken record',
  usage: 'usage: node kig.cjs verify-log (--db <file> | --adapter <stateDir>)',
  options: { ...STORE_OPTIONS },
  async run({ values, io }) {
    const file = storePath(values);
    const r = withStore(file, (db) => audit.verifyChain(db));
    if (r.ok) { io.out(`OK ${r.count} ${r.head.toString('hex')}\n`); return 0; }
    io.out(`BROKEN seq=${r.seq} ${r.reason}\n`);
    return 1;
  },
};
