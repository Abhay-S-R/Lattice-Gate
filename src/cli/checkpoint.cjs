'use strict';
// @ts-check
// `kig checkpoint (--db|--adapter) --key <file> --anchor <file>`: sign the current
// audit-chain head and append it to the anchor file (architecture §14.2).
// Refuses a broken chain, a key that differs from the anchor's, a store that is not
// the anchor's, and a store that no longer matches the anchor's earlier checkpoints.
const fs = require('node:fs');
const path = require('node:path');
const provider = require('../crypto/provider.cjs');
const cp = require('../core/checkpoint.cjs');
const { STORE_OPTIONS, storePath, withStore } = require('./store-arg.cjs');
const { UsageError, CommandError } = require('./main.cjs');

function loadKey(file) {
  try { return provider.importPrivate(fs.readFileSync(path.resolve(file))); } catch { throw new CommandError('cannot read the signing key'); }
}

module.exports = {
  name: 'checkpoint',
  describe: 'sign the audit-log head and append it to an external anchor file',
  usage: 'usage: node kig.cjs checkpoint (--db <file> | --adapter <stateDir>) --key <file> --anchor <file>',
  options: { ...STORE_OPTIONS, key: { type: 'string' }, anchor: { type: 'string' } },
  async run({ values, io }) {
    const file = storePath(values);
    if (!values.key) throw new UsageError('missing --key <file>');
    if (!values.anchor) throw new UsageError('missing --anchor <file>');
    const anchorFile = path.resolve(values.anchor);
    const priv = loadKey(values.key);
    const pubB64 = provider.exportPublic(provider.publicFromPrivate(priv)).toString('base64');

    const anchor = withStore(file, (db) => {
      let a;
      if (fs.existsSync(anchorFile)) {
        try { a = cp.readAnchor(anchorFile); } catch (e) { throw new CommandError(e.message); }
        if (a.public_key !== pubB64) throw new CommandError('signing key does not match the anchor');
        const v = cp.verifyAgainstAnchor(db, a);
        if (!v.ok) throw new CommandError(`store does not match the anchor (seq ${v.seq} ${v.reason}); not extending`);
      } else {
        a = { version: 1, store_id: cp.storeId(db), public_key: pubB64, checkpoints: [] };
      }
      const prev = a.checkpoints.length ? a.checkpoints[a.checkpoints.length - 1].checkpoint_id : null;
      let next;
      try { next = cp.signCheckpoint(db, priv, prev); } catch (e) {
        if (e instanceof cp.AnchorError) throw new CommandError(e.message);
        throw e;
      }
      a.checkpoints.push(next);
      return a;
    });
    cp.writeAnchor(anchorFile, anchor);
    const last = anchor.checkpoints[anchor.checkpoints.length - 1];
    io.out(`CHECKPOINT seq=${last.seq} id=${last.checkpoint_id}\n`);
    return 0;
  },
};
