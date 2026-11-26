'use strict';
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const { revoke } = require('../cp/revoke.cjs');
const { safe } = require('./text.cjs');
const { UsageError, CommandError } = require('./main.cjs');

module.exports = {
  name: 'revoke', describe: 'revoke an active device and distribute the signed policy',
  usage: 'usage: node kig.cjs revoke --device <device> [--home <dir>]',
  options: { device: { type: 'string' }, home: { type: 'string' } },
  run({ values, positionals, io }) {
    if (positionals.length || !values.device) throw new UsageError('expected --device <device>');
    const home = path.resolve(values.home || contracts.kigHome());
    const L = contracts.layout(home);
    const db = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
    let result;
    try {
      const env = { ...process.env, KIG_HOME: home };
      result = revoke(db, values.device, { env });
    } catch (e) {
      const reason = ['invalid_device_id', 'device_not_found', 'device_already_revoked', 'device_not_active'].includes(e.message)
        ? e.message : 'device revocation failed';
      throw new CommandError(reason);
    } finally { db.close(); }
    io.out(`REVOKED ${safe(result.device_id)} epoch=${result.epoch}\n`);
    return 0;
  },
};
