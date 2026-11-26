'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { call } = require('../core/http.cjs');
const { kigHome, layout, ports, url, NODE_IDS } = require('../core/contracts.cjs');
const { UsageError, CommandError } = require('./main.cjs');
module.exports = {
  name: 'node', describe: 'partition or heal a local node',
  usage: 'usage: node kig.cjs node <partition|heal> <A|B|C> [--home <dir>]',
  options: { home: { type: 'string' } },
  async run({ positionals, values, io }) {
    const [action, id, ...extra] = positionals;
    if (extra.length || !['partition', 'heal'].includes(action) || !NODE_IDS.includes(id)) throw new UsageError('expected partition|heal <A|B|C>');
    const home = path.resolve(values.home || kigHome());
    const tokenFile = path.join(layout(home).root, 'run', `${id}.control`);
    let token;
    try { token = fs.readFileSync(tokenFile, 'utf8').trim(); } catch { throw new CommandError('node is not running under the KIG supervisor'); }
    if (!/^[0-9a-f]{64}$/.test(token)) throw new CommandError('node control token is invalid');
    try {
      const response = await call(`${url(ports(process.env)[id])}/v1/control/${action}`, 'POST', {}, { timeoutMs: 2000, headers: { 'x-kig-control-token': token } });
      if (response.status !== 200) throw new Error('control request refused');
      const label = action === 'partition' ? `partitioned; access denied when current lease expires in at most ${response.json.expires_in_ms} ms` : 'healed; policy sync resumed';
      io.out(`Node ${id} ${label}\n`);
      return 0;
    } catch (e) { throw new CommandError(e.message === 'control request refused' ? e.message : 'could not reach local node'); }
  },
};
