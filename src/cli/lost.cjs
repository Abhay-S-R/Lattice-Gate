'use strict';
// `kig lost --device <device>`: revoke the device on every node, then re-key every file it could read
// (features P1-03). Replacement devices enrol and are approved through `kig device` (second factor).
const { ROUTES, NODE_IDS } = require('../core/contracts.cjs');
const { safe } = require('./text.cjs');
const { UsageError, CommandError } = require('./main.cjs');
const { cpPost, describeRotation, code } = require('./rotate.cjs');

const ms = (x) => (typeof x === 'number' && Number.isFinite(x) ? `${x.toFixed(1)} ms` : 'no ack within 5 s');

module.exports = {
  name: 'lost',
  describe: 'report a device lost: revoke it on every node and re-key every file it could read',
  usage: 'usage: node kig.cjs lost --device <device>',
  options: { device: { type: 'string' } },
  async run({ values, positionals, io }) {
    if (positionals.length || !values.device) throw new UsageError('expected --device <device>');
    const response = await cpPost(ROUTES.cp.lost, { device_id: values.device }, process.env, 120000);
    if (response.status !== 200) throw new CommandError(`lost-device response refused (${code(response.json?.error || response.status)})`);
    const r = response.json;
    if (r.revocation.already_revoked) io.out(`LOST ${safe(r.device_id)}: already revoked; re-keying its files\n`);
    else {
      const lat = NODE_IDS.map((id) => `${id} ${ms(r.revocation.ack_latency_ms?.[id])}`).join(', ');
      io.out(`LOST ${safe(r.device_id)}: revoked at epoch ${r.revocation.epoch}; signed node acks after ${lat} (CP monotonic clock, from the revocation commit)\n`);
    }
    if (!r.rotations.length) io.out('  no files to re-key\n');
    let failed = false;
    for (const rot of r.rotations) {
      const d = rot.to_version === undefined ? { ok: false, line: `ROTATION ABORTED ${safe(rot.file_id)} (${code(rot.reason)})` } : describeRotation(rot);
      failed ||= !d.ok;
      io.out(`  ${d.line}\n`);
    }
    if (failed) throw new CommandError('device revoked, but at least one file was not re-keyed; run kig rotate --file <file>');
    return 0;
  },
};
