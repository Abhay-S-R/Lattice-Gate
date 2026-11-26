'use strict';
// @ts-check
// `kig keys init --out <dir> [--force]`: operator audit-signing key pair (ML-DSA-65),
// used by `kig checkpoint`. Private key: PKCS#8 DER, mode 0600. Public key: SPKI DER.
// Keep the private key with the operator, not in the state directory it signs for.
const fs = require('node:fs');
const path = require('node:path');
const provider = require('../crypto/provider.cjs');
const { UsageError, CommandError } = require('./main.cjs');

const KEY = 'audit-signing.key';
const PUB = 'audit-signing.pub';

module.exports = {
  name: 'keys',
  describe: 'create the operator audit-signing key pair (keys init --out <dir>)',
  usage: 'usage: node kig.cjs keys init --out <dir> [--force]',
  options: { out: { type: 'string' }, force: { type: 'boolean' } },
  async run({ values, positionals, io }) {
    if (positionals.length !== 1 || positionals[0] !== 'init') throw new UsageError('expected subcommand: init');
    if (!values.out) throw new UsageError('missing --out <dir>');
    const dir = path.resolve(values.out);
    const keyFile = path.join(dir, KEY), pubFile = path.join(dir, PUB);
    if (!values.force && (fs.existsSync(keyFile) || fs.existsSync(pubFile))) {
      throw new CommandError(`keys already exist in ${dir} (use --force to replace)`);
    }
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { publicKey, privateKey } = provider.sigGenerate();
    const tmp = `${keyFile}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, provider.exportPrivate(privateKey), { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, keyFile);
    fs.writeFileSync(pubFile, provider.exportPublic(publicKey));
    io.out(`KEYS ${keyFile} ${pubFile}\n`);
    return 0;
  },
};
