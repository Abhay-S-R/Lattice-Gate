'use strict';
const fs = require('node:fs');
const path = require('node:path');
const contracts = require('../core/contracts.cjs');
const { openDb } = require('../store/db.cjs');
const cpSchema = require('../store/schema-cp.cjs');
const registry = require('../cp/registry.cjs');
const files = require('../cp/files.cjs');
const client = require('../device/client.cjs');
const deviceFiles = require('../device/files.cjs');
const { UsageError, CommandError } = require('./main.cjs');
function openCp(home) { const l = contracts.layout(home); return openDb(l.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init }); }
module.exports = { name: 'file', describe: 'publish and read encrypted files', usage: 'usage: node kig.cjs file <publish|read> <file> [options]', options: { home: { type: 'string' }, as: { type: 'string' }, input: { type: 'string' }, device: { type: 'string' }, node: { type: 'string' }, out: { type: 'string' } }, async run({ values, positionals, io }) {
  const home = path.resolve(values.home || contracts.kigHome());
  if (positionals[0] === 'publish' && positionals.length === 2) {
    if (!values.as || !values.input) throw new UsageError('publish requires --as <device> --input <path>');
    const plain = fs.readFileSync(path.resolve(values.input)); const db = openCp(home);
    try { const result = files.publish(db, { file_id: positionals[1], owner_device: values.as, plaintext: plain, home }); io.out(`PUBLISHED ${result.file_id} version=${result.version} bytes=${result.ciphertext_bytes}\n`); }
    catch (e) { throw new CommandError(`publish failed (${e.message})`); } finally { db.close(); }
    return 0;
  }
  if (positionals[0] === 'read' && positionals.length === 2) {
    if (!values.device || !values.node) throw new UsageError('read requires --device <device> --node <A|B|C>');
    if (!contracts.NODE_IDS.includes(values.node)) throw new UsageError('invalid --node; expected A, B or C');
    const db = openCp(home); let device, file;
    try { device = registry.getDevice(db, values.device); file = db.prepare('SELECT active_version FROM files WHERE file_id=?').get(require('../core/ids.cjs').enc(positionals[1])); }
    finally { db.close(); }
    if (!device || device.status !== 'active' || !file) throw new CommandError('device or file is unavailable');
    const p = contracts.ports(); const nodeUrl = contracts.url(p[values.node]);
    const fields = { home, version: 1, op: 'file.read', account: device.account, device_id: values.device, resource: positionals[1], request_id: require('../crypto/provider.cjs').random(16).toString('hex'), key_version: file.active_version };
    try {
      const result = await client.request(nodeUrl, contracts.layout(home).device(values.device).dir, 'file.read', fields);
      const response = result.json || result;
      const plaintext = deviceFiles.read(home, values.device, response);
      if (values.out) { fs.writeFileSync(path.resolve(values.out), plaintext, { mode: 0o600 }); io.out(`READ ${positionals[1]} via ${values.node} -> ${path.resolve(values.out)}\n`); }
      else io.out(plaintext.toString('utf8') + (plaintext.length && plaintext[plaintext.length - 1] === 10 ? '' : '\n'));
      plaintext.fill(0);
    } catch (e) { throw new CommandError(`read failed (${e.message})`); }
    return 0;
  }
  throw new UsageError('expected publish <file> --as <device> --input <path> or read <file> --device <device> --node <A|B|C> [--out <path>]');
} };
