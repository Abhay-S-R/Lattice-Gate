'use strict';
const fs = require('node:fs');
const path = require('node:path');
const provider = require('../crypto/provider.cjs');

function writePrivate(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, bytes, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}
function writePublic(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, bytes, { mode: 0o644 });
}
function createKeys(layout) {
  const result = {};
  for (const name of ['policy', 'audit', 'backup']) {
    const pair = provider.sigGenerate();
    writePrivate(layout.cp.keys[name].key, provider.exportPrivate(pair.privateKey));
    writePublic(layout.cp.keys[name].pub, provider.exportPublic(pair.publicKey));
    result[name] = pair;
  }
  const master = provider.kemGenerate();
  writePrivate(layout.cp.keys.masterKem.key, provider.exportPrivate(master.privateKey));
  const recovery = provider.kemGenerate();
  writePrivate(layout.operator.recoveryKey.key, provider.exportPrivate(recovery.privateKey));
  writePublic(path.join(path.dirname(layout.operator.recoveryKey.key), 'recovery.pub'), provider.exportPublic(recovery.publicKey));
  fs.mkdirSync(path.dirname(layout.anchor.cpPolicyPub), { recursive: true, mode: 0o700 });
  writePublic(layout.anchor.cpPolicyPub, provider.exportPublic(result.policy.publicKey));
  const anchor = { version: 1, policy_public_key: provider.exportPublic(result.policy.publicKey).toString('base64'), audit_public_key: provider.exportPublic(result.audit.publicKey).toString('base64'), backup_public_key: provider.exportPublic(result.backup.publicKey).toString('base64'), recovery_public_key: provider.exportPublic(recovery.publicKey).toString('base64') };
  writePublic(path.join(path.dirname(layout.anchor.cpPolicyPub), 'keys.json'), Buffer.from(JSON.stringify(anchor, null, 2) + '\n'));
  return result;
}
module.exports = { createKeys, writePrivate, writePublic };
