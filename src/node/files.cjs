'use strict';
const auth = require('./auth.cjs');
const ids = require('../core/ids.cjs');
function read(db, req, options = {}) {
  const result = auth.authenticate(db, req, options);
  if (!result.ok) return { decision: 'deny', rule: result.rule };
  const allowed = (options.policy?.snapshot || require('./policy.cjs').current(db).snapshot);
  if (!(allowed.grants || []).some(g => g.file_id === req.resource && g.account === result.device.account)) return { decision: 'deny', rule: 'not_granted' };
  const row = db.prepare('SELECT c.version,c.nonce,c.ciphertext,e.envelope FROM ciphertexts c JOIN node_envelopes e ON e.file_id=c.file_id AND e.version=c.version WHERE c.file_id=? AND e.device_id=?').get(ids.enc(req.resource), ids.enc(req.device_id));
  return row ? { decision: 'allow', rule: 'allowed', account: result.device.account, file_id: req.resource, version: row.version, nonce: Buffer.from(row.nonce).toString('base64'), ciphertext: Buffer.from(row.ciphertext).toString('base64'), envelope: JSON.parse(row.envelope) } : { decision: 'deny', rule: 'unknown_file' };
}
module.exports = { read };
