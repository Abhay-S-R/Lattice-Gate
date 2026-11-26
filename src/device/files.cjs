'use strict';
const provider = require('../crypto/provider.cjs');
const wrap = require('../core/wrap.cjs');
const { encode } = require('../core/encoding.cjs');
const { WRAP } = require('../core/contracts.cjs');
const keystore = require('./keystore.cjs');
function read(home, deviceId, response) {
  if (!response || response.decision !== 'allow') throw new Error(response?.rule || 'file_denied');
  const keys = keystore.load(home, deviceId);
  const envFields = [response.file_id, response.version, undefined, deviceId, 'kig/v1/envelope'];
  // Account is bound into the envelope and supplied from the authenticated device identity.
  const account = response.account;
  envFields[2] = account;
  const dek = wrap.kemUnwrap(keys.kemPrivate, response.envelope, envFields);
  const aad = encode(WRAP.fileAadLabel, [response.file_id, response.version, 'kig/v1/file']);
  try { return provider.aeadOpen(dek, Buffer.from(response.nonce, 'base64'), aad, Buffer.from(response.ciphertext, 'base64')); }
  finally { dek.fill(0); }
}
module.exports = { read };
