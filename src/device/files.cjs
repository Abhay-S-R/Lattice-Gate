'use strict';
const provider = require('../crypto/provider.cjs');
const wrap = require('../core/wrap.cjs');
const { encode } = require('../core/encoding.cjs');
const { WRAP } = require('../core/contracts.cjs');
const keystore = require('./keystore.cjs');
function read(home, deviceId, response) {
  if (!response || response.decision !== 'allow') throw new Error(response?.rule || 'file_denied');
  const keys = keystore.load(home, deviceId);
  const envFields = [response.file_id, response.version, response.account, deviceId, 'kig/v1/envelope'];
  const dek = wrap.kemUnwrap(keys.kemPrivate, response.envelope, envFields);
  try {
    const aad = encode(WRAP.fileAadLabel, [response.file_id, response.version, 'kig/v1/file']);
    return provider.aeadOpen(dek, Buffer.from(response.nonce, 'base64'), aad, Buffer.from(response.ciphertext, 'base64'));
  }
  finally { dek.fill(0); }
}
/** Reassemble a chunked transfer (Phase 4) and decrypt it exactly like a one-shot read. */
function readTransfer(home, deviceId, start, chunks) {
  if (!start || start.decision !== 'allow') throw new Error(start?.rule || 'file_denied');
  if (!Array.isArray(chunks) || chunks.length !== start.chunk_count) throw new Error('transfer_incomplete');
  const parts = chunks.map((c, i) => {
    if (!c || c.decision !== 'allow' || c.index !== i) throw new Error(c?.rule || 'transfer_incomplete');
    return Buffer.from(c.data, 'base64');
  });
  const ciphertext = Buffer.concat(parts);
  if (ciphertext.length !== start.total_bytes) throw new Error('transfer_incomplete');
  return read(home, deviceId, { ...start, ciphertext: ciphertext.toString('base64') });
}
module.exports = { read, readTransfer };
