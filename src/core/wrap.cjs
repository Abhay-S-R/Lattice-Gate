'use strict';
const provider = require('../crypto/provider.cjs');
const { encode } = require('./encoding.cjs');

function pubKey(value) { return value && typeof value.export === 'function' ? value : provider.importPublic(value); }
function privKey(value) { return value && typeof value.export === 'function' ? value : provider.importPrivate(value); }
function contextBytes(label, fields) { return encode(label, fields); }
function kemWrap(recipientPub, dek, ctxFields) {
  if (!Buffer.isBuffer(dek) || dek.length !== 32) throw new TypeError('DEK must be 32 bytes');
  const { ciphertext, sharedKey } = provider.kemEncapsulate(pubKey(recipientPub));
  let key;
  try {
    const info = contextBytes('kig/v1/wrap', ctxFields);
    const aad = contextBytes('kig/v1/envelope', ctxFields);
    key = provider.hkdf(sharedKey, ciphertext, info, 32);
    const nonce = provider.random(12);
    return { ct: Buffer.from(ciphertext), nonce, wrapped: provider.aeadSeal(key, nonce, aad, dek) };
  } finally { sharedKey.fill(0); key?.fill(0); }
}
function kemUnwrap(recipientPriv, wrap, ctxFields) {
  if (!wrap || typeof wrap !== 'object') throw new TypeError('invalid wrapped key');
  const ct = Buffer.isBuffer(wrap.ct) ? wrap.ct : Buffer.from(wrap.ct, 'base64');
  const nonce = Buffer.isBuffer(wrap.nonce) ? wrap.nonce : Buffer.from(wrap.nonce, 'base64');
  const wrapped = Buffer.isBuffer(wrap.wrapped) ? wrap.wrapped : Buffer.from(wrap.wrapped, 'base64');
  const sharedKey = provider.kemDecapsulate(privKey(recipientPriv), ct);
  let key;
  try {
    key = provider.hkdf(sharedKey, ct, contextBytes('kig/v1/wrap', ctxFields), 32);
    return provider.aeadOpen(key, nonce, contextBytes('kig/v1/envelope', ctxFields), wrapped);
  } finally { sharedKey.fill(0); key?.fill(0); }
}
function serialize(w) { return { ct: w.ct.toString('base64'), nonce: w.nonce.toString('base64'), wrapped: w.wrapped.toString('base64') }; }
module.exports = { kemWrap, kemUnwrap, serialize };
