'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const provider = require('../../src/crypto/provider.cjs');
const wrap = require('../../src/core/wrap.cjs');

const isZero = (value) => value.every((byte) => byte === 0);

test('KEM envelope round trip binds file, account and device context', () => {
  const pair = provider.kemGenerate();
  const dek = provider.random(32);
  const fields = ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope'];
  const envelope = wrap.kemWrap(pair.publicKey, dek, fields);
  assert.deepEqual(wrap.kemUnwrap(pair.privateKey, envelope, fields), dek);
  assert.throws(() => wrap.kemUnwrap(pair.privateKey, envelope,
    ['brief', 1, 'alice', 'alice-laptop', 'kig/v1/envelope']));
});

test('tampered KEM ciphertext, wrap nonce, wrapped bytes and tag are rejected', () => {
  const pair = provider.kemGenerate();
  const dek = provider.random(32);
  const fields = ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope'];
  const envelope = wrap.kemWrap(pair.publicKey, dek, fields);
  for (const field of ['ct', 'nonce', 'wrapped']) {
    const changed = { ...envelope, [field]: Buffer.from(envelope[field]) };
    changed[field][0] ^= 1;
    assert.throws(() => wrap.kemUnwrap(pair.privateKey, changed, fields));
  }
  const badTag = { ...envelope, wrapped: Buffer.from(envelope.wrapped) };
  badTag.wrapped[badTag.wrapped.length - 1] ^= 1;
  assert.throws(() => wrap.kemUnwrap(pair.privateKey, badTag, fields));
});

test('KEM wrap and unwrap wipe derived shared secrets and keys', () => {
  const pair = provider.kemGenerate();
  const dek = provider.random(32);
  const fields = ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope'];
  const originalEncapsulate = provider.kemEncapsulate;
  const originalDecapsulate = provider.kemDecapsulate;
  const originalHkdf = provider.hkdf;
  const secrets = [], derived = [];
  try {
    provider.kemEncapsulate = (pub) => {
      const result = originalEncapsulate(pub); secrets.push(result.sharedKey); return result;
    };
    provider.kemDecapsulate = (priv, ct) => {
      const secret = originalDecapsulate(priv, ct); secrets.push(secret); return secret;
    };
    provider.hkdf = (...args) => {
      const key = originalHkdf(...args); derived.push(key); return key;
    };
    const envelope = wrap.kemWrap(pair.publicKey, dek, fields);
    assert.ok(secrets.every(isZero));
    assert.ok(derived.every(isZero));
    secrets.length = 0; derived.length = 0;
    const unwrapped = wrap.kemUnwrap(pair.privateKey, envelope, fields);
    assert.deepEqual(unwrapped, dek);
    unwrapped.fill(0);
    assert.ok(secrets.every(isZero));
    assert.ok(derived.every(isZero));
  } finally {
    provider.kemEncapsulate = originalEncapsulate;
    provider.kemDecapsulate = originalDecapsulate;
    provider.hkdf = originalHkdf;
    dek.fill(0);
  }
});
