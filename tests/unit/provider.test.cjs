'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const p = require('../../src/crypto/provider.cjs');

const hex = (s) => Buffer.from(s, 'hex');

test('hkdf RFC 5869 TC1', () => {
  const okm = p.hkdf(Buffer.alloc(22, 0x0b), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'), 42);
  assert.ok(Buffer.isBuffer(okm));
  assert.equal(okm.toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('aead round trip and AAD tamper', () => {
  const key = p.random(32), nonce = p.random(12);
  const sealed = p.aeadSeal(key, nonce, Buffer.from('aad'), Buffer.from('secret'));
  assert.equal(sealed.length, 'secret'.length + 16);
  assert.equal(p.aeadOpen(key, nonce, Buffer.from('aad'), sealed).toString(), 'secret');
  assert.throws(() => p.aeadOpen(key, nonce, Buffer.from('aaX'), sealed), p.AeadError);
  const flipped = Buffer.from(sealed); flipped[0] ^= 1;
  assert.throws(() => p.aeadOpen(key, nonce, Buffer.from('aad'), flipped), p.AeadError);
});

test('aead rejects wrong key or nonce length', () => {
  assert.throws(() => p.aeadSeal(p.random(16), p.random(12), Buffer.alloc(0), Buffer.alloc(1)), TypeError);
  assert.throws(() => p.aeadSeal(p.random(32), p.random(8), Buffer.alloc(0), Buffer.alloc(1)), TypeError);
});

test('kem raw round trip', async () => {
  const { publicKey, privateKey } = p.kemGenerate();
  const raw = await p.kemExportRawPublic(publicKey);
  assert.equal(raw.length, 1184);
  const { ciphertext, sharedKey } = await p.kemEncapsulateRaw(raw);
  assert.ok(Buffer.isBuffer(ciphertext) && Buffer.isBuffer(sharedKey));
  assert.equal(ciphertext.length, 1088);
  assert.equal(sharedKey.length, 32);
  assert.ok(p.kemDecapsulate(privateKey, ciphertext).equals(sharedKey));
});

test('kem KeyObject encapsulate round trip', () => {
  const { publicKey, privateKey } = p.kemGenerate();
  const { ciphertext, sharedKey } = p.kemEncapsulate(publicKey);
  assert.ok(p.kemDecapsulate(privateKey, ciphertext).equals(sharedKey));
});

test('kem rejects bad keys', async () => {
  await assert.rejects(p.kemEncapsulateRaw(Buffer.alloc(1183, 1)), p.InvalidKeyError);
  await assert.rejects(p.kemEncapsulateRaw(Buffer.alloc(1185, 1)), p.InvalidKeyError);
  await assert.rejects(p.kemEncapsulateRaw(Buffer.alloc(1184, 0xff)), p.InvalidKeyError);
});

test('ml-dsa context separation', () => {
  const { publicKey, privateKey } = p.sigGenerate();
  const msg = Buffer.from('hello');
  const sig = p.sign(privateKey, p.CONTEXTS.request, msg);
  assert.equal(sig.length, 3309);
  assert.equal(p.verify(publicKey, p.CONTEXTS.request, msg, sig), true);
  assert.equal(p.verify(publicKey, p.CONTEXTS.backup, msg, sig), false);
  assert.equal(p.verify(publicKey, p.CONTEXTS.request, Buffer.from('hellO'), sig), false);
});

test('sign rejects unknown context', () => {
  const { privateKey } = p.sigGenerate();
  assert.throws(() => p.sign(privateKey, 'kig/v1/other', Buffer.from('x')), TypeError);
});

test('private key export/import round trip (ML-DSA)', () => {
  const { publicKey, privateKey } = p.sigGenerate();
  const restored = p.importPrivate(p.exportPrivate(privateKey));
  const sig = p.sign(restored, p.CONTEXTS.checkpoint, Buffer.from('m'));
  assert.equal(p.verify(publicKey, p.CONTEXTS.checkpoint, Buffer.from('m'), sig), true);
});

test('private key export/import round trip (ML-KEM)', () => {
  const { publicKey, privateKey } = p.kemGenerate();
  const restored = p.importPrivate(p.exportPrivate(privateKey));
  const { ciphertext, sharedKey } = p.kemEncapsulate(publicKey);
  assert.ok(p.kemDecapsulate(restored, ciphertext).equals(sharedKey));
});

test('public key export/import round trip', () => {
  const { publicKey, privateKey } = p.sigGenerate();
  const pub = p.importPublic(p.exportPublic(publicKey));
  const sig = p.sign(privateKey, p.CONTEXTS.request, Buffer.from('m'));
  assert.equal(p.verify(pub, p.CONTEXTS.request, Buffer.from('m'), sig), true);
});

test('hmac helpers', () => {
  const k = Buffer.from('key');
  assert.equal(p.hmacHex(k, Buffer.from('data')), p.hmac(k, Buffer.from('data')).toString('hex'));
  assert.match(p.hmacHex(k, Buffer.from('data')), /^[0-9a-f]{64}$/);
  assert.equal(p.hmacEqual(Buffer.from('ab'), Buffer.from('ab')), true);
  assert.equal(p.hmacEqual(Buffer.from('ab'), Buffer.from('ac')), false);
  assert.equal(p.hmacEqual(Buffer.from('ab'), Buffer.from('abc')), false);
});

test('sha256 known answer', () => {
  assert.equal(p.sha256(Buffer.from('abc')).toString('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('selfTest all pass', async () => {
  const results = await p.selfTest();
  assert.ok(results.length >= 5);
  for (const r of results) assert.equal(r.pass, true, r.name);
});
