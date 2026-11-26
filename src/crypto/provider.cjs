'use strict';
// @ts-check
// The ONLY module allowed to import node:crypto (architecture §1.3, §4.5).
// Fixed algorithms: ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF/HMAC/SHA-256.
const crypto = require('node:crypto');

const { subtle } = crypto.webcrypto;

const KEM_PK_BYTES = 1184;
const KEM_ALG = 'ml-kem-768';
const SIG_ALG = 'ml-dsa-65';

/** ML-DSA domain-separation contexts (features P1-01). */
const CONTEXTS = Object.freeze({
  request: 'kig/v1/request',
  handshake: 'kig/v1/handshake',
  revocation: 'kig/v1/revocation',
  checkpoint: 'kig/v1/checkpoint',
  backup: 'kig/v1/backup',
});
const CONTEXT_SET = new Set(Object.values(CONTEXTS));

class InvalidKeyError extends Error {
  constructor(message = 'invalid key') { super(message); this.name = 'InvalidKeyError'; }
}
class AeadError extends Error {
  constructor(message = 'authentication failed') { super(message); this.name = 'AeadError'; }
}

/** @param {number} n */
const random = (n) => crypto.randomBytes(n);

/** @param {Buffer} buf */
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

/** @param {Buffer} key @param {Buffer} buf */
const hmac = (key, buf) => crypto.createHmac('sha256', key).update(buf).digest();

/** @param {Buffer} key @param {Buffer} buf */
const hmacHex = (key, buf) => crypto.createHmac('sha256', key).update(buf).digest('hex');

/** Constant-time equality; false (not throw) on length mismatch. */
const hmacEqual = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

/** HKDF-SHA-256 (RFC 5869). */
const hkdf = (ikm, salt, info, len) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));

function checkAeadParams(key, nonce) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('AES-256-GCM key must be 32 bytes');
  if (!Buffer.isBuffer(nonce) || nonce.length !== 12) throw new TypeError('AES-256-GCM nonce must be 12 bytes');
}

/** AES-256-GCM seal → ciphertext ‖ 16-byte tag. */
function aeadSeal(key, nonce, aad, plaintext) {
  checkAeadParams(key, nonce);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  c.setAAD(aad);
  return Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
}

/** AES-256-GCM open; throws AeadError on any authentication failure. */
function aeadOpen(key, nonce, aad, ctTag) {
  checkAeadParams(key, nonce);
  if (!Buffer.isBuffer(ctTag) || ctTag.length < 16) throw new AeadError();
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  d.setAAD(aad);
  d.setAuthTag(ctTag.subarray(ctTag.length - 16));
  try {
    return Buffer.concat([d.update(ctTag.subarray(0, ctTag.length - 16)), d.final()]);
  } catch {
    throw new AeadError();
  }
}

/**
 * Encapsulate to a raw ML-KEM-768 public key supplied by an untrusted party
 * (protected_read). WebCrypto import performs the FIPS 203 encapsulation-key check.
 * @param {Buffer} rawPub
 */
async function kemEncapsulateRaw(rawPub) {
  if (!Buffer.isBuffer(rawPub) || rawPub.length !== KEM_PK_BYTES) throw new InvalidKeyError();
  let key;
  try {
    key = await subtle.importKey('raw-public', rawPub, { name: 'ML-KEM-768' }, false, ['encapsulateBits']);
  } catch {
    throw new InvalidKeyError();
  }
  const { sharedKey, ciphertext } = await subtle.encapsulateBits({ name: 'ML-KEM-768' }, key);
  return { ciphertext: Buffer.from(ciphertext), sharedKey: Buffer.from(sharedKey) };
}

const kemGenerate = () => crypto.generateKeyPairSync(KEM_ALG);

/**
 * Raw 1184-byte encapsulation key. KeyObject.export has no raw format for ML-KEM
 * in Node 24.11.1, so go through WebCrypto (async).
 * @param {crypto.KeyObject} publicKey
 */
async function kemExportRawPublic(publicKey) {
  const ck = publicKey.toCryptoKey({ name: 'ML-KEM-768' }, true, ['encapsulateBits']);
  return Buffer.from(await subtle.exportKey('raw-public', ck));
}

/** @param {crypto.KeyObject} publicKey */
function kemEncapsulate(publicKey) {
  const { sharedKey, ciphertext } = crypto.encapsulate(publicKey);
  return { ciphertext: Buffer.from(ciphertext), sharedKey: Buffer.from(sharedKey) };
}

/** @param {crypto.KeyObject} privateKey @param {Buffer} ciphertext */
const kemDecapsulate = (privateKey, ciphertext) => Buffer.from(crypto.decapsulate(privateKey, ciphertext));

const sigGenerate = () => crypto.generateKeyPairSync(SIG_ALG);

function checkContext(context) {
  if (!CONTEXT_SET.has(context)) throw new TypeError('unknown signature context');
  return Buffer.from(context, 'utf8');
}

/** ML-DSA-65 signature with a fixed domain-separation context. */
function sign(privateKey, context, buf) {
  return crypto.sign(null, buf, { key: privateKey, context: checkContext(context) });
}

/** ML-DSA-65 verification; false on any mismatch or malformed signature. */
function verify(publicKey, context, buf, sig) {
  try {
    return crypto.verify(null, buf, { key: publicKey, context: checkContext(context) }, sig);
  } catch {
    return false;
  }
}

const exportPrivate = (key) => key.export({ format: 'der', type: 'pkcs8' });
const importPrivate = (der) => crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
const exportPublic = (key) => key.export({ format: 'der', type: 'spki' });
const importPublic = (der) => crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
/** Public key matching a private KeyObject (e.g. to pin it in an anchor). */
const publicFromPrivate = (privateKey) => crypto.createPublicKey(privateKey);

/** Known-answer and round-trip checks used by `kig compat`. */
async function selfTest() {
  const results = [];
  const check = async (name, fn) => {
    let pass = false;
    try { pass = (await fn()) === true; } catch { pass = false; }
    results.push({ name, pass });
  };
  await check('hkdf-sha256 RFC 5869 TC1', () =>
    hkdf(Buffer.alloc(22, 0x0b), Buffer.from('000102030405060708090a0b0c', 'hex'),
      Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42).toString('hex') ===
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  await check('aes-256-gcm round trip + tamper rejection', () => {
    const k = random(32), n = random(12), aad = Buffer.from('a');
    const s = aeadSeal(k, n, aad, Buffer.from('x'));
    if (aeadOpen(k, n, aad, s).toString() !== 'x') return false;
    try { aeadOpen(k, n, Buffer.from('b'), s); return false; } catch (e) { return e instanceof AeadError; }
  });
  await check('ml-kem-768 raw-public encapsulate/decapsulate', async () => {
    const { publicKey, privateKey } = kemGenerate();
    const { ciphertext, sharedKey } = await kemEncapsulateRaw(await kemExportRawPublic(publicKey));
    return ciphertext.length === 1088 && kemDecapsulate(privateKey, ciphertext).equals(sharedKey);
  });
  await check('ml-kem-768 rejects invalid encapsulation key', async () => {
    try { await kemEncapsulateRaw(Buffer.alloc(KEM_PK_BYTES, 0xff)); return false; } catch (e) { return e instanceof InvalidKeyError; }
  });
  await check('ml-dsa-65 sign/verify with context separation', () => {
    const { publicKey, privateKey } = sigGenerate();
    const m = Buffer.from('m');
    const s = sign(privateKey, CONTEXTS.request, m);
    return verify(publicKey, CONTEXTS.request, m, s) && !verify(publicKey, CONTEXTS.backup, m, s);
  });
  await check('pkcs8 private key round trip (ml-dsa-65, ml-kem-768)', () => {
    const d = sigGenerate();
    const s = sign(importPrivate(exportPrivate(d.privateKey)), CONTEXTS.checkpoint, Buffer.from('m'));
    const k = kemGenerate();
    const e = kemEncapsulate(k.publicKey);
    return verify(d.publicKey, CONTEXTS.checkpoint, Buffer.from('m'), s) &&
      kemDecapsulate(importPrivate(exportPrivate(k.privateKey)), e.ciphertext).equals(e.sharedKey);
  });
  return results;
}

module.exports = {
  CONTEXTS, KEM_PK_BYTES, InvalidKeyError, AeadError,
  random, sha256, hmac, hmacHex, hmacEqual, hkdf, aeadSeal, aeadOpen,
  kemEncapsulateRaw, kemGenerate, kemExportRawPublic, kemEncapsulate, kemDecapsulate,
  sigGenerate, sign, verify, exportPrivate, importPrivate, exportPublic, importPublic, publicFromPrivate,
  selfTest,
};
