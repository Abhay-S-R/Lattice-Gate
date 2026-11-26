'use strict';
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { CONTEXTS } = provider;
const identity = require('./identity.cjs');
const replay = require('./replay.cjs');

const VERSION = 1;
const SUITE = 'ML-KEM-768+ML-DSA-65+HKDF-SHA-256+AES-256-GCM';
const HANDSHAKE = 'kig/v1/handshake';
const SID_PREFIX = Buffer.from('kig/v1/sid', 'utf8');

function identityFor(self) {
  if (!self || typeof self.home !== 'string' || typeof self.deviceId !== 'string') throw new TypeError('self must include home and deviceId');
  return identity.load(self.home, self.deviceId);
}
function b64(value, size, label) {
  if (typeof value !== 'string' || value.length > 12000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`invalid_${label}`);
  const result = Buffer.from(value, 'base64');
  if (result.toString('base64') !== value || (size !== undefined && result.length !== size)) throw new Error(`invalid_${label}`);
  return result;
}
function m1Fields(m) { return [m.version, m.suite, m.initiator, m.responder, b64(m.nonce_i, 32, 'nonce'), b64(m.ephemeral_pk, undefined, 'ephemeral_key')]; }
function hashM1(m) { return provider.sha256(encode(`${HANDSHAKE}/m1`, m1Fields(m))); }
function hashM2(th1, ct, nonceR, responder, epoch) {
  return provider.sha256(encode(`${HANDSHAKE}/m2`, [th1, ct, nonceR, responder, epoch]));
}
function sessionId(th2) { return provider.sha256(Buffer.concat([SID_PREFIX, th2])).subarray(0, 16).toString('hex'); }
function derive(shared, th2, initiator, responder) {
  const key = (direction) => provider.hkdf(shared, th2,
    encode('kig/v1/traffic-key', [VERSION, SUITE, direction, initiator, responder]), 32);
  const conf = provider.hkdf(shared, th2,
    encode('kig/v1/key-confirmation-key', [VERSION, SUITE, initiator, responder]), 32);
  return { i2r: key('initiator-to-responder'), r2i: key('responder-to-initiator'), conf };
}
function confirmation(key, role, th2) { return provider.hmac(key, encode('kig/v1/key-confirmation', [role, th2])); }
function createSession(local, peer, epoch, sid, th2, keys, role, established) {
  const session = {
    version: VERSION, suite: SUITE, home: local.home, deviceId: local.deviceId,
    account: local.account, peerDevice: peer.deviceId, peerAccount: peer.account,
    epoch, sessionId: sid, transcriptHash: Buffer.from(th2), role,
    sendKey: Buffer.from(role === 'initiator' ? keys.i2r : keys.r2i),
    receiveKey: Buffer.from(role === 'initiator' ? keys.r2i : keys.i2r),
    confirmationKey: Buffer.from(keys.conf), sendSeq: 0n, established, closed: false,
  };
  for (const key of Object.values(keys)) key.fill(0);
  return session;
}
function clearSession(session) {
  for (const key of ['sendKey', 'receiveKey', 'confirmationKey', 'transcriptHash']) session[key]?.fill(0);
  session.closed = true;
  session.established = false;
}

function initiate(self, peerId) {
  const local = identityFor(self);
  const { peer, epoch } = identity.assertPairActive(local.home, local.deviceId, peerId);
  const ephemeral = provider.kemGenerate();
  const m1 = {
    version: VERSION, suite: SUITE, initiator: local.deviceId, responder: peerId,
    nonce_i: provider.random(32).toString('base64'),
    ephemeral_pk: provider.exportPublic(ephemeral.publicKey).toString('base64'),
  };
  const th1 = hashM1(m1);
  m1.sig_i = provider.sign(local.keys.signPrivate, CONTEXTS.handshake, th1).toString('base64');
  return { state: { home: local.home, deviceId: local.deviceId, peerId, epoch, th1, ephemeralPrivate: ephemeral.privateKey, used: false }, m1 };
}

function respond(self, m1) {
  const local = identityFor(self);
  if (!m1 || m1.version !== VERSION || m1.suite !== SUITE || m1.responder !== local.deviceId ||
      typeof m1.initiator !== 'string' || typeof m1.sig_i !== 'string') throw new Error('invalid_handshake_message');
  const { peer, epoch } = identity.assertPairActive(local.home, local.deviceId, m1.initiator);
  const th1 = hashM1(m1);
  if (!provider.verify(provider.importPublic(peer.sign_pk), CONTEXTS.handshake, th1, b64(m1.sig_i, undefined, 'signature'))) {
    throw new Error('bad_initiator_signature');
  }
  const ephPub = provider.importPublic(b64(m1.ephemeral_pk, undefined, 'ephemeral_key'));
  const { ciphertext, sharedKey } = provider.kemEncapsulate(ephPub);
  let session;
  try {
    const nonceR = provider.random(32);
    const th2 = hashM2(th1, ciphertext, nonceR, local.deviceId, epoch);
    const keys = derive(sharedKey, th2, m1.initiator, local.deviceId);
    session = createSession(local, peer, epoch, sessionId(th2), th2, keys, 'responder', false);
    const sigR = provider.sign(local.keys.signPrivate, CONTEXTS.handshake, th2);
    const m2 = {
      version: VERSION, suite: SUITE, initiator: m1.initiator, responder: local.deviceId,
      th1: th1.toString('hex'), ct: ciphertext.toString('base64'), nonce_r: nonceR.toString('base64'), epoch,
      sig_r: sigR.toString('base64'), mac_r: confirmation(session.confirmationKey, 'R', th2).toString('base64'),
    };
    replay.register(local.home, local.deviceId, session.sessionId, peer.deviceId, epoch, 'pending');
    return { session, m2 };
  } catch (e) {
    if (session) clearSession(session);
    throw e;
  } finally { sharedKey.fill(0); }
}

function finish(state, m2) {
  if (!state || state.used || !state.ephemeralPrivate) throw new Error('handshake_state_consumed');
  state.used = true;
  let sharedKey, session;
  try {
    const local = identityFor({ home: state.home, deviceId: state.deviceId });
    const { peer, epoch } = identity.assertPairActive(state.home, state.deviceId, state.peerId);
    if (epoch !== state.epoch) throw new Error('policy_changed_during_handshake');
    if (!m2 || m2.version !== VERSION || m2.suite !== SUITE || m2.initiator !== state.deviceId ||
        m2.responder !== state.peerId || m2.epoch !== state.epoch || m2.th1 !== state.th1.toString('hex')) {
      throw new Error('invalid_handshake_message');
    }
    const ct = b64(m2.ct, undefined, 'ciphertext');
    const nonceR = b64(m2.nonce_r, 32, 'nonce');
    const th2 = hashM2(state.th1, ct, nonceR, state.peerId, m2.epoch);
    if (!provider.verify(provider.importPublic(peer.sign_pk), CONTEXTS.handshake, th2, b64(m2.sig_r, undefined, 'signature'))) {
      throw new Error('bad_responder_signature');
    }
    sharedKey = provider.kemDecapsulate(state.ephemeralPrivate, ct);
    const keys = derive(sharedKey, th2, state.deviceId, state.peerId);
    const expected = confirmation(keys.conf, 'R', th2);
    let confirmed;
    try { confirmed = provider.hmacEqual(expected, b64(m2.mac_r, 32, 'confirmation')); }
    finally { expected.fill(0); }
    if (!confirmed) {
      for (const key of Object.values(keys)) key.fill(0);
      throw new Error('bad_key_confirmation');
    }
    session = createSession(local, peer, epoch, sessionId(th2), th2, keys, 'initiator', true);
    try {
      replay.register(local.home, local.deviceId, session.sessionId, peer.deviceId, epoch, 'active');
      const mac = confirmation(session.confirmationKey, 'I', th2);
      const m3 = { version: VERSION, session_id: session.sessionId, mac_i: mac.toString('base64') };
      mac.fill(0);
      session.confirmationKey.fill(0);
      session.confirmationKey = null;
      return { session, m3 };
    } catch (e) {
      try { replay.close(local.home, local.deviceId, session.sessionId); } catch { /* remove the active session if it was registered */ }
      clearSession(session);
      throw e;
    }
  } finally {
    sharedKey?.fill(0);
    state.ephemeralPrivate = null;
    state.th1?.fill(0);
  }
}

function confirm(session, m3) {
  if (!session || session.role !== 'responder' || session.closed || session.established ||
      !m3 || m3.version !== VERSION || m3.session_id !== session.sessionId) throw new Error('invalid_key_confirmation');
  let valid = false;
  let expected;
  try {
    const pair = identity.assertPairActive(session.home, session.deviceId, session.peerDevice);
    if (pair.epoch !== session.epoch) throw new Error('policy_changed_during_handshake');
    expected = confirmation(session.confirmationKey, 'I', session.transcriptHash);
    valid = provider.hmacEqual(expected, b64(m3.mac_i, 32, 'confirmation'));
  } catch { valid = false; }
  finally { expected?.fill(0); }
  if (!valid) {
    try { replay.close(session.home, session.deviceId, session.sessionId); } finally { clearSession(session); }
    throw new Error('bad_key_confirmation');
  }
  try {
    replay.activate(session.home, session.deviceId, session.sessionId);
    session.confirmationKey.fill(0);
    session.confirmationKey = null;
    session.established = true;
    return true;
  } catch (e) {
    try { replay.close(session.home, session.deviceId, session.sessionId); } catch { /* best-effort persistent close */ }
    clearSession(session);
    throw e;
  }
}

function close(session) {
  if (!session || session.closed) return false;
  try { replay.close(session.home, session.deviceId, session.sessionId); }
  finally { clearSession(session); }
  return true;
}

function abort(state) {
  if (!state || state.used) return false;
  state.ephemeralPrivate = null;
  state.th1?.fill(0);
  state.used = true;
  return true;
}

module.exports = { VERSION, SUITE, initiate, respond, finish, confirm, close, abort };
