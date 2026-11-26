'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb } = require('../../src/store/db.cjs');
const schema = require('../../src/store/schema-node.cjs');
const { layout, REQUEST } = require('../../src/core/contracts.cjs');
const provider = require('../../src/crypto/provider.cjs');
const { encode } = require('../../src/core/encoding.cjs');
const auth = require('../../src/node/auth.cjs');
const policy = require('../../src/node/policy.cjs');
const keystore = require('../../src/device/keystore.cjs');

function fixture({ revoked = false, files = [] } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-auth-'));
  const L = layout(home);
  fs.mkdirSync(path.dirname(L.node('A').db), { recursive: true });
  const db = openDb(L.node('A').db, { create: true, version: schema.VERSION, init: schema.init });
  keystore.create(home, 'phone');
  const keys = keystore.load(home, 'phone');
  const cpKeys = provider.sigGenerate();
  const signPk = provider.exportPublic(keys.signPublic);
  const snapshot = {
    epoch: 1, issued_at_ms: Date.now(), lease_ms: 5000,
    devices: [{
      device_id: 'phone', account: 'alice',
      sign_pk_sha256: provider.sha256(signPk).toString('hex'),
      kem_pk_sha256: provider.sha256(provider.exportPublic(keys.kemPublic)).toString('hex'),
      status: revoked ? 'revoked' : 'active',
    }],
    revoked_devices: revoked ? ['phone'] : [], files, grants: [],
  };
  const { signSnapshot } = require('../../src/cp/snapshot.cjs');
  assert.equal(policy.applySnapshot(db, signSnapshot(snapshot, cpKeys.privateKey), cpKeys.publicKey).applied, true);
  return { home, db, keys, signPk, cpKeys, snapshot };
}

function close(f) {
  f.db.close();
  fs.rmSync(f.home, { recursive: true, force: true });
}

function signedRequest(f, { context = REQUEST.context, ...overrides } = {}) {
  const challenge = auth.challenge(f.db);
  const nonce = Buffer.from(challenge.nonce, 'base64');
  const signed = {
    version: REQUEST.version, op: 'probe', account: 'alice', device_id: 'phone',
    resource: 'item', request_id: 'request-1', nonce, key_version: 1,
    ...overrides,
  };
  const req = { ...signed, nonce: nonce.toString('base64'), sign_pk: f.signPk.toString('base64') };
  req.sig = provider.sign(f.keys.signPrivate, context,
    encode(REQUEST.label, REQUEST.fields.map((key) => signed[key]))).toString('base64');
  return req;
}

test('challenge returns a unique 32-byte nonce with a 30 second lifetime', () => {
  const f = fixture();
  try {
    const before = Date.now();
    const first = auth.challenge(f.db), second = auth.challenge(f.db);
    assert.equal(Buffer.from(first.nonce, 'base64').length, REQUEST.nonceBytes);
    assert.notEqual(first.nonce, second.nonce);
    assert.ok(first.expires_ms >= before + REQUEST.challengeTtlMs - 2);
    assert.ok(first.expires_ms <= Date.now() + REQUEST.challengeTtlMs);
  } finally { close(f); }
});

test('valid signed request is allowed', () => {
  const f = fixture();
  try {
    const result = auth.authenticate(f.db, signedRequest(f));
    assert.deepEqual({ ok: result.ok, rule: result.rule, device_id: result.device?.device_id },
      { ok: true, rule: 'allowed', device_id: 'phone' });
  } finally { close(f); }
});

test('altered transcript field is denied as bad_signature', () => {
  const f = fixture();
  try {
    const req = signedRequest(f);
    const nonce = Buffer.from(req.nonce, 'base64');
    req.resource = 'other';
    assert.equal(auth.authenticate(f.db, req).rule, 'bad_signature');
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM challenges WHERE nonce=?').get(nonce).n, 0);
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM used_nonces WHERE nonce=?').get(nonce).n, 1);
    assert.equal(auth.authenticate(f.db, req).rule, 'nonce_reused');
  } finally { close(f); }
});

test('replayed nonce is denied as nonce_reused', () => {
  const f = fixture();
  try {
    const req = signedRequest(f);
    assert.equal(auth.authenticate(f.db, req).ok, true);
    assert.equal(auth.authenticate(f.db, req).rule, 'nonce_reused');
  } finally { close(f); }
});

test('expired challenge is denied as nonce_expired', () => {
  const f = fixture();
  try {
    const req = signedRequest(f);
    const nonce = Buffer.from(req.nonce, 'base64');
    f.db.prepare('UPDATE challenges SET expires_ms=? WHERE nonce=?').run(Date.now() - 1, nonce);
    auth.challenge(f.db);
    assert.equal(auth.authenticate(f.db, req).rule, 'nonce_expired');
  } finally { close(f); }
});

test('unknown device is rejected before its nonce or signature is considered', () => {
  const f = fixture();
  try {
    const req = signedRequest(f);
    req.device_id = 'unknown';
    assert.equal(auth.authenticate(f.db, req).rule, 'unknown_device');
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM used_nonces').get().n, 0);
  } finally { close(f); }
});

test('signature made with the wrong context is denied as bad_signature', () => {
  const f = fixture();
  try {
    assert.equal(auth.authenticate(f.db, signedRequest(f, { context: provider.CONTEXTS.handshake })).rule, 'bad_signature');
  } finally { close(f); }
});

test('revoked device is denied before nonce processing', () => {
  const f = fixture({ revoked: true });
  try {
    assert.equal(auth.authenticate(f.db, signedRequest(f)).rule, 'device_revoked');
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM used_nonces').get().n, 0);
  } finally { close(f); }
});

test('stale lease is denied before device or nonce processing', () => {
  const f = fixture();
  try {
    f.db.prepare("UPDATE lease SET v='0' WHERE k='lease_until_mono_ns'").run();
    assert.equal(auth.authenticate(f.db, signedRequest(f)).rule, 'lease_expired');
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM used_nonces').get().n, 0);
  } finally { close(f); }
});

test('request naming a stale file version is denied as old_key_version', () => {
  const f = fixture({ files: [{ file_id: 'item', active_version: 2, cutoff: null }] });
  try {
    assert.equal(auth.authenticate(f.db, signedRequest(f, { op: 'file.read', key_version: 1 })).rule, 'old_key_version');
  } finally { close(f); }
});

test('malformed auth body receives HTTP 400', async () => {
  const f = fixture();
  try {
    const result = await require('../../src/node/routes-auth.cjs').routeAuthenticate(f.db)(null);
    assert.deepEqual(result, { status: 400, json: { error: 'bad_request' } });
  } finally { close(f); }
});

test('device client returns decision fields directly', async () => {
  const f = fixture();
  const transport = require('../../src/core/http.cjs');
  const originalCall = transport.call;
  try {
    transport.call = async (_url, method, body) => {
      if (method === 'GET') return { status: 200, json: auth.challenge(f.db) };
      const result = auth.authenticate(f.db, body);
      return { status: 200, json: { decision: result.ok ? 'allow' : 'deny', rule: result.rule } };
    };
    const result = await require('../../src/device/client.cjs').request('http://127.0.0.1:7401',
      layout(f.home).device('phone').dir, 'probe', {
        home: f.home, account: 'alice', device_id: 'phone', resource: 'item', request_id: 'client-1', key_version: 1,
      });
    assert.deepEqual(result, { decision: 'allow', rule: 'allowed' });
  } finally {
    transport.call = originalCall;
    close(f);
  }
});
