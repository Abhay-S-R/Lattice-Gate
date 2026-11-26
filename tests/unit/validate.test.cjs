'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const v = require('../../src/adapter/validate.cjs');

// 1184 bytes whose Base64 contains both '+' and '/', so URL-safe substitution is a real change.
const KEY_BYTES = Buffer.from(Array.from({ length: 1184 }, (_, i) => (i * 37 + 251) & 0xff));
const KEY_B64 = KEY_BYTES.toString('base64');

const setupReq = (extra = {}) => ({ op: 'setup', owners: { brief: 'maya' }, contents: { brief: 'demo note' }, disabled: [], key_material: 'synthetic-only', ...extra });
const readReq = (extra = {}) => ({ op: 'read', actor: 'maya', asset: 'brief', request_id: 'r01', ...extra });
const prReq = (extra = {}) => ({ op: 'protected_read', actor: 'maya', asset: 'brief', challenge: 'c', public_key: KEY_B64, ...extra });

// Turn Maps/Sets into plain JSON so the whole req can be scanned as text.
const dump = (req) => JSON.stringify(req, (_k, val) =>
  val instanceof Map ? [...val] : val instanceof Set ? [...val] : Buffer.isBuffer(val) ? val.toString('hex') : val);

test('fixture key is 1580 chars and uses + and /', () => {
  assert.equal(KEY_B64.length, 1580);
  assert.ok(KEY_B64.includes('+') && KEY_B64.includes('/'));
});

test('OPS lists exactly the five operations', () => {
  assert.deepEqual([...v.OPS].sort(), ['audit', 'protected_read', 'read', 'revoke', 'setup']);
});

// ---- setup ----

test('setup accepts proto keys', () => {
  const obj = JSON.parse('{"op":"setup","owners":{"__proto__":"maya","constructor":"bob"},"contents":{"__proto__":"x","constructor":"y"},"disabled":[]}');
  const r = v.validate('setup', obj);
  assert.equal(r.ok, true);
  assert.ok(r.req.owners instanceof Map && r.req.contents instanceof Map && r.req.disabled instanceof Set);
  assert.equal(r.req.owners.get('__proto__'), 'maya');
  assert.equal(r.req.owners.get('constructor'), 'bob');
  assert.equal(r.req.owners.size, 2);
  assert.equal(r.req.contents.get('__proto__'), 'x');
  assert.equal(r.req.contents.size, 2);
});

test('setup converts disabled to a Set and keeps opaque ids exactly', () => {
  const odd = ['', '\ud800', 'a\u0000b', 'x\n{"actor":"admin"}', '__proto__'];
  const r = v.validate('setup', setupReq({ disabled: odd }));
  assert.equal(r.ok, true);
  assert.deepEqual([...r.req.disabled], odd);
});

test('setup allows assets present in only one of owners/contents', () => {
  const r = v.validate('setup', setupReq({ owners: { a: 'maya' }, contents: { b: 'body' } }));
  assert.equal(r.ok, true);
  assert.equal(r.req.owners.size, 1);
  assert.equal(r.req.contents.size, 1);
});

test('setup rejects non-string owner value', () => {
  for (const bad of [1, null, true, ['maya'], { a: 1 }]) {
    assert.equal(v.validate('setup', setupReq({ owners: { brief: bad } })).ok, false);
  }
});

test('setup rejects non-string content value', () => {
  for (const bad of [1, null, ['x'], { a: 'b' }]) {
    assert.equal(v.validate('setup', setupReq({ contents: { brief: bad } })).ok, false);
  }
});

test('setup rejects disabled not array', () => {
  for (const bad of ['maya', { 0: 'maya' }, null, 1]) {
    assert.equal(v.validate('setup', setupReq({ disabled: bad })).ok, false);
  }
  assert.equal(v.validate('setup', setupReq({ disabled: ['ok', 7] })).ok, false);
});

test('setup rejects owners/contents that are not plain objects, or missing fields', () => {
  for (const field of ['owners', 'contents']) {
    for (const bad of [null, [], 'x', 1]) {
      assert.equal(v.validate('setup', setupReq({ [field]: bad })).ok, false, `${field}=${JSON.stringify(bad)}`);
    }
  }
  for (const field of ['owners', 'contents', 'disabled']) {
    const obj = setupReq();
    delete obj[field];
    assert.equal(v.validate('setup', obj).ok, false, `missing ${field}`);
  }
});

test('setup rejects over-long ids (owner value, asset key, disabled entry)', () => {
  const long = 'a'.repeat(8193);
  assert.equal(v.validate('setup', setupReq({ owners: { brief: long } })).ok, false);
  assert.equal(v.validate('setup', setupReq({ owners: { [long]: 'maya' } })).ok, false);
  assert.equal(v.validate('setup', setupReq({ contents: { [long]: 'x' } })).ok, false);
  assert.equal(v.validate('setup', setupReq({ disabled: [long] })).ok, false);
});

test('setup accepts long bodies (bodies are not identifiers)', () => {
  const r = v.validate('setup', setupReq({ contents: { brief: 'b'.repeat(100000) } }));
  assert.equal(r.ok, true);
});

test('key_material not in req', () => {
  const marker = 'MARKER-6f1c2e9a-key-material';
  const r = v.validate('setup', setupReq({ key_material: marker }));
  assert.equal(r.ok, true);
  assert.ok(!('key_material' in r.req));
  assert.ok(!dump(r.req).includes(marker));
  assert.deepEqual(Object.keys(r.req).sort(), ['contents', 'disabled', 'owners']);
});

test('key_material of any type is ignored, not validated', () => {
  for (const km of [undefined, null, 5, { nested: 'x' }, ['x']]) {
    assert.equal(v.validate('setup', setupReq({ key_material: km })).ok, true);
  }
});

// ---- read / revoke / audit ----

test('read returns exactly actor, asset, request_id', () => {
  const r = v.validate('read', readReq({ extra: 'ignored' }));
  assert.deepEqual(r, { ok: true, req: { actor: 'maya', asset: 'brief', request_id: 'r01' } });
});

test('read rejects missing request_id', () => {
  const obj = readReq();
  delete obj.request_id;
  assert.equal(v.validate('read', obj).ok, false);
  assert.equal(v.validate('read', readReq({ request_id: null })).ok, false);
});

test('read rejects number actor', () => {
  assert.equal(v.validate('read', readReq({ actor: 42 })).ok, false);
  assert.equal(v.validate('read', readReq({ asset: ['brief'] })).ok, false);
});

test('read rejects 8193-char id and accepts 8192', () => {
  assert.equal(v.validate('read', readReq({ actor: 'a'.repeat(8193) })).ok, false);
  assert.equal(v.validate('read', readReq({ request_id: 'r'.repeat(8193) })).ok, false);
  assert.equal(v.validate('read', readReq({ asset: 'a'.repeat(8192) })).ok, true);
});

test('read accepts hostile-looking ids (they are opaque)', () => {
  for (const id of ['', '__proto__', 'constructor', '\ud800', 'a\u0000b', '../../etc/passwd']) {
    const r = v.validate('read', readReq({ actor: id, asset: id, request_id: id }));
    assert.equal(r.ok, true);
    assert.equal(r.req.actor, id);
  }
});

test('revoke requires a string actor', () => {
  assert.deepEqual(v.validate('revoke', { op: 'revoke', actor: 'maya' }), { ok: true, req: { actor: 'maya' } });
  assert.equal(v.validate('revoke', { op: 'revoke' }).ok, false);
  assert.equal(v.validate('revoke', { op: 'revoke', actor: 1 }).ok, false);
});

test('audit requires a string request_id', () => {
  assert.deepEqual(v.validate('audit', { op: 'audit', request_id: 'r02' }), { ok: true, req: { request_id: 'r02' } });
  assert.equal(v.validate('audit', { op: 'audit' }).ok, false);
  assert.equal(v.validate('audit', { op: 'audit', request_id: 2 }).ok, false);
});

// ---- protected_read ----

test('protected_read returns decoded 1184-byte key', () => {
  const r = v.validate('protected_read', prReq());
  assert.equal(r.ok, true);
  assert.ok(Buffer.isBuffer(r.req.publicKey));
  assert.equal(r.req.publicKey.length, 1184);
  assert.ok(r.req.publicKey.equals(KEY_BYTES));
  assert.deepEqual(Object.keys(r.req).sort(), ['actor', 'asset', 'challenge', 'publicKey', 'request_id']);
});

test('base64 strict', () => {
  assert.equal(v.isStrictBase64(KEY_B64), true);
  assert.equal(v.validate('protected_read', prReq()).ok, true);

  const rejects = {
    'url-safe': KEY_B64.replace(/\+/g, '-').replace(/\//g, '_'),
    'inserted space': KEY_B64.slice(0, 100) + ' ' + KEY_B64.slice(100),
    'trailing newline': KEY_B64 + '\n',
    '1183 bytes': KEY_BYTES.subarray(0, 1183).toString('base64'),
    '1185 bytes': Buffer.concat([KEY_BYTES, Buffer.from([1])]).toString('base64'),
    'empty': '',
    'no padding': KEY_B64.replace(/=+$/, ''),
  };
  for (const [name, s] of Object.entries(rejects)) {
    assert.equal(v.validate('protected_read', prReq({ public_key: s })).ok, false, name);
  }
  for (const name of ['url-safe', 'inserted space', 'trailing newline', 'no padding']) {
    assert.equal(v.isStrictBase64(rejects[name]), false, name);
  }
});

test('base64 strict rejects non-canonical trailing bits', () => {
  // 1184 = 3*394 + 2, so the char before '=' carries 2 unused bits that must be zero.
  const i = KEY_B64.length - 2;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const bumped = KEY_B64.slice(0, i) + alphabet[alphabet.indexOf(KEY_B64[i]) | 1] + KEY_B64.slice(i + 1);
  assert.notEqual(bumped, KEY_B64);
  assert.ok(Buffer.from(bumped, 'base64').equals(KEY_BYTES), 'lenient decoder accepts it');
  assert.equal(v.isStrictBase64(bumped), false);
  assert.equal(v.validate('protected_read', prReq({ public_key: bumped })).ok, false);
});

test('base64 strict: misc shapes', () => {
  assert.equal(v.isStrictBase64('QUJD'), true);
  assert.equal(v.isStrictBase64('QUI='), true);
  assert.equal(v.isStrictBase64('QQ=='), true);
  assert.equal(v.isStrictBase64(''), true, 'empty is valid Base64; the 1184 length rule rejects it');
  for (const bad of ['QUJ', 'Q===', '=QUJ', 'QU=I', 'QUJD\r\n', 'QUJD====', 123, null, undefined, Buffer.from('QUJD')]) {
    assert.equal(v.isStrictBase64(bad), false, String(bad));
  }
  assert.equal(v.validate('protected_read', prReq({ public_key: KEY_BYTES })).ok, false, 'non-string key');
});

test('challenge over 4096 rejected', () => {
  assert.equal(v.validate('protected_read', prReq({ challenge: 'c'.repeat(4097) })).ok, false);
  assert.equal(v.validate('protected_read', prReq({ challenge: 'c'.repeat(4096) })).ok, true);
  assert.equal(v.validate('protected_read', prReq({ challenge: '' })).ok, true);
  assert.equal(v.validate('protected_read', prReq({ challenge: 5 })).ok, false);
  const obj = prReq();
  delete obj.challenge;
  assert.equal(v.validate('protected_read', obj).ok, false);
});

test('optional request_id on protected_read', () => {
  assert.equal(v.validate('protected_read', prReq()).req.request_id, null);
  assert.equal(v.validate('protected_read', prReq({ request_id: null })).req.request_id, null);
  assert.equal(v.validate('protected_read', prReq({ request_id: 'p01' })).req.request_id, 'p01');
  assert.equal(v.validate('protected_read', prReq({ request_id: '' })).req.request_id, '');
  assert.equal(v.validate('protected_read', prReq({ request_id: 7 })).ok, false);
  assert.equal(v.validate('protected_read', prReq({ request_id: 'r'.repeat(8193) })).ok, false);
});

test('protected_read rejects non-string actor/asset', () => {
  assert.equal(v.validate('protected_read', prReq({ actor: 1 })).ok, false);
  assert.equal(v.validate('protected_read', prReq({ asset: null })).ok, false);
});

// ---- general ----

test('unknown op and non-object input are rejected', () => {
  assert.equal(v.validate('delete', { op: 'delete' }).ok, false);
  assert.equal(v.validate('__proto__', {}).ok, false);
  assert.equal(v.validate('toString', {}).ok, false);
  for (const bad of [null, [], 'x', 1, undefined]) {
    assert.equal(v.validate('read', bad).ok, false);
  }
});

test('fields are read as own properties only', () => {
  const proto = { actor: 'maya', asset: 'brief', request_id: 'r01' };
  const obj = Object.create(proto);
  assert.equal(v.validate('read', obj).ok, false);
});

test('failure reasons are fixed codes that never echo client data', () => {
  const secret = 'SECRET-ECHO-CHECK';
  const cases = [
    ['setup', setupReq({ owners: { [secret]: 5 } })],
    ['setup', setupReq({ disabled: [secret, 1] })],
    ['read', readReq({ actor: secret.repeat(1000) })],
    ['protected_read', prReq({ public_key: secret })],
    ['audit', { request_id: { [secret]: 1 } }],
  ];
  for (const [op, obj] of cases) {
    const r = v.validate(op, obj);
    assert.equal(r.ok, false);
    assert.equal(typeof r.reason, 'string');
    assert.match(r.reason, /^[a-z_]+$/);
    assert.ok(!r.reason.includes(secret));
  }
});

test('hostileIds lists hostile identifiers from each req shape', () => {
  const setup = v.validate('setup', JSON.parse(
    '{"owners":{"__proto__":"maya","ok":"a\\u0000b"},"contents":{"x\\ny":"body \\u0000 is not an id"},"disabled":["../a","fine"]}')).req;
  assert.deepEqual(new Set(v.hostileIds(setup)), new Set(['__proto__', 'a\u0000b', 'x\ny', '../a']));

  const read = v.validate('read', readReq({ actor: '\ud800', asset: 'brief', request_id: 'constructor' })).req;
  assert.deepEqual(new Set(v.hostileIds(read)), new Set(['\ud800', 'constructor']));

  assert.deepEqual(v.hostileIds(v.validate('read', readReq()).req), []);
  assert.deepEqual(v.hostileIds(v.validate('revoke', { actor: '..\\x' }).req), ['..\\x']);
  assert.deepEqual(v.hostileIds(v.validate('audit', { request_id: 'r\n' }).req), ['r\n']);
  assert.deepEqual(v.hostileIds(v.validate('protected_read', prReq()).req), []);
  assert.deepEqual(v.hostileIds(v.validate('protected_read', prReq({ request_id: '__proto__' })).req), ['__proto__']);
});

test('hostileIds reports each id once', () => {
  const req = v.validate('read', readReq({ actor: '__proto__', asset: '__proto__', request_id: '__proto__' })).req;
  assert.deepEqual(v.hostileIds(req), ['__proto__']);
});
