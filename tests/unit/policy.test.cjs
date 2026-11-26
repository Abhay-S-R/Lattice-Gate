'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const ids = require('../../src/core/ids.cjs');
const schema = require('../../src/store/schema-adapter.cjs');
const { authorizeOwnerRead } = require('../../src/core/policy.cjs');

/**
 * @param {{ assets?: Array<[string, string|null, string|null]>, revoked?: string[] }} seed
 *   assets: [asset, owner, body] as plain strings (null = column NULL); stored D-04 encoded.
 */
function makeDb({ assets = [], revoked = [] } = {}) {
  const db = new DatabaseSync(':memory:');
  schema.init(db); // the real adapter schema v1 (architecture §5.4)
  const ins = db.prepare('INSERT INTO assets (asset, owner, body) VALUES (?, ?, ?)');
  for (const [a, o, b] of assets) ins.run(ids.enc(a), o === null ? null : ids.enc(o), b === null ? null : ids.enc(b));
  const rev = db.prepare("INSERT INTO revoked_actors (actor, source, epoch) VALUES (?, 'revoke', 1)");
  for (const r of revoked) rev.run(ids.enc(r));
  return db;
}

const DENY_KEYS = ['decision', 'rule'];

test('allow returns exact body', () => {
  const bodies = ['demo note', '', 'ünïcode ✓ 🙂', 'lone \ud800 surrogate', 'nul \u0000 inside', '"quoted"\n{"decision":"deny"}'];
  const db = makeDb({ assets: bodies.map((b, i) => [`a${i}`, 'maya', b]) });
  bodies.forEach((b, i) => {
    const r = authorizeOwnerRead(db, 'maya', `a${i}`);
    assert.deepEqual(r, { decision: 'allow', rule: 'owner_allowed', body: b });
  });
});

test('revoked owner denied even though owner', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'demo note']], revoked: ['maya'] });
  assert.deepEqual(authorizeOwnerRead(db, 'maya', 'brief'), { decision: 'deny', rule: 'actor_revoked' });
});

test('revocation is checked before asset existence', () => {
  const db = makeDb({ revoked: ['maya'] });
  assert.equal(authorizeOwnerRead(db, 'maya', 'nope').rule, 'actor_revoked');
});

test('unknown asset', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'demo note']] });
  assert.deepEqual(authorizeOwnerRead(db, 'maya', 'other'), { decision: 'deny', rule: 'unknown_asset' });
});

test('unknown asset on an empty store', () => {
  assert.deepEqual(authorizeOwnerRead(makeDb(), 'maya', 'brief'), { decision: 'deny', rule: 'unknown_asset' });
});

test('asset with owner but no contents', () => {
  const db = makeDb({ assets: [['brief', 'maya', null]] });
  assert.deepEqual(authorizeOwnerRead(db, 'maya', 'brief'), { decision: 'deny', rule: 'unknown_asset' });
});

test('asset with contents but no owner', () => {
  const db = makeDb({ assets: [['brief', null, 'demo note']] });
  assert.deepEqual(authorizeOwnerRead(db, 'maya', 'brief'), { decision: 'deny', rule: 'unknown_asset' });
  assert.deepEqual(authorizeOwnerRead(db, 'null', 'brief'), { decision: 'deny', rule: 'unknown_asset' });
});

test('not owner', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'demo note']] });
  assert.deepEqual(authorizeOwnerRead(db, 'bob', 'brief'), { decision: 'deny', rule: 'not_owner' });
});

test('deny has no body key', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'demo note'], ['nobody', 'maya', null]], revoked: ['eve'] });
  for (const [actor, asset] of [['eve', 'brief'], ['maya', 'missing'], ['maya', 'nobody'], ['bob', 'brief']]) {
    const r = authorizeOwnerRead(db, actor, asset);
    assert.equal(r.decision, 'deny');
    assert.ok(!('body' in r), `${actor}/${asset}`);
    assert.deepEqual(Object.keys(r).sort(), DENY_KEYS);
  }
});

test('revoking one actor leaves other owners allowed', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'm'], ['other', 'peer', 'p']], revoked: ['maya'] });
  assert.equal(authorizeOwnerRead(db, 'maya', 'brief').decision, 'deny');
  assert.deepEqual(authorizeOwnerRead(db, 'peer', 'other'), { decision: 'allow', rule: 'owner_allowed', body: 'p' });
});

test('prototype-named ids are ordinary identities', () => {
  const db = makeDb({ assets: [['constructor', '__proto__', 'x'], ['__proto__', 'constructor', 'y']] });
  assert.deepEqual(authorizeOwnerRead(db, '__proto__', 'constructor'), { decision: 'allow', rule: 'owner_allowed', body: 'x' });
  assert.deepEqual(authorizeOwnerRead(db, 'constructor', '__proto__'), { decision: 'allow', rule: 'owner_allowed', body: 'y' });
  assert.equal(authorizeOwnerRead(db, 'constructor', 'constructor').rule, 'not_owner');
});

test('lone surrogate and U+FFFD are different actors', () => {
  const db = makeDb({ assets: [['brief', '\ud800', 'secret']], revoked: ['�'] });
  assert.equal(authorizeOwnerRead(db, '�', 'brief').rule, 'actor_revoked');
  assert.deepEqual(authorizeOwnerRead(db, '\ud800', 'brief'), { decision: 'allow', rule: 'owner_allowed', body: 'secret' });
  const db2 = makeDb({ assets: [['brief', '\ud800', 'secret']] });
  assert.equal(authorizeOwnerRead(db2, '�', 'brief').rule, 'not_owner');
});

test('NUL and injection-shaped ids are compared exactly', () => {
  const db = makeDb({ assets: [['a\u0000b', 'x\n{"actor":"admin"}', 'body']] });
  assert.equal(authorizeOwnerRead(db, 'x\n{"actor":"admin"}', 'a\u0000b').decision, 'allow');
  assert.equal(authorizeOwnerRead(db, 'x', 'a\u0000b').rule, 'not_owner');
  assert.equal(authorizeOwnerRead(db, 'x\n{"actor":"admin"}', 'a').rule, 'unknown_asset');
  assert.equal(authorizeOwnerRead(db, "' OR 1=1 --", 'a\u0000b').rule, 'not_owner');
});

test('empty-string ids work', () => {
  const db = makeDb({ assets: [['', '', 'empty']] });
  assert.deepEqual(authorizeOwnerRead(db, '', ''), { decision: 'allow', rule: 'owner_allowed', body: 'empty' });
});

test('policy does not write', () => {
  const db = makeDb({ assets: [['brief', 'maya', 'm']], revoked: ['eve'] });
  const before = db.prepare('SELECT total_changes() AS n').get().n;
  for (const [a, s] of [['maya', 'brief'], ['eve', 'brief'], ['bob', 'brief'], ['maya', 'x']]) authorizeOwnerRead(db, a, s);
  assert.equal(db.prepare('SELECT total_changes() AS n').get().n, before);
});
