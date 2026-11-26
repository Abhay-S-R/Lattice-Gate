'use strict';
// Task 2.3: signed checkpoints + external anchor (features P1-08, architecture §14.2–14.3).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runKig } = require('../helpers/run-kig.cjs');
const { makeStore, tamperedCopy, appendReads } = require('../helpers/audit-fixture.cjs');
const { tx } = require('../../src/store/db.cjs');
const audit = require('../../src/core/audit.cjs');
const provider = require('../../src/crypto/provider.cjs');

const OK = /^OK (\d+) [0-9a-f]{64}\n$/;
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));

function keys() {
  const dir = tmp('kig-keys-');
  const r = runKig(['keys', 'init', '--out', dir]);
  assert.equal(r.code, 0, r.stderr);
  return { dir, key: path.join(dir, 'audit-signing.key'), pub: path.join(dir, 'audit-signing.pub') };
}

/** Store + key + one checkpoint; anchor kept outside the state dir. */
async function anchored() {
  const s = await makeStore();
  const k = keys();
  const anchor = path.join(tmp('kig-anchor-'), 'adapter-anchor.json');
  const r = runKig(['checkpoint', '--adapter', s.ctx.stateDir, '--key', k.key, '--anchor', anchor]);
  assert.equal(r.code, 0, r.stderr);
  return { ...s, ...k, anchor };
}

const readAnchor = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const writeAnchor = (f, a) => fs.writeFileSync(f, JSON.stringify(a));

test('publicFromPrivate derives the matching public key', () => {
  const { publicKey, privateKey } = provider.sigGenerate();
  assert.ok(provider.exportPublic(provider.publicFromPrivate(privateKey)).equals(provider.exportPublic(publicKey)));
});

test('keys init writes a private and a public key; private is 0600', { skip: process.platform === 'win32' }, () => {
  const k = keys();
  assert.equal(fs.statSync(k.key).mode & 0o777, 0o600);
  const priv = provider.importPrivate(fs.readFileSync(k.key));
  const pub = provider.importPublic(fs.readFileSync(k.pub));
  const sig = provider.sign(priv, provider.CONTEXTS.checkpoint, Buffer.from('m'));
  assert.equal(provider.verify(pub, provider.CONTEXTS.checkpoint, Buffer.from('m'), sig), true);
});

test('keys init refuses to overwrite without --force', () => {
  const k = keys();
  const before = fs.readFileSync(k.key);
  assert.equal(runKig(['keys', 'init', '--out', k.dir]).code, 1);
  assert.ok(fs.readFileSync(k.key).equals(before));
  assert.equal(runKig(['keys', 'init', '--out', k.dir, '--force']).code, 0);
  assert.ok(!fs.readFileSync(k.key).equals(before));
});

test('keys without a subcommand → exit 2', () => {
  assert.equal(runKig(['keys']).code, 2);
  assert.equal(runKig(['keys', 'rotate']).code, 2);
});

test('checkpoint writes an anchor outside the store and does not touch the store', async () => {
  const s = await makeStore();
  const k = keys();
  const anchor = path.join(tmp('kig-anchor-'), 'a.json');
  const before = fs.readFileSync(s.dbPath);
  const r = runKig(['checkpoint', '--db', s.dbPath, '--key', k.key, '--anchor', anchor]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^CHECKPOINT seq=\d+ id=[0-9a-f]{32}\n$/);
  assert.ok(fs.readFileSync(s.dbPath).equals(before));
  const a = readAnchor(anchor);
  assert.equal(a.version, 1);
  assert.equal(a.checkpoints.length, 1);
  assert.equal(a.checkpoints[0].prev_checkpoint_id, null);
  assert.ok(provider.exportPublic(provider.importPublic(Buffer.from(a.public_key, 'base64')))
    .equals(fs.readFileSync(k.pub)));
});

test('verify-log --anchor on an untouched store → OK', async () => {
  const s = await anchored();
  const r = runKig(['verify-log', '--db', s.dbPath, '--anchor', s.anchor]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, OK);
});

test('growth after the checkpoint is fine; a second checkpoint links to the first', async () => {
  const s = await anchored();
  await appendReads(s.ctx, 3);
  assert.match(runKig(['verify-log', '--db', s.dbPath, '--anchor', s.anchor]).stdout, OK);
  assert.equal(runKig(['checkpoint', '--db', s.dbPath, '--key', s.key, '--anchor', s.anchor]).code, 0);
  const a = readAnchor(s.anchor);
  assert.equal(a.checkpoints.length, 2);
  assert.equal(a.checkpoints[1].prev_checkpoint_id, a.checkpoints[0].checkpoint_id);
  assert.ok(a.checkpoints[1].seq > a.checkpoints[0].seq);
  assert.match(runKig(['verify-log', '--db', s.dbPath, '--anchor', s.anchor]).stdout, OK);
});

test('truncated after anchored checkpoint detected', async () => {
  const s = await anchored();
  const cpSeq = readAnchor(s.anchor).checkpoints[0].seq;
  const copy = tamperedCopy(s.dbPath, (db) => db.prepare('DELETE FROM audit_events WHERE seq > ?').run(cpSeq - 2));
  // Without the anchor, a clean truncation is invisible: that is why the anchor exists.
  assert.match(runKig(['verify-log', '--db', copy]).stdout, OK);
  const r = runKig(['verify-log', '--db', copy, '--anchor', s.anchor]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, `BROKEN seq=${cpSeq - 1} truncated\n`);
});

test('rewritten chain (recomputed hashes) detected by the checkpoint', async () => {
  const s = await anchored();
  const cpSeq = readAnchor(s.anchor).checkpoints[0].seq;
  const copy = tamperedCopy(s.dbPath, (db) => {
    db.prepare('DELETE FROM audit_events WHERE seq >= ?').run(2);
    for (let i = 2; i <= cpSeq; i++) {
      tx(db, () => audit.append(db, { gen: 1, kind: 'access', op: 'read', request_id: `forged${i}`, actor: 'maya', asset: 'brief', decision: 'allow', rule: 'owner_allowed' }));
    }
  });
  assert.match(runKig(['verify-log', '--db', copy]).stdout, OK);
  const r = runKig(['verify-log', '--db', copy, '--anchor', s.anchor]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, `BROKEN seq=${cpSeq} checkpoint_mismatch\n`);
});

test('forged checkpoint signature rejected', async () => {
  const s = await anchored();
  const a = readAnchor(s.anchor);
  a.checkpoints[0].seq -= 1; // claim an earlier head without re-signing
  writeAnchor(s.anchor, a);
  const r = runKig(['verify-log', '--db', s.dbPath, '--anchor', s.anchor]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, `BROKEN seq=${a.checkpoints[0].seq} invalid_checkpoint\n`);
});

test('broken prev link between checkpoints rejected', async () => {
  const s = await anchored();
  runKig(['checkpoint', '--db', s.dbPath, '--key', s.key, '--anchor', s.anchor]);
  const a = readAnchor(s.anchor);
  a.checkpoints.splice(0, 1); // drop the first: the second's prev link now dangles
  writeAnchor(s.anchor, a);
  assert.match(runKig(['verify-log', '--db', s.dbPath, '--anchor', s.anchor]).stdout, /invalid_checkpoint/);
});

test('anchor for a different store rejected', async () => {
  const a1 = await anchored();
  const other = await makeStore();
  const r = runKig(['verify-log', '--db', other.dbPath, '--anchor', a1.anchor]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /invalid_checkpoint/);
});

test('unreadable anchor file → exit 1, one line', async () => {
  const s = await makeStore();
  const bad = path.join(tmp('kig-anchor-'), 'bad.json');
  fs.writeFileSync(bad, '{not json');
  const r = runKig(['verify-log', '--db', s.dbPath, '--anchor', bad]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.trim().split('\n').length, 1);
});

test('checkpoint refuses to sign a broken chain', async () => {
  const s = await makeStore();
  const k = keys();
  const copy = tamperedCopy(s.dbPath, (db) => db.exec("UPDATE audit_events SET rule = 'x' WHERE seq = 2"));
  const anchor = path.join(tmp('kig-anchor-'), 'a.json');
  const r = runKig(['checkpoint', '--db', copy, '--key', k.key, '--anchor', anchor]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /broken/i);
  assert.equal(fs.existsSync(anchor), false);
});

test('checkpoint refuses a key that does not match the anchor', async () => {
  const s = await anchored();
  const other = keys();
  const before = fs.readFileSync(s.anchor);
  assert.equal(runKig(['checkpoint', '--db', s.dbPath, '--key', other.key, '--anchor', s.anchor]).code, 1);
  assert.ok(fs.readFileSync(s.anchor).equals(before));
});

test('checkpoint refuses to extend an anchor the store no longer matches', async () => {
  const s = await anchored();
  const cpSeq = readAnchor(s.anchor).checkpoints[0].seq;
  const copy = tamperedCopy(s.dbPath, (db) => db.prepare('DELETE FROM audit_events WHERE seq > ?').run(cpSeq - 2));
  assert.equal(runKig(['checkpoint', '--db', copy, '--key', s.key, '--anchor', s.anchor]).code, 1);
  assert.equal(readAnchor(s.anchor).checkpoints.length, 1);
});
