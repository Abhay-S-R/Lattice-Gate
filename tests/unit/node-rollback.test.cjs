'use strict';
// Task 4.5: node anti-rollback (architecture §12.3 extra rules, features P1-06 [NEW]) and cutoff application.
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
const ids = require('../../src/core/ids.cjs');
const auth = require('../../src/node/auth.cjs');
const policy = require('../../src/node/policy.cjs');
const keystore = require('../../src/device/keystore.cjs');
const { signSnapshot } = require('../../src/cp/snapshot.cjs');

function fixture() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-rollback-'));
  const L = layout(home);
  fs.mkdirSync(L.node('A').dir, { recursive: true });
  const open = () => openDb(L.node('A').db, { create: true, version: schema.VERSION, init: schema.init });
  keystore.create(home, 'phone');
  const keys = keystore.load(home, 'phone');
  const signPk = provider.exportPublic(keys.signPublic);
  const cp = provider.sigGenerate();
  const device = (status) => ({
    device_id: 'phone', account: 'alice', sign_pk_sha256: provider.sha256(signPk).toString('hex'),
    kem_pk_sha256: provider.sha256(provider.exportPublic(keys.kemPublic)).toString('hex'), status,
  });
  const snap = (epoch, { status = 'active', files = [] } = {}) => signSnapshot({
    epoch, issued_at_ms: Date.now(), lease_ms: 5000, devices: [device(status)],
    revoked_devices: status === 'revoked' ? ['phone'] : [], files, grants: [],
  }, cp.privateKey);
  return { home, L, open, keys, signPk, cp, snap };
}

function probe(f, db) {
  const nonce = Buffer.from(auth.challenge(db).nonce, 'base64');
  const signed = { version: REQUEST.version, op: 'policy.probe', account: 'alice', device_id: 'phone', resource: 'probe',
    request_id: `r-${provider.random(6).toString('hex')}`, nonce, key_version: 1 };
  const req = { ...signed, nonce: nonce.toString('base64'), sign_pk: f.signPk.toString('base64') };
  req.sig = provider.sign(f.keys.signPrivate, REQUEST.context, encode(REQUEST.label, REQUEST.fields.map((k) => signed[k]))).toString('base64');
  return auth.authenticate(db, req);
}

const removeStore = (file) => { for (const s of ['', '-wal', '-shm']) fs.rmSync(file + s, { force: true }); };

test('an old node.db copied back fails closed, refuses the old snapshot, and the revoked device stays denied', () => {
  const f = fixture();
  const old = path.join(f.home, 'old-node.db');
  let db = f.open();
  try {
    assert.equal(policy.applySnapshot(db, f.snap(1), f.cp.publicKey).applied, true);
    assert.equal(probe(f, db).rule, 'allowed');
    db.exec(`VACUUM INTO '${old.replace(/'/g, "''")}'`); // the "old backup" of this node's store, at epoch 1
    assert.equal(policy.applySnapshot(db, f.snap(2, { status: 'revoked' }), f.cp.publicKey).applied, true);
    assert.equal(probe(f, db).rule, 'device_revoked');
    assert.equal(fs.readFileSync(`${f.L.node('A').db}.epoch`, 'utf8'), '2\n');
    db.close();

    // Roll the store back while the lease recorded in it is still fresh (it was refreshed < 5 s ago).
    removeStore(f.L.node('A').db);
    fs.copyFileSync(old, f.L.node('A').db);
    db = f.open();
    const state = policy.current(db);
    assert.equal(state.applied_epoch, 1);
    assert.equal(state.high_water, 2);
    assert.equal(state.lease_valid, false, 'a store behind the high-water mark must not be trusted');
    assert.equal(probe(f, db).rule, 'lease_expired', 'the rolled-back store must fail closed, never allow');

    assert.deepEqual(policy.applySnapshot(db, f.snap(1), f.cp.publicKey), { applied: false, reason: 'stale_epoch' });
    const nonce = provider.random(16);
    const head = { epoch: 1, nonce: nonce.toString('hex'), sig: provider.sign(f.cp.privateKey, 'kig/v1/revocation', encode('kig/v1/policy-head', [1, nonce])).toString('base64') };
    assert.equal(policy.acceptHead(db, head, nonce, f.cp.publicKey).reason, 'stale_head');

    // The current snapshot (epoch 2) is accepted even though it equals the mark, and the device stays revoked.
    assert.deepEqual(policy.applySnapshot(db, f.snap(2, { status: 'revoked' }), f.cp.publicKey), { applied: true, reason: 'applied' });
    assert.equal(policy.current(db).lease_valid, true);
    assert.equal(probe(f, db).rule, 'device_revoked');
  } finally { db.close(); fs.rmSync(f.home, { recursive: true, force: true }); }
});

test('a corrupt high-water file fails closed until the next snapshot is applied', () => {
  const f = fixture();
  const db = f.open();
  try {
    assert.equal(policy.applySnapshot(db, f.snap(1), f.cp.publicKey).applied, true);
    fs.writeFileSync(`${f.L.node('A').db}.epoch`, 'not-a-number');
    assert.equal(policy.current(db).lease_valid, false);
    assert.equal(probe(f, db).rule, 'lease_expired');
    assert.equal(policy.applySnapshot(db, f.snap(2), f.cp.publicKey).applied, true);
    assert.equal(policy.current(db).lease_valid, true);
    assert.equal(fs.readFileSync(`${f.L.node('A').db}.epoch`, 'utf8'), '2\n');
  } finally { db.close(); fs.rmSync(f.home, { recursive: true, force: true }); }
});

test('a cutoff is recorded once with this node\'s monotonic time and is not reset by a later snapshot', async () => {
  const f = fixture();
  const db = f.open();
  try {
    const files = [{ file_id: 'brief', active_version: 2, cutoff: { old_version: 1, from_epoch: 1, grace_ms: 30000 } }];
    assert.equal(policy.applySnapshot(db, f.snap(1, { files }), f.cp.publicKey).applied, true);
    const first = db.prepare('SELECT * FROM cutoffs WHERE file_id=?').get(ids.enc('brief'));
    assert.equal(first.old_version, 1);
    assert.equal(first.grace_ms, 30000);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(policy.applySnapshot(db, f.snap(2, { files }), f.cp.publicKey).applied, true);
    const again = db.prepare('SELECT * FROM cutoffs WHERE file_id=?').all(ids.enc('brief'));
    assert.equal(again.length, 1);
    assert.equal(again[0].applied_mono_ns, first.applied_mono_ns);
  } finally { db.close(); fs.rmSync(f.home, { recursive: true, force: true }); }
});

test('malformed cutoffs are rejected before anything is stored', () => {
  const f = fixture();
  const db = f.open();
  try {
    const bad = [
      { old_version: 2, from_epoch: 1, grace_ms: 30000 },            // not older than the active version
      { old_version: 0, from_epoch: 1, grace_ms: 30000 },            // no version 0
      { old_version: 1, from_epoch: 9, grace_ms: 30000 },            // from a future epoch
      { old_version: 1, from_epoch: 1, grace_ms: 0 },                // no grace
      { old_version: 1, from_epoch: 1, grace_ms: 600001 },           // above the cap
      { old_version: 1, from_epoch: 1, grace_ms: 30000, extra: 1 },  // unknown field
      { old_version: '1', from_epoch: 1, grace_ms: 30000 },          // not an integer
      [1, 1, 30000],
    ];
    for (const cutoff of bad) {
      const r = policy.applySnapshot(db, f.snap(1, { files: [{ file_id: 'brief', active_version: 2, cutoff }] }), f.cp.publicKey);
      assert.deepEqual(r, { applied: false, reason: 'invalid_snapshot' }, JSON.stringify(cutoff));
    }
    const dup = [{ file_id: 'brief', active_version: 1, cutoff: null }, { file_id: 'brief', active_version: 2, cutoff: null }];
    assert.deepEqual(policy.applySnapshot(db, f.snap(1, { files: dup }), f.cp.publicKey), { applied: false, reason: 'invalid_snapshot' });
    assert.equal(policy.current(db).applied_epoch, 0);
  } finally { db.close(); fs.rmSync(f.home, { recursive: true, force: true }); }
});

test('applying a snapshot that revokes a device terminates its open transfers in the same transaction', () => {
  const f = fixture();
  const db = f.open();
  try {
    assert.equal(policy.applySnapshot(db, f.snap(1), f.cp.publicKey).applied, true);
    db.prepare("INSERT INTO transfers(transfer_id,file_id,version,device_id,account,created_mono_ns,created_ms,chunk_count,total_bytes,state) VALUES(?,?,?,?,?,?,?,?,?,'open')")
      .run('t1', ids.enc('brief'), 1, ids.enc('phone'), ids.enc('alice'), process.hrtime.bigint().toString(), Date.now(), 1, 10);
    assert.equal(policy.applySnapshot(db, f.snap(2, { status: 'revoked' }), f.cp.publicKey).applied, true);
    const t = db.prepare('SELECT state, reason FROM transfers WHERE transfer_id=?').get('t1');
    assert.deepEqual({ ...t }, { state: 'terminated', reason: 'device_revoked' });
  } finally { db.close(); fs.rmSync(f.home, { recursive: true, force: true }); }
});
