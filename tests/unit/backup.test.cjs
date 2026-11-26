'use strict';
// Task 4.4: signed, encrypted backup and verified restore (features P1-07, D-07; architecture §13).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { layout, BACKUP } = require('../../src/core/contracts.cjs');
const { freshHome } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const provider = require('../../src/crypto/provider.cjs');
const backup = require('../../src/cp/backup.cjs');
const { openReadOnly } = require('../../src/store/db.cjs');
const ids = require('../../src/core/ids.cjs');

function liveState(home) {
  const out = new Map();
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (!/-(wal|shm)$/.test(e.name)) out.set(path.relative(home, p), provider.sha256(fs.readFileSync(p)).toString('hex'));
    }
  };
  walk(home);
  return out;
}

function fixture(t) {
  const home = freshHome();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-backup-work-'));
  t.after(() => { fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });
  // Port base nobody listens on: these tests run without a cluster.
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(20000 + Math.floor(Math.random() * 20000)) };
  const run = (args) => runKig(args, { env, timeoutMs: 60000 });
  const ok = (args) => { const r = run(args); assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr || r.stdout}`); return r; };
  ok(['init']);
  ok(['account', 'add', 'alice']);
  ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'first']);
  const input = path.join(work, 'brief.txt');
  fs.writeFileSync(input, 'backup me');
  ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  const L = layout(home);
  const recovery = L.operator.recoveryKey.key;
  const anchor = path.join(path.dirname(L.anchor.cpPolicyPub), 'keys.json');
  const restore = (dir, { key = recovery, anc = anchor } = {}) => run(['restore', dir, '--recovery-key', key, '--anchor', anc]);
  const makeBackup = (name) => {
    const dir = path.join(work, name);
    const r = ok(['backup', '--out', dir]);
    assert.match(r.stdout, /^BACKUP .+ id=[0-9a-f]{32} epoch=\d+ log_seq=\d+ schema=2\n$/);
    return dir;
  };
  const copy = (dir, name) => { const to = path.join(work, name); fs.cpSync(dir, to, { recursive: true }); return to; };
  const epoch = () => { const db = openReadOnly(L.cp.db); try { return Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v); } finally { db.close(); } };
  return { home, work, L, run, ok, restore, makeBackup, copy, epoch, recovery, anchor };
}

function refused(f, dir, category, opts) {
  const before = liveState(f.home);
  const r = f.restore(dir, opts);
  assert.equal(r.code, 1, `${category}: ${r.stdout}`);
  assert.equal(r.stderr, `kig restore: RESTORE REFUSED: ${category} (live state unchanged)\n`);
  assert.deepEqual(liveState(f.home), before, `${category}: live state must be byte-identical`);
}

test('backup layout, manifest fields, signature and encryption', (t) => {
  const f = fixture(t);
  const dir = f.makeBackup('b1');
  assert.deepEqual(fs.readdirSync(dir).sort(), [...BACKUP.files].sort());
  const m = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  assert.equal(m.format, BACKUP.format);
  assert.equal(m.schema_version, 2);
  assert.equal(m.revocation_epoch, f.epoch());
  assert.deepEqual(m.key_versions, [{ file_id: 'brief', active_version: 1 }]);
  assert.ok(m.log_seq > 0);
  assert.deepEqual(m.algorithms, { payload: 'AES-256-GCM', key_wrap: 'ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM', signature: 'ML-DSA-65', digest: 'SHA-256' });
  const backupPub = provider.importPublic(fs.readFileSync(f.L.cp.keys.backup.pub));
  assert.ok(provider.verify(backupPub, 'kig/v1/backup', backup.manifestBytes(m), fs.readFileSync(path.join(dir, 'manifest.sig'))));
  // Nothing readable in the payload: no key bytes, no SQLite header.
  const payload = fs.readFileSync(path.join(dir, 'payload.bin'));
  assert.equal(payload.includes(Buffer.from('SQLite format 3')), false);
  assert.equal(payload.includes(fs.readFileSync(f.L.cp.keys.masterKem.key).subarray(-32)), false);
  assert.equal(JSON.parse(fs.readFileSync(f.anchor, 'utf8')).min_backup_epoch, m.revocation_epoch, 'backup pins its epoch in the anchor');
  const again = f.run(['backup', '--out', dir]);
  assert.equal(again.code, 1, 'never overwrite an existing backup');
});

test('restore refuses flipped bits, truncation, bad signatures, unsupported schema, wrong key and defective contents', (t) => {
  const f = fixture(t);
  const good = f.makeBackup('good');
  const m = JSON.parse(fs.readFileSync(path.join(good, 'manifest.json'), 'utf8'));
  const writeManifest = (dir, manifest, signer) => {
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
    if (signer) fs.writeFileSync(path.join(dir, 'manifest.sig'), provider.sign(signer, 'kig/v1/backup', backup.manifestBytes(manifest)));
  };
  const backupKey = provider.importPrivate(fs.readFileSync(f.L.cp.keys.backup.key));

  for (const at of [0, 12, 100, -1]) { // nonce, ciphertext, tag
    const d = f.copy(good, `flip-${at}`); const p = path.join(d, 'payload.bin'); const b = fs.readFileSync(p);
    b[at < 0 ? b.length + at : at] ^= 0x01; fs.writeFileSync(p, b);
    refused(f, d, 'digest_mismatch');
  }
  const trunc = f.copy(good, 'truncated'); const tp = path.join(trunc, 'payload.bin');
  fs.writeFileSync(tp, fs.readFileSync(tp).subarray(0, -1));
  refused(f, trunc, 'digest_mismatch');
  const gone = f.copy(good, 'no-payload'); fs.rmSync(path.join(gone, 'payload.bin'));
  refused(f, gone, 'digest_mismatch');

  const sigFlip = f.copy(good, 'sig-flip'); const sp = path.join(sigFlip, 'manifest.sig'); const s = fs.readFileSync(sp); s[10] ^= 1; fs.writeFileSync(sp, s);
  refused(f, sigFlip, 'bad_signature');
  const edited = f.copy(good, 'edited'); writeManifest(edited, { ...m, revocation_epoch: m.revocation_epoch + 5 });
  refused(f, edited, 'bad_signature');
  const forged = f.copy(good, 'forged'); writeManifest(forged, { ...m, revocation_epoch: m.revocation_epoch + 5 }, provider.sigGenerate().privateKey);
  refused(f, forged, 'bad_signature'); // signed, but not by the key the anchor pins
  const extra = f.copy(good, 'extra'); writeManifest(extra, { ...m, restore_hint: 'trust me' }, backupKey);
  refused(f, extra, 'bad_signature'); // unsigned extra fields are not accepted
  const noSig = f.copy(good, 'no-sig'); fs.rmSync(path.join(noSig, 'manifest.sig'));
  refused(f, noSig, 'bad_signature');

  const schema = f.copy(good, 'schema-99'); writeManifest(schema, { ...m, schema_version: 99 }, backupKey);
  refused(f, schema, 'unsupported_schema');
  const format = f.copy(good, 'format'); writeManifest(format, { ...m, format: 'kig-backup/9' }, backupKey);
  refused(f, format, 'unsupported_schema');

  const wrongKey = path.join(f.work, 'other-recovery.key');
  fs.writeFileSync(wrongKey, provider.exportPrivate(provider.kemGenerate().privateKey));
  refused(f, good, 'decrypt_failed', { key: wrongKey });

  const meta = { schema_version: m.schema_version, revocation_epoch: m.revocation_epoch, log_seq: m.log_seq, key_versions: m.key_versions };
  const keyDir = path.dirname(f.L.cp.keys.policy.key);
  const realKeys = Object.fromEntries(backup.KEY_FILES.map((n) => [`keys/${n}`, fs.readFileSync(path.join(keyDir, n))]));
  const goodDb = (() => { // the registry exactly as it was when `good` was taken
    const v = backup.validate(f.home, good, { recoveryKeyFile: f.recovery, anchor: backup.readAnchor(f.anchor) });
    try { return fs.readFileSync(v.dbFile); } finally { fs.rmSync(v.tmp, { recursive: true, force: true }); }
  })();
  const sealed = (name, payloadFiles) => { const d = path.join(f.work, name); backup.seal(f.home, d, { payloadFiles, meta }); return d; };
  const { ['keys/master-kem.key']: _drop, ...noMaster } = realKeys;
  refused(f, sealed('no-master', { 'registry.db': goodDb, ...noMaster }), 'incomplete_backup');
  refused(f, sealed('garbage-db', { 'registry.db': provider.random(4096), ...realKeys }), 'incomplete_backup');
  const otherPolicy = provider.sigGenerate();
  refused(f, sealed('foreign-key', { 'registry.db': goodDb, ...realKeys, 'keys/policy.key': provider.exportPrivate(otherPolicy.privateKey),
    'keys/policy.pub': provider.exportPublic(otherPolicy.publicKey) }), 'incomplete_backup');
  const otherMaster = provider.kemGenerate();
  refused(f, sealed('wrong-master', { 'registry.db': goodDb, ...realKeys, 'keys/master-kem.key': provider.exportPrivate(otherMaster.privateKey) }), 'incomplete_backup');

  const badAnchor = path.join(f.work, 'anchor.json'); fs.writeFileSync(badAnchor, '{}');
  const r = f.restore(good, { anc: badAnchor });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /anchor file is unreadable/);

  // After all those refusals the good backup still restores.
  const ok = f.restore(good);
  assert.equal(ok.code, 0, ok.stderr);
});

test('anti-rollback: older than the live CP or the anchor minimum is stale; current backups restore, with or without a live registry', (t) => {
  const f = fixture(t);
  const b1 = f.makeBackup('b1');
  const e1 = f.epoch();
  f.ok(['account', 'add', 'bob']); // a committed change: new epoch
  assert.ok(f.epoch() > e1);
  refused(f, b1, 'stale_backup');
  const flipStale = f.copy(b1, 'stale-and-flipped'); const p = path.join(flipStale, 'payload.bin'); const b = fs.readFileSync(p); b[50] ^= 1; fs.writeFileSync(p, b);
  refused(f, flipStale, 'digest_mismatch'); // checks run in §13.2 order

  const b2 = f.makeBackup('b2');
  const e2 = JSON.parse(fs.readFileSync(path.join(b2, 'manifest.json'), 'utf8')).revocation_epoch;
  const restored = f.restore(b2); // equal to the live epoch: allowed
  assert.equal(restored.code, 0, restored.stderr);
  assert.match(restored.stdout, new RegExp(`^RESTORED [0-9a-f]{32} epoch=${e2} log_seq=\\d+; previous registry kept as .+registry\\.db\\.quarantine-\\d+\\n$`));

  // Disaster: the live registry is gone. The anchor minimum (raised by b2) still refuses b1.
  const lost = `${f.L.cp.db}.lost`;
  fs.renameSync(f.L.cp.db, lost);
  for (const s of ['-wal', '-shm']) fs.rmSync(f.L.cp.db + s, { force: true });
  refused(f, b1, 'stale_backup');
  const fromNothing = f.restore(b2);
  assert.equal(fromNothing.code, 0, fromNothing.stderr);
  assert.doesNotMatch(fromNothing.stdout, /previous registry/);
  const db = openReadOnly(f.L.cp.db);
  try {
    assert.equal(Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v), e2);
    assert.ok(db.prepare('SELECT 1 FROM accounts WHERE account=?').get(ids.enc('bob')));
    assert.equal(db.prepare("SELECT rule FROM audit_events ORDER BY seq DESC LIMIT 1").get().rule, 'backup_restored');
  } finally { db.close(); }
  const verified = f.run(['verify-log', '--db', f.L.cp.db]);
  assert.equal(verified.code, 0, verified.stderr);
  // The restored control plane works: sharing unwraps the file key through the restored master KEM key.
  const shared = f.run(['share', 'brief', '--with', 'bob']);
  assert.equal(shared.code, 0, shared.stderr);
});
