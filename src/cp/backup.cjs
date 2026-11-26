'use strict';
// Signed, encrypted backups with anti-rollback restore (features P1-07, D-07; architecture §13;
// docs/plans/phase-4.md P4-D14, P4-D15).
//
// Backup directory:
//   manifest.json  {format, backup_id, schema_version, created_ms, key_versions, revocation_epoch,
//                   log_seq, payload_sha256, payload_bytes, algorithms}
//   manifest.sig   ML-DSA-65 (CP backup-signing key, ctx kig/v1/backup) over the length-prefixed manifest
//   wrap.bin       DEK_b wrapped to the operator recovery ML-KEM-768 key, context [backup_id, kig/v1/backup]
//   payload.bin    nonce(12) ‖ AES-256-GCM(DEK_b, aad = encode(backup_id, schema_version),
//                   {registry.db (VACUUM INTO snapshot), CP key files})
//
// Restore runs checks 1–6 against a temporary copy and touches live state only in step 7.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const wrap = require('../core/wrap.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const { openDb, openReadOnly, tx, quarantine } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const { BACKUP, layout } = require('../core/contracts.cjs');
const files = require('./files.cjs');

const SUPPORTED_SCHEMAS = Object.freeze([schema.VERSION]);
const KEY_FILES = Object.freeze(['policy.key', 'policy.pub', 'audit.key', 'audit.pub', 'backup.key', 'backup.pub', 'master-kem.key']);
const ALGORITHMS = Object.freeze({ payload: 'AES-256-GCM', key_wrap: 'ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM', signature: 'ML-DSA-65', digest: 'SHA-256' });
const MANIFEST_KEYS = ['algorithms', 'backup_id', 'created_ms', 'format', 'key_versions', 'log_seq', 'payload_bytes', 'payload_sha256', 'revocation_epoch', 'schema_version'];

class BackupError extends Error {
  constructor(code) { super(code); this.name = 'BackupError'; this.code = code; }
}
/** A refused restore. category is one of BACKUP.failures; live state was not modified. */
class RestoreError extends Error {
  constructor(category) { super(category); this.name = 'RestoreError'; this.category = category; }
}

const manifestBytes = (m) => encode(BACKUP.manifestLabel, [m.format, m.backup_id, m.schema_version, m.created_ms,
  JSON.stringify(m.key_versions), m.revocation_epoch, m.log_seq, m.payload_sha256, m.payload_bytes, JSON.stringify(m.algorithms)]);
const payloadAad = (backupId, schemaVersion) => encode(BACKUP.payloadLabel, [backupId, schemaVersion]);
const anchorPath = (L) => path.join(path.dirname(L.anchor.cpPolicyPub), 'keys.json');

function readAnchor(file) {
  const a = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const k of ['policy_public_key', 'audit_public_key', 'backup_public_key', 'recovery_public_key']) {
    if (typeof a[k] !== 'string' || !a[k]) throw new Error(`anchor missing ${k}`);
  }
  if (a.min_backup_epoch !== undefined && !(Number.isSafeInteger(a.min_backup_epoch) && a.min_backup_epoch >= 0)) throw new Error('anchor min_backup_epoch invalid');
  return a;
}
function writeAtomic(file, bytes, mode) {
  const tmp = `${file}.tmp-${process.pid}-${provider.random(4).toString('hex')}`;
  const fd = fs.openSync(tmp, 'w', mode);
  try { fs.writeSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
}

/**
 * Seal a backup directory from plaintext payload files and manifest metadata.
 * Exposed for tests that must build validly signed but otherwise defective backups.
 */
function seal(home, outDir, { payloadFiles, meta }) {
  const L = layout(home);
  const anchor = readAnchor(anchorPath(L));
  const backupId = meta.backup_id || provider.random(16).toString('hex');
  const plain = Buffer.from(JSON.stringify({ format: BACKUP.payloadFormat,
    files: Object.fromEntries(Object.entries(payloadFiles).map(([k, v]) => [k, Buffer.from(v).toString('base64')])) }));
  const dek = provider.random(32);
  try {
    const nonce = provider.random(12);
    const payload = Buffer.concat([nonce, provider.aeadSeal(dek, nonce, payloadAad(backupId, meta.schema_version), plain)]);
    const wrapped = wrap.serialize(wrap.kemWrap(Buffer.from(anchor.recovery_public_key, 'base64'), dek, [backupId, BACKUP.wrapLabel]));
    const manifest = {
      format: BACKUP.format, backup_id: backupId, schema_version: meta.schema_version, created_ms: Date.now(),
      key_versions: meta.key_versions, revocation_epoch: meta.revocation_epoch, log_seq: meta.log_seq,
      payload_sha256: provider.sha256(payload).toString('hex'), payload_bytes: payload.length, algorithms: { ...ALGORITHMS },
    };
    const sig = provider.sign(provider.importPrivate(fs.readFileSync(L.cp.keys.backup.key)), BACKUP.context, manifestBytes(manifest));
    fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(outDir, 'manifest.sig'), sig, { mode: 0o600 });
    fs.writeFileSync(path.join(outDir, 'wrap.bin'), `${JSON.stringify(wrapped)}\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(outDir, 'payload.bin'), payload, { mode: 0o600 });
    return manifest;
  } finally { dek.fill(0); plain.fill(0); }
}

/** §13.1. Returns the manifest. The anchor's min_backup_epoch is raised to this backup's epoch. */
function createBackup(home, outDir) {
  const L = layout(home);
  const out = path.resolve(outDir);
  if (fs.existsSync(out) && fs.readdirSync(out).length) throw new BackupError('output_not_empty');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-backup-'));
  try {
    const snapFile = path.join(tmp, 'registry.db');
    const live = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
    try { schema.ensurePhase4(live); live.exec(`VACUUM INTO '${snapFile.replace(/'/g, "''")}'`); } finally { live.close(); }
    const snap = openReadOnly(snapFile);
    let meta;
    try {
      meta = {
        schema_version: snap.prepare('PRAGMA user_version').get().user_version,
        revocation_epoch: Number(snap.prepare("SELECT v FROM meta WHERE k='epoch'").get().v),
        log_seq: Number(snap.prepare('SELECT coalesce(max(seq),0) AS n FROM audit_events').get().n),
        key_versions: snap.prepare('SELECT file_id, active_version FROM files ORDER BY file_id').all()
          .map((r) => ({ file_id: ids.dec(r.file_id), active_version: r.active_version })),
      };
    } finally { snap.close(); }
    const payloadFiles = { 'registry.db': fs.readFileSync(snapFile) };
    for (const name of KEY_FILES) payloadFiles[`keys/${name}`] = fs.readFileSync(path.join(path.dirname(L.cp.keys.policy.key), name));
    const manifest = seal(home, out, { payloadFiles, meta });
    for (const [k, v] of Object.entries(payloadFiles)) if (k.endsWith('.key')) v.fill(0);
    const anchorFile = anchorPath(L);
    const anchor = readAnchor(anchorFile);
    if (!(anchor.min_backup_epoch >= manifest.revocation_epoch)) {
      writeAtomic(anchorFile, Buffer.from(`${JSON.stringify({ ...anchor, min_backup_epoch: manifest.revocation_epoch }, null, 2)}\n`), 0o644);
    }
    const db = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
    try {
      tx(db, () => audit.append(db, { gen: 0, kind: 'backup_created', op: 'cp.backup', actor: 'operator', decision: 'allow', rule: 'backup_created',
        detail: { backup_id: manifest.backup_id, revocation_epoch: manifest.revocation_epoch, log_seq: manifest.log_seq } }));
    } finally { db.close(); }
    return manifest;
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

function liveEpoch(L) {
  if (!fs.existsSync(L.cp.db)) return 0;
  for (const open of [() => openReadOnly(L.cp.db), () => openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init })]) {
    let db;
    try { db = open(); return Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v); } catch { /* try the next way */ } finally { try { db?.close(); } catch { /* ignore */ } }
  }
  return 0; // an unreadable live registry is the disaster restore exists for; the anchor minimum still applies
}

function shapeOk(m) {
  return m && typeof m === 'object' && !Array.isArray(m) && Object.keys(m).sort().join(',') === MANIFEST_KEYS.join(',') &&
    typeof m.format === 'string' && typeof m.backup_id === 'string' && /^[0-9a-f]{32}$/.test(m.backup_id) &&
    Number.isSafeInteger(m.schema_version) && Number.isSafeInteger(m.created_ms) && Array.isArray(m.key_versions) &&
    Number.isSafeInteger(m.revocation_epoch) && m.revocation_epoch >= 0 && Number.isSafeInteger(m.log_seq) && m.log_seq >= 0 &&
    typeof m.payload_sha256 === 'string' && /^[0-9a-f]{64}$/.test(m.payload_sha256) && Number.isSafeInteger(m.payload_bytes) &&
    m.algorithms && typeof m.algorithms === 'object' && !Array.isArray(m.algorithms);
}

/**
 * §13.2 checks 1–6. Returns the validated content (in a temp dir the caller must remove).
 * Throws RestoreError(category) on the first failing check. Never writes live state.
 */
function validate(home, dir, { recoveryKeyFile, anchor }) {
  const L = layout(home);
  const read = (name) => fs.readFileSync(path.join(dir, name));
  // 1. Signature, with the backup key from the anchor (never from the backup).
  let manifest;
  try {
    manifest = JSON.parse(read('manifest.json').toString('utf8'));
    if (!shapeOk(manifest)) throw new Error('shape');
    if (!provider.verify(provider.importPublic(Buffer.from(anchor.backup_public_key, 'base64')), BACKUP.context, manifestBytes(manifest), read('manifest.sig'))) throw new Error('sig');
  } catch { throw new RestoreError('bad_signature'); }
  // 2. Schema.
  if (manifest.format !== BACKUP.format || !SUPPORTED_SCHEMAS.includes(manifest.schema_version)) throw new RestoreError('unsupported_schema');
  // 3. Digest (flipped bits, truncation).
  let payload;
  try { payload = read('payload.bin'); } catch { throw new RestoreError('digest_mismatch'); }
  if (payload.length !== manifest.payload_bytes || provider.sha256(payload).toString('hex') !== manifest.payload_sha256) throw new RestoreError('digest_mismatch');
  // 4. Anti-rollback: not older than the live CP, not older than the anchor's pinned minimum.
  if (manifest.revocation_epoch < liveEpoch(L) || manifest.revocation_epoch < (anchor.min_backup_epoch || 0)) throw new RestoreError('stale_backup');
  // 5. Decrypt.
  let dek, plain;
  try {
    const recovery = provider.importPrivate(fs.readFileSync(recoveryKeyFile));
    dek = wrap.kemUnwrap(recovery, JSON.parse(read('wrap.bin').toString('utf8')), [manifest.backup_id, BACKUP.wrapLabel]);
    plain = provider.aeadOpen(dek, payload.subarray(0, 12), payloadAad(manifest.backup_id, manifest.schema_version), payload.subarray(12));
  } catch { throw new RestoreError('decrypt_failed'); } finally { dek?.fill(0); }
  // 6. Complete: integrity, consistent with the manifest, and the required key material.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-restore-'));
  try {
    let content;
    try { content = JSON.parse(plain.toString('utf8')); } finally { plain.fill(0); }
    if (!content || content.format !== BACKUP.payloadFormat || !content.files || typeof content.files !== 'object') throw new Error('format');
    const get = (name) => { const v = content.files[name]; if (typeof v !== 'string') throw new Error(`missing ${name}`); return Buffer.from(v, 'base64'); };
    const dbFile = path.join(tmp, 'registry.db');
    fs.writeFileSync(dbFile, get('registry.db'), { mode: 0o600 });
    const keys = Object.fromEntries(KEY_FILES.map((n) => [n, get(`keys/${n}`)]));
    const db = openReadOnly(dbFile);
    try {
      if (db.prepare('PRAGMA integrity_check').get().integrity_check !== 'ok') throw new Error('integrity');
      if (db.prepare('PRAGMA user_version').get().user_version !== manifest.schema_version) throw new Error('version');
      if (Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v) !== manifest.revocation_epoch) throw new Error('epoch');
      if (Number(db.prepare('SELECT coalesce(max(seq),0) AS n FROM audit_events').get().n) !== manifest.log_seq) throw new Error('log_seq');
      if (!audit.verifyChain(db).ok) throw new Error('chain');
      // Signing keys must be the ones the anchor pins; .pub files must match their private keys.
      for (const [name, anchorKey] of [['policy', 'policy_public_key'], ['audit', 'audit_public_key'], ['backup', 'backup_public_key']]) {
        const pub = provider.exportPublic(provider.publicFromPrivate(provider.importPrivate(keys[`${name}.key`])));
        if (!pub.equals(Buffer.from(anchor[anchorKey], 'base64')) || !pub.equals(keys[`${name}.pub`])) throw new Error(`${name} key`);
      }
      // The master KEM key must open every active version's custodian wrap.
      const master = provider.importPrivate(keys['master-kem.key']);
      for (const r of db.prepare('SELECT file_id, active_version FROM files WHERE active_version>=1').all()) {
        const fileId = ids.dec(r.file_id);
        const v = db.prepare('SELECT nonce, ciphertext FROM file_versions WHERE file_id=? AND version=?').get(r.file_id, r.active_version);
        const cust = db.prepare('SELECT wrap FROM custodian_wraps WHERE file_id=? AND version=?').get(r.file_id, r.active_version);
        const d = wrap.kemUnwrap(master, JSON.parse(cust.wrap), [fileId, r.active_version, 'cp']);
        try { provider.aeadOpen(d, Buffer.from(v.nonce), files.fileAad(fileId, r.active_version), Buffer.from(v.ciphertext)).fill(0); } finally { d.fill(0); }
      }
    } finally { db.close(); }
    return { manifest, tmp, dbFile, keys };
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    if (e instanceof RestoreError) throw e;
    throw new RestoreError('incomplete_backup');
  }
}

/**
 * §13.2. options.stopCluster / options.startCluster are called around the swap (step 7) when the
 * cluster was running; the CP start then runs recovery (§12.3).
 * @returns {Promise<{ manifest: object, quarantined: string|null, restarted: boolean }>}
 */
async function restoreBackup(home, dir, { recoveryKeyFile, anchorFile, isRunning = async () => false, stopCluster = async () => {}, startCluster = async () => {} }) {
  const L = layout(home);
  let anchor;
  try { anchor = readAnchor(anchorFile); } catch { throw new BackupError('anchor_unreadable'); }
  const v = validate(home, path.resolve(dir), { recoveryKeyFile, anchor });
  try {
    // 7. Stop → swap atomically → start (recovery runs at CP start).
    const running = await isRunning();
    if (running) await stopCluster();
    const staged = `${L.cp.db}.restore-${process.pid}`;
    fs.copyFileSync(v.dbFile, staged);
    const sdb = openDb(staged, { create: false, version: schema.VERSION, init: schema.init });
    try { sdb.prepare('PRAGMA journal_mode = WAL').get(); } finally { sdb.close(); }
    const fd = fs.openSync(staged, 'r+');
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const keyDir = path.dirname(L.cp.keys.policy.key);
    fs.mkdirSync(keyDir, { recursive: true, mode: 0o700 });
    for (const name of KEY_FILES) {
      const target = path.join(keyDir, name);
      const same = fs.existsSync(target) && fs.readFileSync(target).equals(v.keys[name]);
      if (!same) writeAtomic(target, v.keys[name], name.endsWith('.key') ? 0o600 : 0o644);
    }
    const quarantined = fs.existsSync(L.cp.db) ? quarantine(L.cp.db) : null;
    try { fs.renameSync(staged, L.cp.db); } catch (e) {
      // Put the previous registry back exactly as it was (it was renamed, never modified).
      if (quarantined) for (const s of ['', '-wal', '-shm']) if (fs.existsSync(quarantined + s)) fs.renameSync(quarantined + s, L.cp.db + s);
      throw e;
    }
    const db = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
    try {
      tx(db, () => audit.append(db, { gen: 0, kind: 'backup_restored', op: 'cp.restore', actor: 'operator', decision: 'allow', rule: 'backup_restored',
        detail: { backup_id: v.manifest.backup_id, revocation_epoch: v.manifest.revocation_epoch } }));
    } finally { db.close(); }
    if (running) await startCluster();
    return { manifest: v.manifest, quarantined, restarted: running };
  } finally {
    for (const k of Object.values(v.keys)) k.fill(0);
    fs.rmSync(v.tmp, { recursive: true, force: true });
  }
}

module.exports = { createBackup, restoreBackup, validate, seal, manifestBytes, payloadAad, readAnchor, BackupError, RestoreError, KEY_FILES, SUPPORTED_SCHEMAS };
