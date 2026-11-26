'use strict';
// Control-plane recovery after a crash (features P1-06; architecture §12.3).
//
//   last durable phase          action
//   PREPARE, REWRAP or STAGE    abort: discard v+1 at the CP, tell nodes to drop it, v stays active
//   COMMIT or DISTRIBUTE        roll forward: re-push the committed snapshot until every node acks, COMPLETE
//   COMPLETE / ABORTED          nothing
//
// Recovery never writes the epoch (an abort publishes nothing; roll-forward re-pushes the existing
// signed snapshot) and never touches device status, so it cannot lower the epoch or re-activate a
// revoked device. Afterwards every active file version is test-decrypted through its custodian wrap.
const fs = require('node:fs');
const provider = require('../crypto/provider.cjs');
const { tx } = require('../store/db.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const wrap = require('../core/wrap.cjs');
const { layout, kigHome } = require('../core/contracts.cjs');
const rotation = require('./rotate.cjs');
const files = require('./files.cjs');
const alerts = require('./alerts.cjs');

const BEFORE_COMMIT = new Set(['PREPARE', 'REWRAP', 'STAGE']);

/** Decrypt every active version through the custodian wrap; returns the file IDs that fail. */
function verifyActiveVersions(db, env) {
  const rows = db.prepare('SELECT file_id, active_version FROM files WHERE active_version>=1 ORDER BY file_id').all();
  if (!rows.length) return { verified: 0, unreadable: [] };
  let master = null;
  try { master = provider.importPrivate(fs.readFileSync(layout(kigHome(env)).cp.keys.masterKem.key)); } catch { /* every file is reported unreadable */ }
  const unreadable = [];
  for (const r of rows) {
    const fileId = ids.dec(r.file_id);
    let dek, plain;
    try {
      const v = db.prepare('SELECT nonce, ciphertext FROM file_versions WHERE file_id=? AND version=?').get(r.file_id, r.active_version);
      const cust = db.prepare('SELECT wrap FROM custodian_wraps WHERE file_id=? AND version=?').get(r.file_id, r.active_version);
      if (!master || !v || !cust) throw new Error('missing');
      dek = wrap.kemUnwrap(master, JSON.parse(cust.wrap), [fileId, r.active_version, 'cp']);
      plain = provider.aeadOpen(dek, Buffer.from(v.nonce), files.fileAad(fileId, r.active_version), Buffer.from(v.ciphertext));
    } catch { unreadable.push(fileId); } finally { dek?.fill(0); plain?.fill(0); }
  }
  return { verified: rows.length - unreadable.length, unreadable };
}

/**
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {{ env?: object, rotationIds?: Set<string>|null, distributeTimeoutMs?: number }} [o]
 *   rotationIds: only these rotations (the CP captures the set pending at startup, so a live
 *   rotation started after startup is never treated as crashed).
 * @returns {Promise<{ action: 'none'|'abort'|'roll_forward', rotations: object[], verified: number, unreadable: string[] }>}
 */
async function recover(db, { env = process.env, rotationIds = null, distributeTimeoutMs } = {}) {
  rotation.retireExpired(db);
  const out = [];
  for (const rot of rotation.pending(db)) {
    if (rotationIds && !rotationIds.has(rot.rotation_id)) continue;
    const base = { rotation_id: rot.rotation_id, file_id: rot.file_id, from_version: rot.from_version, to_version: rot.to_version, last_phase: rot.last };
    if (BEFORE_COMMIT.has(rot.last)) {
      await rotation.abort(db, rot, 'recovered_before_commit', env);
      out.push({ ...base, action: 'abort', status: 'aborted' });
    } else {
      const r = await rotation.finish(db, rot, rot.epoch, env, distributeTimeoutMs ? { timeoutMs: distributeTimeoutMs } : {});
      out.push({ ...base, action: 'roll_forward', status: r.status, epoch: rot.epoch, ...(r.pending_nodes ? { pending_nodes: r.pending_nodes } : {}) });
    }
  }
  const action = out.some((r) => r.action === 'roll_forward') ? 'roll_forward' : out.length ? 'abort' : 'none';
  const check = verifyActiveVersions(db, env);
  for (const fileId of check.unreadable) alerts.recordUnreadableVersion(db, fileId);
  tx(db, () => audit.append(db, { gen: 0, kind: 'recovery', op: 'cp.recover', actor: 'control-plane', decision: check.unreadable.length ? 'deny' : 'allow',
    rule: check.unreadable.length ? 'recovery_unreadable' : 'recovery_verified',
    detail: { action, rotations: out.length, files_verified: check.verified, files_unreadable: check.unreadable.length } }));
  return { action, rotations: out, verified: check.verified, unreadable: check.unreadable };
}

module.exports = { recover, verifyActiveVersions };
