'use strict';
// Versioned key rotation on the control plane (features P1-04, P1-06; architecture §12; docs/plans/phase-4.md).
//
//   PREPARE ─► REWRAP ─► STAGE ─► COMMIT ─► DISTRIBUTE ─► COMPLETE
//        └────────┴────────┴──► ABORTED   (crash or missing node ack before COMMIT)
//
// Every phase is written to rotation_journal in its own transaction BEFORE the CP acts on it (§12.3);
// REWRAP and COMMIT journal rows commit atomically with the state they describe. COMMIT is one
// transaction: active version, old version → retiring, cutoff, signed snapshot E and the journal row
// (P4-D3). After COMMIT the rotation only ever rolls forward.
//
// Crash injection (§12.3, Task 4.3): KIG_CRASH_AT=<point> makes this process SIGKILL itself at that
// point, honoured only with NODE_ENV=test or KIG_CRASH_HARNESS=1 (set by `kig crash-test`).
const fs = require('node:fs');
const provider = require('../crypto/provider.cjs');
const { tx } = require('../store/db.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const wrap = require('../core/wrap.cjs');
const stageBytes = require('../core/stage.cjs');
const { call } = require('../core/http.cjs');
const { getMeta } = require('../store/schema-base.cjs');
const { ROTATION, NODE_IDS, HTTP, ROUTES, layout, kigHome, ports, url } = require('../core/contracts.cjs');
const snapshots = require('./snapshot.cjs');
const registry = require('./registry.cjs');
const files = require('./files.cjs');

class RotationError extends Error {
  constructor(code) { super(code); this.name = 'RotationError'; this.code = code; }
}

const TERMINAL = new Set(['COMPLETE', 'ABORTED']);
const ORDER = Object.fromEntries(ROTATION.phases.map((p, i) => [p, i]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const routePath = (route) => route.slice(route.indexOf(' ') + 1);
const nodeUrl = (env, id) => url(ports(env)[id]);

function crashPoint(env, point) {
  if (!env || env.KIG_CRASH_AT !== point || !ROTATION.crashPoints.includes(point)) return;
  if (env.NODE_ENV !== 'test' && env.KIG_CRASH_HARNESS !== '1') return;
  process.kill(process.pid, 'SIGKILL');
  process.exit(137); // not reached on any supported platform; never continue past a crash point
}

// ---- journal ----
function journal(db, rot, phase, { epoch = null, reason = null } = {}) {
  db.prepare('INSERT INTO rotation_journal(rotation_id,phase,file_id,from_version,to_version,epoch,reason,ts_ms) VALUES(?,?,?,?,?,?,?,?)')
    .run(rot.rotation_id, phase, ids.enc(rot.file_id), rot.from_version, rot.to_version, epoch, reason, Date.now());
}
/** All rotations, each with its phases in journal order and the last phase reached. */
function rotations(db) {
  const byId = new Map();
  for (const r of db.prepare('SELECT * FROM rotation_journal ORDER BY rowid').all()) {
    let rot = byId.get(r.rotation_id);
    if (!rot) {
      rot = { rotation_id: r.rotation_id, file_id: ids.dec(r.file_id), from_version: r.from_version, to_version: r.to_version, phases: [], epoch: null, reason: null };
      byId.set(r.rotation_id, rot);
    }
    rot.phases.push(r.phase);
    if (r.epoch !== null) rot.epoch = r.epoch;
    if (r.reason !== null) rot.reason = r.reason;
  }
  for (const rot of byId.values()) rot.last = rot.phases.reduce((a, b) => (ORDER[b] > ORDER[a] ? b : a));
  return [...byId.values()];
}
const pending = (db) => rotations(db).filter((r) => !TERMINAL.has(r.last));
const phaseSet = (db, rotationId) => new Set(db.prepare('SELECT phase FROM rotation_journal WHERE rotation_id=?').all(rotationId).map((r) => r.phase));
const summary = (rot, extra) => ({ rotation_id: rot.rotation_id, file_id: rot.file_id, from_version: rot.from_version, to_version: rot.to_version, ...extra });

// ---- helpers ----
function masterKeys(env) {
  const priv = provider.importPrivate(fs.readFileSync(layout(kigHome(env)).cp.keys.masterKem.key));
  return { priv, pub: provider.publicFromPrivate(priv) };
}
const grantAccounts = (db, fileId) => db.prepare('SELECT account FROM grants WHERE file_id=?').all(ids.enc(fileId)).map((r) => ids.dec(r.account));
function expectedDevices(db, fileId) {
  const accounts = new Set(grantAccounts(db, fileId));
  return registry.listDevices(db).filter((d) => d.status === 'active' && accounts.has(d.account)).map((d) => d.device_id).sort();
}
const envelopeDevices = (db, fileId, version) => db.prepare('SELECT device_id FROM envelopes WHERE file_id=? AND version=?')
  .all(ids.enc(fileId), version).map((r) => ids.dec(r.device_id)).sort();
const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Old versions past their CP-recorded grace become 'retired' (informational at the CP; nodes enforce on their own clocks). */
function retireExpired(db) {
  tx(db, () => {
    const now = Date.now();
    const up = db.prepare("UPDATE file_versions SET status='retired' WHERE file_id=? AND version=? AND status='retiring'");
    for (const c of db.prepare('SELECT file_id, old_version, grace_ms, committed_ms FROM file_cutoffs').all()) {
      if (now >= c.committed_ms + c.grace_ms) up.run(c.file_id, c.old_version);
    }
  });
}

// ---- phases ----
function prepare(db, fileId) {
  return tx(db, () => {
    const f = db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc(fileId));
    if (!f || f.active_version < 1) throw new RotationError('file_unknown');
    if (pending(db).some((r) => r.file_id === fileId)) throw new RotationError('rotation_in_progress');
    const highest = db.prepare('SELECT max(to_version) AS v FROM rotation_journal WHERE file_id=?').get(ids.enc(fileId)).v || 0;
    // P4-D4: never reuse a version number, not even an aborted one.
    const rot = { rotation_id: provider.random(16).toString('hex'), file_id: fileId, from_version: f.active_version, to_version: Math.max(f.active_version, highest) + 1 };
    journal(db, rot, 'PREPARE');
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.prepare', actor: 'control-plane', asset: fileId, decision: 'allow', rule: 'prepare',
      detail: { rotation_id: rot.rotation_id, from_version: rot.from_version, to_version: rot.to_version } });
    return rot;
  });
}

/** New DEK, re-encrypted file, custodian wrap and envelopes, persisted with the REWRAP journal row. */
function rewrap(db, rot, env) {
  const enc = ids.enc(rot.file_id);
  const old = db.prepare('SELECT nonce, ciphertext FROM file_versions WHERE file_id=? AND version=?').get(enc, rot.from_version);
  const cust = db.prepare('SELECT wrap FROM custodian_wraps WHERE file_id=? AND version=?').get(enc, rot.from_version);
  if (!old || !cust) throw new RotationError('version_unreadable');
  const master = masterKeys(env);
  let oldDek, newDek, plaintext;
  try {
    try {
      oldDek = wrap.kemUnwrap(master.priv, JSON.parse(cust.wrap), [rot.file_id, rot.from_version, 'cp']);
      plaintext = provider.aeadOpen(oldDek, Buffer.from(old.nonce), files.fileAad(rot.file_id, rot.from_version), Buffer.from(old.ciphertext));
    } catch { throw new RotationError('version_unreadable'); }
    if (plaintext.length > ROTATION.maxFileBytes) throw new RotationError('file_too_large');
    newDek = provider.random(32);
    const nonce = provider.random(12);
    const ciphertext = provider.aeadSeal(newDek, nonce, files.fileAad(rot.file_id, rot.to_version), plaintext);
    const custodian = wrap.serialize(wrap.kemWrap(master.pub, newDek, [rot.file_id, rot.to_version, 'cp']));
    const accounts = grantAccounts(db, rot.file_id);
    tx(db, () => {
      journal(db, rot, 'REWRAP');
      db.prepare("INSERT INTO file_versions(file_id,version,nonce,ciphertext,status,created_ms) VALUES(?,?,?,?,'staged',?)").run(enc, rot.to_version, nonce, ciphertext, Date.now());
      db.prepare('INSERT INTO custodian_wraps(file_id,version,wrap) VALUES(?,?,?)').run(enc, rot.to_version, JSON.stringify(custodian));
      files.makeEnvelopes(db, rot.file_id, rot.to_version, newDek, accounts);
    });
  } finally { oldDek?.fill(0); newDek?.fill(0); plaintext?.fill(0); }
}

function stageMessage(db, rot, policyPriv) {
  const enc = ids.enc(rot.file_id);
  const v = db.prepare('SELECT nonce, ciphertext FROM file_versions WHERE file_id=? AND version=?').get(enc, rot.to_version);
  if (!v) throw new RotationError('stage_missing');
  const envelopes = db.prepare('SELECT device_id, envelope FROM envelopes WHERE file_id=? AND version=?').all(enc, rot.to_version)
    .map((r) => ({ device_id: ids.dec(r.device_id), envelope: r.envelope })).sort(stageBytes.byDevice);
  const nonce = Buffer.from(v.nonce);
  const ciphertext = Buffer.from(v.ciphertext);
  const digest = stageBytes.digest(rot.file_id, rot.to_version, nonce, ciphertext, envelopes);
  const sig = provider.sign(policyPriv, ROTATION.context, stageBytes.signedBytes('stage', rot.rotation_id, rot.file_id, rot.to_version, digest));
  return {
    digest,
    body: { op: 'stage', rotation_id: rot.rotation_id, file_id: rot.file_id, version: rot.to_version,
      nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64'), envelopes, sig: sig.toString('base64') },
  };
}

function nodePublic(env, id) {
  try { return provider.importPublic(fs.readFileSync(layout(kigHome(env)).node(id).key.pub)); } catch { return null; }
}
function validAck(env, id, op, rot, digest, ack) {
  const pub = nodePublic(env, id);
  return !!pub && !!ack && ack.node_id === id && typeof ack.sig === 'string' &&
    provider.verify(pub, ROTATION.context, stageBytes.ackBytes(id, op, rot.rotation_id, rot.file_id, rot.to_version, digest), Buffer.from(ack.sig, 'base64'));
}

/** Push the staged version to every node; returns the nodes that did NOT return a valid signed ack. */
async function stageAll(db, rot, env, policyPriv) {
  const { body, digest } = stageMessage(db, rot, policyPriv);
  if (Buffer.byteLength(JSON.stringify(body)) > HTTP.maxBodyBytes) return { missing: [...NODE_IDS], reason: 'stage_too_large' };
  const results = await Promise.all(NODE_IDS.map(async (id) => {
    try {
      const r = await call(`${nodeUrl(env, id)}${routePath(ROUTES.node.stage)}`, 'POST', body, { timeoutMs: ROTATION.stageTimeoutMs });
      if (r.status === 200 && r.json.staged === true && validAck(env, id, 'stage', rot, digest, r.json.ack)) return [id, Buffer.from(r.json.ack.sig, 'base64')];
    } catch { /* unreachable node: no ack */ }
    return [id, null];
  }));
  const acked = results.filter(([, sig]) => sig);
  tx(db, () => {
    const put = db.prepare('INSERT OR REPLACE INTO rotation_stage_acks(rotation_id,node_id,digest,sig,acked_ms) VALUES(?,?,?,?,?)');
    for (const [id, sig] of acked) put.run(rot.rotation_id, id, digest, sig, Date.now());
  });
  return { missing: results.filter(([, sig]) => !sig).map(([id]) => id), reason: 'missing_stage_ack' };
}

/** Best effort: ask every node to delete a never-active version. Nodes refuse to drop an active one. */
async function dropAll(rot, env) {
  let policyPriv;
  try { policyPriv = snapshots.policyKey(env); } catch { return; }
  const body = { op: 'drop', rotation_id: rot.rotation_id, file_id: rot.file_id, version: rot.to_version };
  body.sig = provider.sign(policyPriv, ROTATION.context, stageBytes.signedBytes('drop', rot.rotation_id, rot.file_id, rot.to_version, Buffer.alloc(0))).toString('base64');
  await Promise.all(NODE_IDS.map((id) => call(`${nodeUrl(env, id)}${routePath(ROUTES.node.stageDrop)}`, 'POST', body, { timeoutMs: ROTATION.stageTimeoutMs }).catch(() => null)));
}

/** Discard v+1 at the CP (never after COMMIT) and tell the nodes to drop it. Idempotent. */
async function abort(db, rot, reason, env) {
  const changed = tx(db, () => {
    const phases = phaseSet(db, rot.rotation_id);
    if (phases.has('COMPLETE') || phases.has('ABORTED')) return false;
    if (phases.has('COMMIT')) throw new RotationError('already_committed');
    const enc = ids.enc(rot.file_id);
    db.prepare('DELETE FROM envelopes WHERE file_id=? AND version=?').run(enc, rot.to_version);
    db.prepare('DELETE FROM custodian_wraps WHERE file_id=? AND version=?').run(enc, rot.to_version);
    db.prepare("DELETE FROM file_versions WHERE file_id=? AND version=? AND status='staged'").run(enc, rot.to_version);
    journal(db, rot, 'ABORTED', { reason });
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.abort', actor: 'control-plane', asset: rot.file_id, decision: 'deny', rule: 'aborted',
      detail: { rotation_id: rot.rotation_id, from_version: rot.from_version, to_version: rot.to_version, reason } });
    return true;
  });
  await dropAll(rot, env);
  return changed;
}

/** The durable commit (P4-D3). Throws RotationError if anything changed since staging. */
function commit(db, rot, graceMs, policyPriv) {
  return tx(db, () => {
    const phases = phaseSet(db, rot.rotation_id);
    if (phases.has('ABORTED')) throw new RotationError('aborted');
    const enc = ids.enc(rot.file_id);
    const f = db.prepare('SELECT active_version FROM files WHERE file_id=?').get(enc);
    if (!f || f.active_version !== rot.from_version) throw new RotationError('concurrent_change');
    const v = db.prepare('SELECT status FROM file_versions WHERE file_id=? AND version=?').get(enc, rot.to_version);
    if (!v || v.status !== 'staged') throw new RotationError('stage_missing');
    // P4-D11: the staged envelopes must be exactly the active devices of the granted accounts, now.
    if (!sameList(envelopeDevices(db, rot.file_id, rot.to_version), expectedDevices(db, rot.file_id))) throw new RotationError('device_set_changed');
    const acked = db.prepare('SELECT node_id FROM rotation_stage_acks WHERE rotation_id=?').all(rot.rotation_id).map((r) => r.node_id);
    if (!NODE_IDS.every((id) => acked.includes(id))) throw new RotationError('missing_stage_ack');
    db.prepare("UPDATE file_versions SET status='retired' WHERE file_id=? AND status='retiring'").run(enc);
    db.prepare("UPDATE file_versions SET status='retiring' WHERE file_id=? AND version=? AND status='active'").run(enc, rot.from_version);
    db.prepare("UPDATE file_versions SET status='active' WHERE file_id=? AND version=?").run(enc, rot.to_version);
    db.prepare('UPDATE files SET active_version=? WHERE file_id=?').run(rot.to_version, enc);
    const epoch = Number(getMeta(db, 'epoch')) + 1;
    db.prepare(`INSERT INTO file_cutoffs(file_id,old_version,from_epoch,grace_ms,committed_ms) VALUES(?,?,?,?,?)
      ON CONFLICT(file_id) DO UPDATE SET old_version=excluded.old_version, from_epoch=excluded.from_epoch, grace_ms=excluded.grace_ms, committed_ms=excluded.committed_ms`)
      .run(enc, rot.from_version, epoch, graceMs, Date.now());
    const signed = snapshots.commitInTx(db, policyPriv);
    if (signed.snapshot.epoch !== epoch) throw new Error('epoch mismatch at commit');
    journal(db, rot, 'COMMIT', { epoch });
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.commit', actor: 'control-plane', asset: rot.file_id, decision: 'allow', rule: 'committed',
      detail: { rotation_id: rot.rotation_id, from_version: rot.from_version, to_version: rot.to_version, epoch, grace_ms: graceMs } });
    return epoch;
  });
}

/** Wait until every node has acknowledged an epoch ≥ epoch; returns the nodes still behind. */
async function waitAcks(db, epoch, timeoutMs) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const acked = snapshots.ackedEpochs(db);
    const behind = NODE_IDS.filter((id) => acked[id] < epoch);
    if (!behind.length || Date.now() >= end) return behind;
    await sleep(20);
  }
}

/** DISTRIBUTE → COMPLETE. Also the roll-forward path of recovery. */
async function finish(db, rot, epoch, env, { timeoutMs = ROTATION.distributeTimeoutMs } = {}) {
  tx(db, () => { if (!phaseSet(db, rot.rotation_id).has('DISTRIBUTE')) journal(db, rot, 'DISTRIBUTE', { epoch }); });
  const signed = snapshots.latest(db); // epoch ≥ E: nodes accept anything newer than what they hold
  for (const [i, id] of NODE_IDS.entries()) {
    try { await snapshots.pushTo(id, signed, env, { timeoutMs: ROTATION.stageTimeoutMs }); } catch { /* the node's pull loop converges */ }
    if (i === 0) crashPoint(env, 'during_distribute');
  }
  const behind = await waitAcks(db, epoch, timeoutMs);
  if (behind.length) return summary(rot, { status: 'committed', epoch, pending_nodes: behind });
  tx(db, () => {
    if (phaseSet(db, rot.rotation_id).has('COMPLETE')) return;
    journal(db, rot, 'COMPLETE', { epoch });
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.complete', actor: 'control-plane', asset: rot.file_id, decision: 'allow', rule: 'complete',
      detail: { rotation_id: rot.rotation_id, to_version: rot.to_version, epoch } });
  });
  return summary(rot, { status: 'complete', epoch });
}

/**
 * Rotate one file v → v+1. Resolves to { status: 'complete' | 'committed' | 'aborted', ... }.
 * Throws RotationError('file_unknown' | 'rotation_in_progress' | 'invalid_grace') before anything is journalled.
 */
async function rotate(db, fileId, { env = process.env, graceMs = ROTATION.graceMs } = {}) {
  if (!ids.isId(fileId)) throw new RotationError('file_unknown');
  if (!Number.isSafeInteger(graceMs) || graceMs < 1 || graceMs > ROTATION.maxGraceMs) throw new RotationError('invalid_grace');
  retireExpired(db);
  const rot = prepare(db, fileId);
  crashPoint(env, 'after_prepare');
  try { rewrap(db, rot, env); } catch (e) {
    const reason = e instanceof RotationError ? e.code : 'rewrap_failed';
    await abort(db, rot, reason, env);
    return summary(rot, { status: 'aborted', reason });
  }
  tx(db, () => journal(db, rot, 'STAGE'));
  const policyPriv = snapshots.policyKey(env);
  const staged = await stageAll(db, rot, env, policyPriv);
  if (staged.missing.length) {
    await abort(db, rot, staged.reason, env);
    return summary(rot, { status: 'aborted', reason: staged.reason, nodes: staged.missing });
  }
  crashPoint(env, 'after_stage');
  crashPoint(env, 'before_commit');
  let epoch;
  try { epoch = commit(db, rot, graceMs, policyPriv); } catch (e) {
    if (!(e instanceof RotationError)) throw e;
    await abort(db, rot, e.code, env);
    return summary(rot, { status: 'aborted', reason: e.code });
  }
  crashPoint(env, 'after_commit');
  return finish(db, rot, epoch, env);
}

module.exports = { rotate, abort, finish, pending, rotations, retireExpired, crashPoint, RotationError };
