'use strict';
// Node side of rotation (architecture §12.1, §12.2; docs/plans/phase-4.md P4-D2, P4-D5–P4-D8).
//
// stage / drop: CP-signed (policy key, ctx kig/v1/revocation) messages that store or remove a NOT YET
//   ACTIVE file version. The node answers with an ack signed by its node key over the same content
//   digest, so the CP knows exactly what each node holds before it commits.
// start: an authenticated device request (op 'file.transfer', §8.2) for the ACTIVE version opens a
//   chunked transfer bound to that version on this node.
// chunk: a transfer may keep fetching chunks of its version while it is active, or — if the version
//   was cut off after the transfer started — until this node's cutoff time + grace (node-local
//   monotonic clock, D-06). Anything else terminates the transfer.
const { tx } = require('../store/db.cjs');
const stageBytes = require('../core/stage.cjs');
const ids = require('../core/ids.cjs');
const audit = require('../core/audit.cjs');
const provider = require('../crypto/provider.cjs');
const { ROTATION, RULES } = require('../core/contracts.cjs');
const auth = require('./auth.cjs');
const policy = require('./policy.cjs');
const { ensurePhase4 } = require('../store/schema-node.cjs');

const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const isB64 = (v) => typeof v === 'string' && B64.test(v);
const isVersion = (v) => Number.isSafeInteger(v) && v >= 1;
const mono = () => process.hrtime.bigint();


function activeVersion(db, fileId) {
  const snap = policy.current(db).snapshot;
  const f = snap && snap.files.find((x) => x.file_id === fileId);
  return f ? f.active_version : 0;
}

function verifyCp(cpPub, op, body, digest) {
  try {
    return provider.verify(typeof cpPub.export === 'function' ? cpPub : provider.importPublic(cpPub), ROTATION.context,
      stageBytes.signedBytes(op, body.rotation_id, body.file_id, body.version, digest), Buffer.from(body.sig, 'base64'));
  } catch { return false; }
}

function sign(nodeKey, nodeId, op, body, digest) {
  return { node_id: nodeId, sig: provider.sign(nodeKey, ROTATION.context, stageBytes.ackBytes(nodeId, op, body.rotation_id, body.file_id, body.version, digest)).toString('base64') };
}

const malformed = { status: 400, json: { error: 'bad_request' } };

/** POST /v1/stage */
function stage(db, body, { nodeId, nodeKey, cpPub, partitioned }) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.op !== 'stage' || typeof body.rotation_id !== 'string' ||
      !/^[0-9a-f]{32}$/.test(body.rotation_id) || typeof body.file_id !== 'string' || !isVersion(body.version) ||
      !isB64(body.nonce) || !isB64(body.ciphertext) || !isB64(body.sig) || !Array.isArray(body.envelopes) ||
      !body.envelopes.every((e) => e && typeof e.device_id === 'string' && typeof e.envelope === 'string') ||
      new Set(body.envelopes.map((e) => e.device_id)).size !== body.envelopes.length) return malformed;
  if (partitioned) return { status: 200, json: { staged: false, reason: 'partitioned' } };
  const nonce = Buffer.from(body.nonce, 'base64');
  const ciphertext = Buffer.from(body.ciphertext, 'base64');
  if (nonce.length !== 12 || ciphertext.length < 16) return malformed;
  const digest = stageBytes.digest(body.file_id, body.version, nonce, ciphertext, body.envelopes);
  if (!verifyCp(cpPub, 'stage', body, digest)) return { status: 200, json: { staged: false, reason: 'bad_signature' } };
  if (body.version <= activeVersion(db, body.file_id)) return { status: 200, json: { staged: false, reason: 'not_newer' } };
  const file = ids.enc(body.file_id);
  tx(db, () => {
    db.prepare('INSERT OR REPLACE INTO ciphertexts(file_id,version,nonce,ciphertext) VALUES(?,?,?,?)').run(file, body.version, nonce, ciphertext);
    db.prepare('DELETE FROM node_envelopes WHERE file_id=? AND version=?').run(file, body.version);
    const put = db.prepare('INSERT INTO node_envelopes(file_id,version,device_id,envelope) VALUES(?,?,?,?)');
    for (const e of body.envelopes) put.run(file, body.version, ids.enc(e.device_id), e.envelope);
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.stage', actor: 'control-plane', asset: body.file_id,
      decision: 'allow', rule: 'staged', detail: { rotation_id: body.rotation_id, version: body.version } });
  });
  return { status: 200, json: { staged: true, digest: digest.toString('hex'), ack: sign(nodeKey, nodeId, 'stage', body, digest) } };
}

/** POST /v1/stage/drop — remove an aborted, never-active version. */
function drop(db, body, { nodeId, nodeKey, cpPub, partitioned }) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || body.op !== 'drop' || typeof body.rotation_id !== 'string' ||
      !/^[0-9a-f]{32}$/.test(body.rotation_id) || typeof body.file_id !== 'string' || !isVersion(body.version) || !isB64(body.sig)) return malformed;
  if (partitioned) return { status: 200, json: { dropped: false, reason: 'partitioned' } };
  const digest = Buffer.alloc(0);
  if (!verifyCp(cpPub, 'drop', body, digest)) return { status: 200, json: { dropped: false, reason: 'bad_signature' } };
  if (body.version <= activeVersion(db, body.file_id)) return { status: 200, json: { dropped: false, reason: 'active_version' } };
  const file = ids.enc(body.file_id);
  tx(db, () => {
    db.prepare('DELETE FROM node_envelopes WHERE file_id=? AND version=?').run(file, body.version);
    db.prepare('DELETE FROM ciphertexts WHERE file_id=? AND version=?').run(file, body.version);
    audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.drop', actor: 'control-plane', asset: body.file_id,
      decision: 'allow', rule: 'dropped', detail: { rotation_id: body.rotation_id, version: body.version } });
  });
  return { status: 200, json: { dropped: true, ack: sign(nodeKey, nodeId, 'drop', body, digest) } };
}

/** POST /v1/transfer/start — body is a signed device request (§8.2) with op 'file.transfer'. */
function start(db, req) {
  ensurePhase4(db);
  const result = auth.authenticate(db, req);
  if (!result.ok) return { decision: 'deny', rule: result.rule };
  const snap = policy.current(db).snapshot;
  if (!snap) return { decision: 'deny', rule: RULES.leaseExpired };
  if (!(snap.grants || []).some((g) => g.file_id === req.resource && g.account === result.device.account)) return { decision: 'deny', rule: RULES.notGranted };
  const file = ids.enc(req.resource);
  const row = db.prepare('SELECT c.nonce, c.ciphertext, e.envelope FROM ciphertexts c JOIN node_envelopes e ON e.file_id=c.file_id AND e.version=c.version WHERE c.file_id=? AND c.version=? AND e.device_id=?')
    .get(file, req.key_version, ids.enc(req.device_id));
  if (!row) return { decision: 'deny', rule: 'unknown_file' };
  const total = Buffer.from(row.ciphertext).length;
  const chunkCount = Math.max(1, Math.ceil(total / ROTATION.chunkBytes));
  const transferId = provider.random(32).toString('hex');
  tx(db, () => db.prepare("INSERT INTO transfers(transfer_id,file_id,version,device_id,account,created_mono_ns,created_ms,chunk_count,total_bytes,state) VALUES(?,?,?,?,?,?,?,?,?,'open')")
    .run(transferId, file, req.key_version, ids.enc(req.device_id), ids.enc(result.device.account), mono().toString(), Date.now(), chunkCount, total));
  return {
    decision: 'allow', rule: RULES.allowed, transfer_id: transferId, file_id: req.resource, version: req.key_version,
    account: result.device.account, nonce: Buffer.from(row.nonce).toString('base64'), envelope: JSON.parse(row.envelope),
    chunk_count: chunkCount, chunk_bytes: ROTATION.chunkBytes, total_bytes: total,
  };
}

function terminate(db, t, reason) {
  tx(db, () => {
    const changed = db.prepare("UPDATE transfers SET state='terminated', reason=? WHERE transfer_id=? AND state='open'").run(reason, t.transfer_id);
    if (Number(changed.changes) === 1) {
      audit.append(db, { gen: 0, kind: 'access', op: 'file.transfer.chunk', actor: ids.dec(t.device_id), asset: ids.dec(t.file_id),
        decision: 'deny', rule: reason, detail: { version: t.version } });
    }
  });
  return { decision: 'deny', rule: reason };
}

/** POST /v1/transfer/chunk {transfer_id, index} */
function chunk(db, body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.transfer_id !== 'string' ||
      !/^[0-9a-f]{64}$/.test(body.transfer_id) || !Number.isSafeInteger(body.index) || body.index < 0) return null;
  ensurePhase4(db);
  const t = db.prepare('SELECT * FROM transfers WHERE transfer_id=?').get(body.transfer_id);
  if (!t) return { decision: 'deny', rule: RULES.transferUnknown };
  if (t.state !== 'open') return { decision: 'deny', rule: RULES.transferTerminated, reason: t.reason };
  if (body.index >= t.chunk_count) return null;
  const now = mono();
  if (now - BigInt(t.created_mono_ns) > BigInt(ROTATION.transferTtlMs) * 1_000_000n) return terminate(db, t, RULES.transferExpired);
  const state = policy.current(db);
  if (!state.lease_valid) return { decision: 'deny', rule: RULES.leaseExpired }; // transient: the transfer stays open
  const fileId = ids.dec(t.file_id);
  const deviceId = ids.dec(t.device_id);
  const device = state.snapshot.devices.find((d) => d.device_id === deviceId);
  if (!device || device.status !== 'active') return terminate(db, t, RULES.deviceRevoked);
  const file = state.snapshot.files.find((f) => f.file_id === fileId);
  let rule = RULES.allowed;
  if (!file || file.active_version !== t.version) {
    const cut = db.prepare('SELECT grace_ms, applied_mono_ns FROM cutoffs WHERE file_id=? AND old_version=?').get(t.file_id, t.version);
    // Only a transfer authenticated BEFORE this node applied the cutoff may continue (D-06).
    if (!cut || BigInt(t.created_mono_ns) >= BigInt(cut.applied_mono_ns)) return terminate(db, t, RULES.oldKeyVersion);
    if (now >= BigInt(cut.applied_mono_ns) + BigInt(cut.grace_ms) * 1_000_000n) return terminate(db, t, RULES.graceExpired);
    rule = 'grace';
  }
  const row = db.prepare('SELECT ciphertext FROM ciphertexts WHERE file_id=? AND version=?').get(t.file_id, t.version);
  if (!row) return terminate(db, t, rule === 'grace' ? RULES.graceExpired : 'unknown_file');
  const ct = Buffer.from(row.ciphertext);
  const data = ct.subarray(body.index * ROTATION.chunkBytes, (body.index + 1) * ROTATION.chunkBytes);
  if (rule === 'grace') {
    tx(db, () => audit.append(db, { gen: 0, kind: 'access', op: 'file.transfer.chunk', actor: deviceId, asset: fileId,
      decision: 'allow', rule: 'grace', detail: { version: t.version, index: body.index } }));
  }
  return { decision: 'allow', rule, index: body.index, chunk_count: t.chunk_count, data: data.toString('base64') };
}

/** Delete ciphertext and envelopes of versions whose grace has ended on this node; end their transfers. */
function purgeRetired(db) {
  ensurePhase4(db);
  const now = mono();
  const snap = policy.current(db).snapshot;
  for (const c of db.prepare('SELECT file_id, old_version, grace_ms, applied_mono_ns FROM cutoffs').all()) {
    if (now < BigInt(c.applied_mono_ns) + BigInt(c.grace_ms) * 1_000_000n) continue;
    const f = snap && snap.files.find((x) => x.file_id === ids.dec(c.file_id));
    if (!f || f.active_version === c.old_version) continue; // never touch an active version
    const has = db.prepare('SELECT 1 FROM ciphertexts WHERE file_id=? AND version=?').get(c.file_id, c.old_version);
    const open = db.prepare("SELECT 1 FROM transfers WHERE file_id=? AND version=? AND state='open'").get(c.file_id, c.old_version);
    if (!has && !open) continue;
    tx(db, () => {
      db.prepare("UPDATE transfers SET state='terminated', reason=? WHERE file_id=? AND version=? AND state='open'").run(RULES.graceExpired, c.file_id, c.old_version);
      db.prepare('DELETE FROM node_envelopes WHERE file_id=? AND version=?').run(c.file_id, c.old_version);
      db.prepare('DELETE FROM ciphertexts WHERE file_id=? AND version=?').run(c.file_id, c.old_version);
      audit.append(db, { gen: 0, kind: 'rotation', op: 'rotation.retire', actor: 'node', asset: ids.dec(c.file_id),
        decision: 'allow', rule: 'retired', detail: { version: c.old_version } });
    });
  }
}

module.exports = { stage, drop, start, chunk, purgeRetired };
