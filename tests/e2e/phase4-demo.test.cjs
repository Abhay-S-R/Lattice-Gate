'use strict';
// Gate 4: architecture §17.2 demo steps 4–8 as one scripted run on a live CP + nodes A/B/C,
// with the real 30 s grace window, plus node anti-rollback (Task 4.5) on the same cluster.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { NODE_IDS, ROTATION, layout } = require('../../src/core/contracts.cjs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const client = require('../../src/device/client.cjs');
const deviceFiles = require('../../src/device/files.cjs');
const keystore = require('../../src/device/keystore.cjs');
const wrap = require('../../src/core/wrap.cjs');
const provider = require('../../src/crypto/provider.cjs');
const { encode } = require('../../src/core/encoding.cjs');
const ids = require('../../src/core/ids.cjs');
const { openReadOnly } = require('../../src/store/db.cjs');
const nodePolicy = require('../../src/node/policy.cjs');
const supervisor = require('../../src/cli/supervisor.cjs');

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, what, ms = 10000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() >= end) throw new Error(`timed out: ${what}`); await pause(40); }
}

test('Gate 4: demo steps 4-8 (rotation in flight, lost device, re-enrol, CP crash, backup) and node anti-rollback', { timeout: 300000 }, async (t) => {
  const home = freshHome();
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-gate4-'));
  let cluster;
  t.after(async () => {
    try { if (cluster) await cluster.stop(); } catch { /* best effort */ }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  });
  cluster = await startCluster(home);
  const port = String(new URL(cluster.cpUrl).port);
  const kenv = { KIG_HOME: home, KIG_PORT_BASE: port };
  const env = { ...process.env, ...kenv };
  const run = (args) => runKig(args, { env: kenv, timeoutMs: 120000 });
  const ok = (args) => { const r = run(args); assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr || r.stdout}`); return r; };
  const L = layout(home);
  let seq = 0;
  const req = (node, device, account, op, v) => client.request(cluster.nodeUrls[node], L.device(device).dir, op,
    { home, version: 1, op, account, device_id: device, resource: 'brief', request_id: `g4-${++seq}`, key_version: v });
  const chunk = (node, id, i) => client.transferChunk(cluster.nodeUrls[node], id, i);
  const read = async (node, device, account, v) => {
    const r = await until(async () => { const x = await req(node, device, account, 'file.read', v); return x.decision === 'allow' ? x : null; }, `${device} reads v${v} via ${node}`);
    return deviceFiles.read(home, device, r);
  };
  const cpQuery = (fn) => { const db = openReadOnly(L.cp.db); try { return fn(db); } finally { db.close(); } };
  const cpEpoch = () => cpQuery((db) => Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v));
  const nodeState = (id) => { const db = openReadOnly(L.node(id).db); try { return nodePolicy.current(db); } finally { db.close(); } };

  // Steps 1–3 (Phase 3): enrol, publish, share.
  const plaintext = Buffer.from(provider.random(20000).toString('hex')); // 3 chunks
  const input = path.join(work, 'brief.txt');
  fs.writeFileSync(input, plaintext);
  ok(['account', 'add', 'alice']);
  ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'g4-alice-first']);
  ok(['device', 'enrol', 'alice-laptop', '--account', 'alice']);
  ok(['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'g4-laptop']);
  ok(['account', 'add', 'bob']);
  ok(['device', 'enrol', 'bob-laptop', '--account', 'bob']);
  ok(['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'g4-bob-first']);
  ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  ok(['share', 'brief', '--with', 'bob']);
  for (const id of NODE_IDS) assert.ok((await read(id, 'bob-laptop', 'bob', 1)).equals(plaintext));
  const phoneV1 = await req('A', 'alice-phone', 'alice', 'file.read', 1);
  assert.equal(phoneV1.decision, 'allow');
  const oldBackup = path.join(work, 'backup-old');
  ok(['backup', '--out', oldBackup]);
  // A copy of node A's store while alice-phone is still active (for the anti-rollback check at the end).
  const nodeACopy = path.join(work, 'node-A-old.db');
  { const db = openReadOnly(L.node('A').db); try { db.exec(`VACUUM INTO '${nodeACopy.replace(/'/g, "''")}'`); } finally { db.close(); } }

  // ---- Step 4 (Goal 1): rotate while a transfer is in flight ----
  const inflight = await req('A', 'bob-laptop', 'bob', 'file.transfer', 1);
  assert.equal(inflight.decision, 'allow');
  assert.equal(inflight.chunk_count, 3);
  const parts = [await chunk('A', inflight.transfer_id, 0)];
  const rotated = ok(['rotate', '--file', 'brief']);
  const cutoffAt = Date.now();
  assert.match(rotated.stdout, /^ROTATED "brief" 1 -> 2 epoch=\d+ \(complete/);
  for (const i of [1, 2]) { const c = await chunk('A', inflight.transfer_id, i); assert.equal(c.rule, 'grace'); parts.push(c); }
  assert.ok(deviceFiles.readTransfer(home, 'bob-laptop', inflight, parts).equals(plaintext), 'in-flight transfer finishes within grace');
  for (const id of NODE_IDS) {
    assert.equal((await req(id, 'bob-laptop', 'bob', 'file.transfer', 1)).rule, 'old_key_version', `new old-version transfer on ${id}`);
    assert.equal((await req(id, 'bob-laptop', 'bob', 'file.read', 1)).rule, 'old_key_version', `new old-version read on ${id}`);
    assert.ok((await read(id, 'bob-laptop', 'bob', 2)).equals(plaintext));
    const cut = nodeState(id).snapshot.files.find((f) => f.file_id === 'brief').cutoff;
    assert.deepEqual([cut.old_version, cut.grace_ms], [1, ROTATION.graceMs]);
  }
  assert.ok(Date.now() - cutoffAt < ROTATION.graceMs, 'step 4 checks ran inside the grace window');

  // ---- Step 5 (Goal 2): alice-phone reported lost ----
  const lost = ok(['lost', '--device', 'alice-phone']);
  assert.match(lost.stdout, /^LOST "alice-phone": revoked at epoch \d+; signed node acks after A [\d.]+ ms, B [\d.]+ ms, C [\d.]+ ms/);
  assert.match(lost.stdout, /ROTATED "brief" 2 -> 3 epoch=\d+ \(complete/);
  for (const id of NODE_IDS) assert.equal((await req(id, 'alice-phone', 'alice', 'file.read', 3)).rule, 'device_revoked', `lost phone on ${id}`);

  // ---- Step 6 (Goal 2): replacement enrols with a second factor; peer keeps access; old envelope useless ----
  ok(['device', 'enrol', 'alice-phone-2', '--account', 'alice']);
  for (const id of NODE_IDS) assert.equal((await req(id, 'alice-phone-2', 'alice', 'file.read', 3)).rule, 'unknown_device');
  const refusedApproval = run(['device', 'approve', 'alice-phone-2', '--by', 'alice-phone', '--approval-id', 'g4-by-lost']);
  assert.equal(refusedApproval.code, 1);
  assert.match(refusedApproval.stderr, /approver_not_active/);
  assert.match(ok(['device', 'approve', 'alice-phone-2', '--by', 'alice-laptop', '--approval-id', 'g4-phone-2']).stdout, /PROVISIONED alice-phone-2: "brief" v3/);
  for (const id of NODE_IDS) {
    assert.ok((await read(id, 'alice-phone-2', 'alice', 3)).equals(plaintext), `replacement via ${id}`);
    assert.ok((await read(id, 'bob-laptop', 'bob', 3)).equals(plaintext), `Bob via ${id}`);
  }
  const bobV3 = await req('C', 'bob-laptop', 'bob', 'file.read', 3);
  const oldDek = wrap.kemUnwrap(keystore.load(home, 'alice-phone').kemPrivate, phoneV1.envelope, ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope']);
  assert.throws(() => provider.aeadOpen(oldDek, Buffer.from(bobV3.nonce, 'base64'), encode('kig/v1/file-aad', ['brief', 3, 'kig/v1/file']), Buffer.from(bobV3.ciphertext, 'base64')));

  // ---- Step 7 (Goal 3): crash the CP just before COMMIT ----
  const epochBefore = cpEpoch();
  const armed = await supervisor.restartService(home, { ...env, KIG_CRASH_AT: 'before_commit', KIG_CRASH_HARNESS: '1' }, 'cp');
  const crashed = run(['rotate', '--file', 'brief']);
  assert.equal(crashed.code, 1);
  await until(() => { try { process.kill(armed.pid, 0); return false; } catch (e) { return e.code === 'ESRCH'; } }, 'CP SIGKILLed itself');
  const crashedRot = cpQuery((db) => db.prepare("SELECT rotation_id, to_version FROM rotation_journal WHERE phase='STAGE' ORDER BY rowid DESC LIMIT 1").get());
  assert.equal(crashedRot.to_version, 4);
  await supervisor.restartService(home, env, 'cp');
  await until(() => cpQuery((db) => db.prepare("SELECT 1 FROM rotation_journal WHERE rotation_id=? AND phase='ABORTED'").get(crashedRot.rotation_id)), 'recovery aborted the rotation');
  assert.equal(cpQuery((db) => db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc('brief')).active_version), 3);
  assert.ok(cpEpoch() >= epochBefore);
  for (const id of NODE_IDS) {
    await until(() => nodeState(id).lease_valid, `node ${id} lease after CP restart`);
    assert.equal(nodeState(id).snapshot.files.find((f) => f.file_id === 'brief').active_version, 3, `v3 still active on ${id}`);
    assert.equal((await req(id, 'alice-phone', 'alice', 'file.read', 3)).rule, 'device_revoked', `revocation still in force on ${id}`);
    assert.ok((await read(id, 'bob-laptop', 'bob', 3)).equals(plaintext), `data readable via ${id}`);
  }

  // ---- Step 8 (Goal 4): backup, tamper, stale, restore ----
  const current = path.join(work, 'backup-current');
  ok(['backup', '--out', current]);
  ok(['down']);
  const snapshotLive = () => fs.readFileSync(L.cp.db).toString('hex');
  const live = snapshotLive();
  const flipped = path.join(work, 'flipped'); fs.cpSync(current, flipped, { recursive: true });
  { const p = path.join(flipped, 'payload.bin'); const b = fs.readFileSync(p); b[64] ^= 0x80; fs.writeFileSync(p, b); }
  const truncated = path.join(work, 'truncated'); fs.cpSync(current, truncated, { recursive: true });
  { const p = path.join(truncated, 'payload.bin'); fs.writeFileSync(p, fs.readFileSync(p).subarray(0, 4096)); }
  const restore = (dir) => run(['restore', dir, '--recovery-key', L.operator.recoveryKey.key, '--anchor', path.join(home, 'anchor', 'keys.json')]);
  for (const [dir, category] of [[flipped, 'digest_mismatch'], [truncated, 'digest_mismatch'], [oldBackup, 'stale_backup']]) {
    const r = restore(dir);
    assert.equal(r.stderr, `kig restore: RESTORE REFUSED: ${category} (live state unchanged)\n`);
    assert.equal(snapshotLive(), live, `${category}: live registry byte-identical`);
  }
  const good = restore(current);
  assert.equal(good.code, 0, good.stderr);
  ok(['up']);
  for (const id of NODE_IDS) assert.ok((await read(id, 'bob-laptop', 'bob', 3)).equals(plaintext), `after restore via ${id}`);
  assert.equal(ok(['verify-log', '--db', L.cp.db]).stdout.slice(0, 3), 'OK ');

  // Step 4, continued: the in-flight transfer ends at cutoff + 30 s.
  await pause(Math.max(0, ROTATION.graceMs + 1500 - (Date.now() - cutoffAt)));
  const late = await chunk('A', inflight.transfer_id, 0);
  assert.equal(late.decision, 'deny');
  assert.ok(late.rule === 'grace_expired' || (late.rule === 'transfer_terminated' && late.reason === 'grace_expired'), JSON.stringify(late));
  { const db = openReadOnly(L.node('A').db); try { assert.equal(db.prepare('SELECT reason FROM transfers WHERE transfer_id=?').get(inflight.transfer_id).reason, 'grace_expired'); } finally { db.close(); } }

  // Task 4.5 on the live cluster: put node A's old store back; it must never re-enable alice-phone.
  ok(['down']);
  const hwm = Number(fs.readFileSync(`${L.node('A').db}.epoch`, 'utf8'));
  for (const s of ['', '-wal', '-shm']) fs.rmSync(L.node('A').db + s, { force: true });
  fs.copyFileSync(nodeACopy, L.node('A').db);
  ok(['up']);
  const stateA = nodeState('A');
  assert.ok(stateA.applied_epoch >= hwm, `node A re-applied a snapshot at least as new as its high-water mark (${stateA.applied_epoch} >= ${hwm})`);
  assert.equal((await req('A', 'alice-phone', 'alice', 'file.read', 3)).rule, 'device_revoked');
  // The old store has no ciphertext for versions staged after the copy was taken: node A fails closed
  // for them (stated limit: staged data is not re-sent to a rolled-back node); B and C still serve Bob.
  assert.deepEqual(await req('A', 'bob-laptop', 'bob', 'file.read', 3).then((r) => [r.decision, r.rule]), ['deny', 'unknown_file']);
  for (const id of ['B', 'C']) assert.ok((await read(id, 'bob-laptop', 'bob', 3)).equals(plaintext));
});
