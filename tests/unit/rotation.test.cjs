'use strict';
// Task 4.1: rotation, staging, cutoff and grace across three nodes (features P1-04, D-06; architecture §12).
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
const { openDb, openReadOnly, tx } = require('../../src/store/db.cjs');
const cpSchema = require('../../src/store/schema-cp.cjs');
const ids = require('../../src/core/ids.cjs');
const provider = require('../../src/crypto/provider.cjs');
const stageBytes = require('../../src/core/stage.cjs');
const { call } = require('../../src/core/http.cjs');
const rotation = require('../../src/cp/rotate.cjs');
const nodePolicy = require('../../src/node/policy.cjs');

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
let seq = 0;

async function setup(t) {
  const home = freshHome();
  const inputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-rotate-input-'));
  const plaintext = Buffer.from(provider.random(20000).toString('hex')); // 40 000 bytes → 3 chunks of 16 KiB
  const input = path.join(inputDir, 'brief.txt');
  fs.writeFileSync(input, plaintext);
  let cluster; let db;
  t.after(async () => {
    db?.close();
    if (cluster) await cluster.stop();
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(inputDir, { recursive: true, force: true });
  });
  cluster = await startCluster(home);
  const port = String(new URL(cluster.cpUrl).port);
  const env = { ...process.env, KIG_HOME: home, KIG_PORT_BASE: port };
  const run = (args) => runKig(args, { env: { KIG_HOME: home, KIG_PORT_BASE: port }, timeoutMs: 90000 });
  const ok = (args) => { const r = run(args); assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr || r.stdout}`); return r; };
  ok(['account', 'add', 'alice']);
  ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'a1']);
  ok(['account', 'add', 'bob']);
  ok(['device', 'enrol', 'bob-laptop', '--account', 'bob']);
  ok(['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'b1']);
  ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  ok(['share', 'brief', '--with', 'bob']);
  db = openDb(layout(home).cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
  const ctx = { home, env, run, ok, cluster, plaintext, db: () => db };
  // Nodes pick up the publish/share snapshot through push or the 250 ms pull.
  for (const id of NODE_IDS) await until(() => nodeState(ctx, id).snapshot?.grants.some((g) => g.account === 'bob'), `node ${id} has the share`);
  return ctx;
}

async function until(fn, what, ms = 8000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await pause(25); }
  throw new Error(`timed out waiting for ${what}`);
}

function nodeState(ctx, id) {
  const db = openReadOnly(layout(ctx.home).node(id).db);
  try { return nodePolicy.current(db); } finally { db.close(); }
}

function fields(ctx, device, account, keyVersion, op = 'file.transfer') {
  return { home: ctx.home, version: 1, op, account, device_id: device, resource: 'brief', request_id: `r-${++seq}`, key_version: keyVersion };
}
const startTransfer = (ctx, node, device, account, v) => client.request(ctx.cluster.nodeUrls[node], layout(ctx.home).device(device).dir, 'file.transfer', fields(ctx, device, account, v));
const chunk = (ctx, node, id, i) => client.transferChunk(ctx.cluster.nodeUrls[node], id, i);

async function fullRead(ctx, node, device, account, v) {
  const start = await startTransfer(ctx, node, device, account, v);
  assert.equal(start.decision, 'allow', `${device} via ${node} v${v}: ${start.rule}`);
  const chunks = [];
  for (let i = 0; i < start.chunk_count; i++) chunks.push(await chunk(ctx, node, start.transfer_id, i));
  return deviceFiles.readTransfer(ctx.home, device, start, chunks);
}

test('rotation: in-flight transfer finishes in grace, old version refused on every node, transfer ends at grace', async (t) => {
  const ctx = await setup(t);
  for (const id of NODE_IDS) assert.ok((await fullRead(ctx, id, 'bob-laptop', 'bob', 1)).equals(ctx.plaintext));

  // A transfer authenticated before the cutoff, on node A.
  const inflight = await startTransfer(ctx, 'A', 'bob-laptop', 'bob', 1);
  assert.equal(inflight.decision, 'allow');
  assert.equal(inflight.chunk_count, 3);
  const got = [await chunk(ctx, 'A', inflight.transfer_id, 0)];
  assert.equal(got[0].rule, 'allowed');

  const graceMs = 4000;
  const result = await rotation.rotate(ctx.db(), 'brief', { env: ctx.env, graceMs });
  assert.equal(result.status, 'complete', JSON.stringify(result));
  assert.equal(result.from_version, 1);
  assert.equal(result.to_version, 2);
  const committedAt = Date.now();

  // Every node applied the cutoff epoch before COMPLETE.
  for (const id of NODE_IDS) {
    const s = nodeState(ctx, id);
    assert.ok(s.applied_epoch >= result.epoch);
    assert.deepEqual(s.snapshot.files.find((f) => f.file_id === 'brief'), { file_id: 'brief', active_version: 2, cutoff: { old_version: 1, from_epoch: result.epoch, grace_ms: graceMs } });
  }

  // In-flight: the rest of the old version is served inside the grace window and decrypts.
  for (const i of [1, 2]) {
    const c = await chunk(ctx, 'A', inflight.transfer_id, i);
    assert.equal(c.decision, 'allow');
    assert.equal(c.rule, 'grace');
    got.push(c);
  }
  assert.ok(deviceFiles.readTransfer(ctx.home, 'bob-laptop', inflight, got).equals(ctx.plaintext));

  // New requests naming the old version: refused on every node, even inside the grace window.
  for (const id of NODE_IDS) {
    assert.equal((await startTransfer(ctx, id, 'bob-laptop', 'bob', 1)).rule, 'old_key_version', `transfer start on ${id}`);
    const read = await client.request(ctx.cluster.nodeUrls[id], layout(ctx.home).device('bob-laptop').dir, 'file.read', fields(ctx, 'bob-laptop', 'bob', 1, 'file.read'));
    assert.equal(read.rule, 'old_key_version', `one-shot read on ${id}`);
    assert.ok((await fullRead(ctx, id, 'alice-phone', 'alice', 2)).equals(ctx.plaintext), `new version via ${id}`);
  }
  assert.ok(Date.now() - committedAt < graceMs, 'the checks above must run inside the grace window');

  // After the grace window the in-flight transfer is terminated, then stays terminated.
  await pause(graceMs - (Date.now() - committedAt) + 300);
  // Ended either by this request or by the node's 1 s purge, whichever came first; the reason is the same.
  const ended = await chunk(ctx, 'A', inflight.transfer_id, 0);
  assert.equal(ended.decision, 'deny');
  assert.equal(ended.rule === 'grace_expired' ? 'grace_expired' : ended.reason, 'grace_expired', JSON.stringify(ended));
  assert.deepEqual(await chunk(ctx, 'A', inflight.transfer_id, 0), { decision: 'deny', rule: 'transfer_terminated', reason: 'grace_expired' });

  // Nodes delete the retired ciphertext after grace; the CP keeps the old version (and its custodian copy) as 'retired'.
  for (const id of NODE_IDS) {
    await until(() => {
      const db = openReadOnly(layout(ctx.home).node(id).db);
      try { return !db.prepare('SELECT 1 FROM ciphertexts WHERE file_id=? AND version=1').get(ids.enc('brief')); } finally { db.close(); }
    }, `node ${id} purges version 1`, 4000);
  }
  const versions = ctx.db().prepare('SELECT version, status FROM file_versions WHERE file_id=? ORDER BY version').all(ids.enc('brief')).map((r) => [r.version, r.status]);
  assert.deepEqual(versions, [[1, 'retired'], [2, 'active']]);
  const phases = ctx.db().prepare('SELECT phase FROM rotation_journal WHERE rotation_id=? ORDER BY rowid').all(result.rotation_id).map((r) => r.phase);
  assert.deepEqual(phases, ['PREPARE', 'REWRAP', 'STAGE', 'COMMIT', 'DISTRIBUTE', 'COMPLETE']);
});

test('rotation: a node that cannot stage aborts before commit; version numbers are not reused; kig rotate uses 30 s grace', async (t) => {
  const ctx = await setup(t);
  const token = fs.readFileSync(path.join(ctx.home, 'run', 'B.control'), 'utf8').trim();
  const control = (action) => call(`${ctx.cluster.nodeUrls.B}/v1/control/${action}`, 'POST', {}, { headers: { 'x-kig-control-token': token } });
  assert.equal((await control('partition')).status, 200);
  const epochBefore = Number(ctx.db().prepare("SELECT v FROM meta WHERE k='epoch'").get().v);

  const aborted = ctx.run(['rotate', '--file', 'brief']);
  assert.equal(aborted.code, 1, aborted.stdout);
  assert.match(aborted.stderr, /ROTATION ABORTED "brief" 1 -> 2 \(missing_stage_ack: B; version 1 stays active\)/);
  assert.equal(ctx.db().prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc('brief')).active_version, 1);
  assert.equal(ctx.db().prepare('SELECT count(*) AS n FROM file_versions WHERE file_id=? AND version=2').get(ids.enc('brief')).n, 0);
  assert.equal(Number(ctx.db().prepare("SELECT v FROM meta WHERE k='epoch'").get().v), epochBefore, 'an abort never publishes');
  const last = ctx.db().prepare("SELECT phase, reason FROM rotation_journal WHERE phase='ABORTED'").get();
  assert.deepEqual({ ...last }, { phase: 'ABORTED', reason: 'missing_stage_ack' });
  for (const id of ['A', 'C']) { // the nodes that did stage were told to drop it
    const db = openReadOnly(layout(ctx.home).node(id).db);
    try { assert.equal(db.prepare('SELECT count(*) AS n FROM ciphertexts WHERE file_id=? AND version=2').get(ids.enc('brief')).n, 0, id); } finally { db.close(); }
  }

  assert.equal((await control('heal')).status, 200);
  await until(() => nodeState(ctx, 'B').lease_valid, 'node B healed');
  const done = ctx.run(['rotate', '--file', 'brief']);
  assert.equal(done.code, 0, done.stderr);
  assert.match(done.stdout, /^ROTATED "brief" 1 -> 3 epoch=\d+ \(complete/);
  for (const id of NODE_IDS) {
    const f = nodeState(ctx, id).snapshot.files.find((x) => x.file_id === 'brief');
    assert.equal(f.active_version, 3);
    assert.equal(f.cutoff.grace_ms, ROTATION.graceMs);
    assert.equal(f.cutoff.old_version, 1);
    assert.ok((await fullRead(ctx, id, 'bob-laptop', 'bob', 3)).equals(ctx.plaintext));
  }
  const refused = ctx.run(['rotate', '--file', 'no-such-file']);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /rotation refused \(file_unknown\)/);
});

test('rotation: concurrent rotation refused; stage and drop need the CP signature; revocation ends transfers', async (t) => {
  const ctx = await setup(t);
  const db = ctx.db();
  tx(db, () => db.prepare("INSERT INTO rotation_journal(rotation_id,phase,file_id,from_version,to_version,ts_ms) VALUES('ffffffffffffffffffffffffffffffff','PREPARE',?,1,2,0)").run(ids.enc('brief')));
  await assert.rejects(rotation.rotate(db, 'brief', { env: ctx.env }), (e) => e.code === 'rotation_in_progress');
  await rotation.abort(db, { rotation_id: 'ffffffffffffffffffffffffffffffff', file_id: 'brief', from_version: 1, to_version: 2 }, 'test_cleanup', ctx.env);

  const cpKey = provider.importPrivate(fs.readFileSync(layout(ctx.home).cp.keys.policy.key));
  const forged = provider.sigGenerate().privateKey;
  const stageBody = (key, version) => {
    const nonce = provider.random(12); const ct = provider.random(64); const envelopes = [];
    const digest = stageBytes.digest('brief', version, nonce, ct, envelopes);
    return { op: 'stage', rotation_id: 'e'.repeat(32), file_id: 'brief', version, nonce: nonce.toString('base64'), ciphertext: ct.toString('base64'), envelopes,
      sig: provider.sign(key, ROTATION.context, stageBytes.signedBytes('stage', 'e'.repeat(32), 'brief', version, digest)).toString('base64') };
  };
  const post = (route, body) => call(`${ctx.cluster.nodeUrls.A}${route}`, 'POST', body);
  assert.deepEqual((await post('/v1/stage', stageBody(forged, 9))).json, { staged: false, reason: 'bad_signature' });
  assert.deepEqual((await post('/v1/stage', stageBody(cpKey, 1))).json, { staged: false, reason: 'not_newer' }, 'the active version can never be overwritten');
  const tamper = stageBody(cpKey, 9); tamper.ciphertext = provider.random(64).toString('base64');
  assert.deepEqual((await post('/v1/stage', tamper)).json, { staged: false, reason: 'bad_signature' }, 'signature binds the content');
  const dropActive = { op: 'drop', rotation_id: 'e'.repeat(32), file_id: 'brief', version: 1 };
  dropActive.sig = provider.sign(cpKey, ROTATION.context, stageBytes.signedBytes('drop', dropActive.rotation_id, 'brief', 1, Buffer.alloc(0))).toString('base64');
  assert.deepEqual((await post('/v1/stage/drop', dropActive)).json, { dropped: false, reason: 'active_version' });
  assert.equal((await post('/v1/stage', { op: 'stage' })).status, 400);
  assert.equal((await post('/v1/transfer/chunk', { transfer_id: 'x', index: 0 })).status, 400);
  assert.equal((await post('/v1/transfer/chunk', { transfer_id: '0'.repeat(64), index: 0 })).json.rule, 'transfer_unknown');

  const live = await startTransfer(ctx, 'B', 'alice-phone', 'alice', 1);
  assert.equal(live.decision, 'allow');
  ctx.ok(['revoke', '--device', 'alice-phone']);
  await until(async () => (await chunk(ctx, 'B', live.transfer_id, 0)).decision === 'deny', 'transfer ended by revocation');
  assert.deepEqual(await chunk(ctx, 'B', live.transfer_id, 0), { decision: 'deny', rule: 'transfer_terminated', reason: 'device_revoked' });
  const nb = openReadOnly(layout(ctx.home).node('B').db);
  try { assert.equal(nb.prepare('SELECT reason FROM transfers WHERE transfer_id=?').get(live.transfer_id).reason, 'device_revoked'); } finally { nb.close(); }
});
