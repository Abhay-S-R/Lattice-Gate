'use strict';
// D12 (docs/plans/phase-4.md): Phase 4 adds its tables in place, like Phase 3's lazy node_acks column
// and Phase 6's ensureMessaging. A KIG home created before Phase 4 keeps working, with no re-init.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { NODE_IDS, layout } = require('../../src/core/contracts.cjs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const { openDb, openReadOnly } = require('../../src/store/db.cjs');
const cpSchema = require('../../src/store/schema-cp.cjs');
const nodeSchema = require('../../src/store/schema-node.cjs');

const CP_P4 = ['rotation_journal_by_file', 'rotation_journal', 'rotation_stage_acks', 'file_cutoffs'];
const NODE_P4 = ['transfers_by_device', 'transfers', 'cutoffs'];
const objects = (file) => { const db = openReadOnly(file); try { return new Set(db.prepare("SELECT name FROM sqlite_master WHERE type IN ('table','index')").all().map((r) => r.name)); } finally { db.close(); } };
const version = (file) => { const db = openReadOnly(file); try { return db.prepare('PRAGMA user_version').get().user_version; } finally { db.close(); } };

/** Turn a fresh home into a pre-Phase-4 one: drop exactly what Phase 4 added. */
function downgrade(file, schema, names) {
  const db = openDb(file, { create: false, version: schema.VERSION, init: schema.init });
  try { for (const n of names) db.exec(`DROP ${n.endsWith('_by_file') || n.endsWith('_by_device') ? 'INDEX' : 'TABLE'} ${n}`); } finally { db.close(); }
}

test('a home created before Phase 4 upgrades in place, then rotates, backs up and restores', async (t) => {
  const home = freshHome();
  let cluster;
  t.after(async () => { if (cluster) await cluster.stop(); fs.rmSync(home, { recursive: true, force: true }); });
  const L = layout(home);
  const port = String(20000 + Math.floor(Math.random() * 20000));
  const pre = runKig(['init'], { env: { KIG_HOME: home, KIG_PORT_BASE: port } });
  assert.equal(pre.code, 0, pre.stderr);
  downgrade(L.cp.db, cpSchema, CP_P4);
  for (const id of NODE_IDS) downgrade(L.node(id).db, nodeSchema, NODE_P4);
  for (const n of CP_P4) assert.equal(objects(L.cp.db).has(n), false, n);
  for (const n of NODE_P4) assert.equal(objects(L.node('A').db).has(n), false, n);
  assert.equal(version(L.cp.db), 1);

  // A CLI command on the old store (publish → snapshot → cutoff lookup) upgrades it; no schema error.
  const offline = runKig(['account', 'add', 'alice'], { env: { KIG_HOME: home, KIG_PORT_BASE: port } });
  assert.equal(offline.code, 0, offline.stderr);
  for (const n of CP_P4) assert.ok(objects(L.cp.db).has(n), `registry gained ${n}`);
  assert.equal(version(L.cp.db), 1, 'still schema version 1');

  cluster = await startCluster(home); // node servers upgrade their own stores at start
  for (const id of NODE_IDS) for (const n of NODE_P4) assert.ok(objects(L.node(id).db).has(n), `node ${id} gained ${n}`);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  const ok = (args) => { const r = runKig(args, { env, timeoutMs: 120000 }); assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr || r.stdout}`); return r; };
  const input = path.join(home, 'brief.txt');
  fs.writeFileSync(input, 'written before the upgrade test rotated it');
  ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'up-1']);
  ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  assert.match(ok(['rotate', '--file', 'brief']).stdout, /^ROTATED "brief" 1 -> 2 epoch=\d+ \(complete/);
  for (const id of NODE_IDS) assert.equal(ok(['file', 'read', 'brief', '--device', 'alice-phone', '--node', id]).stdout, 'written before the upgrade test rotated it\n');
  const dir = path.join(home, 'backup');
  assert.match(ok(['backup', '--out', dir]).stdout, / schema=1\n$/);
  const restored = ok(['restore', dir, '--recovery-key', L.operator.recoveryKey.key, '--anchor', path.join(home, 'anchor', 'keys.json')]);
  assert.match(restored.stdout, /cluster restarted/);
  assert.match(ok(['rotate', '--file', 'brief']).stdout, /^ROTATED "brief" 2 -> 3 /);
});
