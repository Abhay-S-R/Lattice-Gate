'use strict';
// Isolated, seeded revocation propagation benchmark (Phase 3 task 3.8).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const supervisor = require('./supervisor.cjs');
const { openDb, tx } = require('../store/db.cjs');
const cpSchema = require('../store/schema-cp.cjs');
const ids = require('../core/ids.cjs');
const provider = require('../crypto/provider.cjs');
const { layout, ports, url, NODE_IDS, SNAPSHOT, RULES } = require('../core/contracts.cjs');
const keystore = require('../device/keystore.cjs');
const { request } = require('../device/client.cjs');
const { publish } = require('../cp/snapshot.cjs');
const { revoke } = require('../cp/revoke.cjs');
const cpAlerts = require('../cp/alerts.cjs');
const { call } = require('../core/http.cjs');

const REPO = path.resolve(__dirname, '..', '..');
const seededDeviceId = (seed, index) => `bench-${provider.sha256(Buffer.from(`${seed}:${index}`)).toString('hex').slice(0, 32)}`;
function summarize(values) {
  if (!Array.isArray(values) || values.length === 0 || values.some(x => !Number.isFinite(x) || x < 0)) throw new RangeError('latencies must be a non-empty array');
  const sorted = [...values].sort((a, b) => a - b);
  const rank = p => sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
  return { p50: rank(.50), p95: rank(.95), max: sorted[sorted.length - 1] };
}
async function reserveBase() {
  for (let i = 0; i < 24; i++) {
    const base = 12000 + (provider.random(4).readUInt32BE(0) % 12000);
    const ss = [];
    try {
      for (let p = base; p < base + 4; p++) { const s = net.createServer(); ss.push(s); await new Promise((ok, no) => s.once('error', no).listen(p, '127.0.0.1', ok)); }
      await Promise.all(ss.map(s => new Promise(ok => s.close(ok)))); return base;
    } catch { await Promise.all(ss.filter(s => s.listening).map(s => new Promise(ok => s.close(ok)))); }
  }
  throw new Error('benchmark could not reserve loopback ports');
}
function seed(home, seed, n) {
  const L = layout(home);
  const db = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
  const rows = [];
  try {
    tx(db, () => {
      db.prepare("INSERT INTO accounts(account,created_ms,status) VALUES(?,?,'active')").run(ids.enc('benchmark-owner'), Date.now());
      for (let i = 0; i <= n; i++) {
        const deviceId = i === n ? 'bench-observer' : seededDeviceId(seed, i);
        const pub = keystore.create(home, deviceId);
        keystore.pinPolicy(home, deviceId, fs.readFileSync(L.anchor.cpPolicyPub));
        db.prepare("INSERT INTO devices(device_id,account,sign_pk,kem_pk,status,key_version,created_ms) VALUES(?,?,?,?,'active',1,?)")
          .run(ids.enc(deviceId), ids.enc('benchmark-owner'), pub.signPublic, pub.kemPublic, Date.now());
        rows.push(deviceId);
      }
    });
  } finally { db.close(); }
  return rows;
}
async function run(values = {}) {
  const n = Number(values.n ?? '100'), seedValue = Number(values.seed);
  if (!Number.isSafeInteger(n) || n < 1 || n > 1000) { process.stderr.write('kig bench revocation: --n must be an integer from 1 to 1000\n'); return 2; }
  if (!Number.isSafeInteger(seedValue) || seedValue < 0 || seedValue > 999999999) { process.stderr.write('kig bench revocation: --seed must be an integer from 0 to 999999999\n'); return 2; }
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-revocation-bench-'));
  const env = { ...process.env, KIG_HOME: home, KIG_PORT_BASE: String(await reserveBase()) };
  let clusterStarted = false;
  let report;
  try {
    const initialized = spawnSync(process.execPath, [path.join(REPO, 'kig.cjs'), 'init'], { cwd: os.tmpdir(), env, encoding: 'utf8', timeout: 30000 });
    if (initialized.status !== 0) throw new Error('temporary benchmark KIG home could not be initialized');
    const deviceIds = seed(home, seedValue, n), observer = deviceIds[n];
    const L = layout(home); const db = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
    try { publish(db, { env }); } finally { db.close(); }
    await supervisor.start(home, env); clusterStarted = true;
    const byNode = Object.fromEntries(NODE_IDS.map(id => [id, []]));
    const ackByNode = Object.fromEntries(NODE_IDS.map(id => [id, []]));
    for (const deviceId of deviceIds.slice(0, n)) {
      const cp = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
      let revoked;
      try { revoked = revoke(cp, deviceId, { env }); } finally { cp.close(); }
      const t0 = BigInt(revoked.committed_mono_ns);
      const deadline = Date.now() + 15000;
      await Promise.all(NODE_IDS.map(async id => {
        const fields = { home, version: 1, op: 'policy.probe', account: 'benchmark-owner', device_id: deviceId, resource: 'benchmark', key_version: 1 };
        while (Date.now() < deadline) {
          let answer;
          try { answer = await request(url(ports(env)[id]), L.device(deviceId).dir, fields.op, { ...fields, request_id: `probe-${provider.random(12).toString('hex')}` }); } catch { await new Promise(r => setTimeout(r, 1)); continue; }
          if (answer.decision === 'deny' && answer.rule === RULES.deviceRevoked) { byNode[id].push(Number(process.hrtime.bigint() - t0) / 1e6); return; }
          if (answer.decision === 'deny') throw new Error(`node ${id} denied ${deviceId} for ${answer.rule}, not revocation`);
          await new Promise(r => setTimeout(r, 1));
        }
        throw new Error(`node ${id} did not deny revoked device before deadline`);
      }));
      const ackDeadline = Date.now() + 5000;
      let pending = new Set(NODE_IDS);
      while (pending.size && Date.now() < ackDeadline) {
        const ackdb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
        try {
          for (const id of pending) {
            const ack = ackdb.prepare('SELECT acked_mono_ns FROM node_acks WHERE node_id=? AND epoch=?').get(id, revoked.epoch);
            if (ack) { ackByNode[id].push(Number(BigInt(ack.acked_mono_ns) - t0) / 1e6); pending.delete(id); }
          }
        } finally { ackdb.close(); }
        if (pending.size) await new Promise(r => setTimeout(r, 5));
      }
      if (pending.size) {
        const ackdb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
        try { for (const id of pending) cpAlerts.recordMissingAck(ackdb, revoked.epoch, id); } finally { ackdb.close(); }
        throw new Error(`nodes did not acknowledge epoch ${revoked.epoch}: ${[...pending].join(',')}`);
      }
    }
    for (const id of NODE_IDS) {
      const allowed = await request(url(ports(env)[id]), L.device('bench-observer').dir, 'policy.probe', {
        home, version: 1, op: 'policy.probe', account: 'benchmark-owner', device_id: 'bench-observer', resource: 'peer-check', key_version: 1, request_id: `peer-check-${id}`,
      });
      if (allowed.decision !== 'allow') throw new Error(`unaffected peer was denied by node ${id}`);
    }
    const partitionId = 'A';
    const token = fs.readFileSync(path.join(L.root, 'run', `${partitionId}.control`), 'utf8').trim();
    const controlUrl = `${url(ports(env)[partitionId])}/v1/control/partition`;
    const partition = await call(controlUrl, 'POST', {}, { headers: { 'x-kig-control-token': token } });
    if (partition.status !== 200) throw new Error('partition control was refused');
    await new Promise(r => setTimeout(r, Number(partition.json.expires_in_ms) + 30));
    const denied = await request(url(ports(env)[partitionId]), L.device(observer).dir, 'policy.probe', {
      home, version: 1, op: 'policy.probe', account: 'benchmark-owner', device_id: observer, resource: 'partition-check', key_version: 1, request_id: 'partition-check',
    });
    if (denied.decision !== 'deny' || denied.rule !== 'lease_expired') throw new Error('partitioned node did not fail closed at lease expiry');
    await call(`${url(ports(env)[partitionId])}/v1/control/heal`, 'POST', {}, { headers: { 'x-kig-control-token': token } });
    const nodeMetrics = Object.fromEntries(NODE_IDS.map(id => [id, { first_denial_ms: summarize(byNode[id]), signed_ack_ms: ackByNode[id].length ? summarize(ackByNode[id]) : null }]));
    const lastNode = Object.entries(nodeMetrics).sort((a, b) => b[1].first_denial_ms.max - a[1].first_denial_ms.max)[0][0];
    report = { generated_at: new Date().toISOString(), seed: seedValue, n, clock: 'process.hrtime.bigint shared host monotonic clock', nodes: nodeMetrics, last_node: lastNode,
      partition: { node: partitionId, lease_ms: SNAPSHOT.leaseMs, result: denied.rule }, limitations: ['single-host run', 'benchmark uses temporary KIG_HOME', 'latency includes loopback HTTP and signed challenge probes'] };
  } catch (e) {
    process.stderr.write(`kig bench revocation: ${String(e.message || e).split(/\r?\n/)[0]}\n`); return 1;
  } finally {
    if (clusterStarted) await supervisor.stop(home, env).catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }
  const generated = report.generated_at;
  const output = values.out ? path.resolve(values.out) : path.join(REPO, 'evidence', `revocation-${generated.replace(/[:.]/g, '-')}.json`);
  fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(values.json ? `${JSON.stringify(report, null, 2)}\n` : `kig bench revocation n=${n} seed=${seedValue}\n${NODE_IDS.map(id => `  ${id}: p50=${report.nodes[id].first_denial_ms.p50.toFixed(2)} ms p95=${report.nodes[id].first_denial_ms.p95.toFixed(2)} ms max=${report.nodes[id].first_denial_ms.max.toFixed(2)} ms`).join('\n')}\n  last node: ${report.last_node}\n  partition: ${report.partition.result} after ${report.partition.lease_ms} ms\n  report: ${output}\n`);
  return 0;
}
module.exports = { run, seededDeviceId, summarize };
