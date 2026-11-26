'use strict';
// `kig crash-test [--point <p>] [--json] [--out <file>]` (features P1-06; architecture §12.3; Task 4.3).
//
// In an isolated temporary KIG home: start the CP and nodes A/B/C, enrol alice-phone, alice-laptop and
// bob-laptop, publish `brief`, share it with Bob and revoke alice-phone. Then, for each crash point:
// restart the CP with KIG_CRASH_AT=<point> (honoured because KIG_CRASH_HARNESS=1), ask it to rotate
// `brief`, confirm it SIGKILLed itself at that point, restart it normally (recovery runs at start) and
// check the invariants. The points run in order on the same cluster, so later points also show that
// recovery copes with the state earlier recoveries left behind.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const supervisor = require('./supervisor.cjs');
const { openReadOnly } = require('../store/db.cjs');
const ids = require('../core/ids.cjs');
const provider = require('../crypto/provider.cjs');
const audit = require('../core/audit.cjs');
const { call } = require('../core/http.cjs');
const { layout, ports, url, NODE_IDS, ROTATION, ROUTES } = require('../core/contracts.cjs');
const client = require('../device/client.cjs');
const deviceFiles = require('../device/files.cjs');
const nodePolicy = require('../node/policy.cjs');
const { UsageError, CommandError } = require('./main.cjs');

const REPO = path.resolve(__dirname, '..', '..');
const KIG = path.join(REPO, 'kig.cjs');
// Last journal phase durable at each crash point, and how recovery must resolve it.
const EXPECT = {
  after_prepare: { phase: 'PREPARE', action: 'abort' },
  after_stage: { phase: 'STAGE', action: 'abort' },
  before_commit: { phase: 'STAGE', action: 'abort' },
  after_commit: { phase: 'COMMIT', action: 'roll_forward' },
  during_distribute: { phase: 'DISTRIBUTE', action: 'roll_forward' },
};
const ORDER = Object.fromEntries(ROTATION.phases.map((p, i) => [p, i]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function reserveBase() {
  for (let i = 0; i < 24; i++) {
    const base = 12000 + (provider.random(4).readUInt32BE(0) % 12000);
    const open = [];
    try {
      for (let p = base; p < base + 4; p++) { const s = net.createServer(); open.push(s); await new Promise((ok, no) => s.once('error', no).listen(p, '127.0.0.1', ok)); }
      await Promise.all(open.map((s) => new Promise((ok) => s.close(ok))));
      return base;
    } catch { await Promise.all(open.filter((s) => s.listening).map((s) => new Promise((ok) => s.close(ok)))); }
  }
  throw new Error('could not reserve loopback ports');
}

function withRegistry(home, fn) {
  const db = openReadOnly(layout(home).cp.db);
  try { return fn(db); } finally { db.close(); }
}
function nodeState(home, id) {
  const db = openReadOnly(layout(home).node(id).db);
  try { return nodePolicy.current(db); } finally { db.close(); }
}
async function until(fn, ms) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v || Date.now() >= end) return v;
    await sleep(50);
  }
}
function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

/** Build the scenario through the real CLI (each command in its own process, like an operator). */
function setup(home, env, marker) {
  const input = path.join(home, 'brief-input.txt');
  fs.writeFileSync(input, marker, { mode: 0o600 });
  const steps = [
    ['account', 'add', 'alice'], ['device', 'enrol', 'alice-phone', '--account', 'alice'],
    ['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'crash-alice-first'],
    ['device', 'enrol', 'alice-laptop', '--account', 'alice'],
    ['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'crash-alice-laptop'],
    ['account', 'add', 'bob'], ['device', 'enrol', 'bob-laptop', '--account', 'bob'],
    ['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'crash-bob-first'],
    ['file', 'publish', 'brief', '--as', 'alice-laptop', '--input', input],
    ['share', 'brief', '--with', 'bob'],
    ['revoke', '--device', 'alice-phone'],
  ];
  for (const args of steps) {
    const r = spawnSync(process.execPath, [KIG, ...args], { cwd: os.tmpdir(), env, encoding: 'utf8', timeout: 60000 });
    if (r.status !== 0) throw new Error(`setup step '${args.slice(0, 2).join(' ')}' failed`);
  }
  fs.rmSync(input, { force: true });
}

async function request(home, env, node, device, account, op, keyVersion) {
  return client.request(url(ports(env)[node]), layout(home).device(device).dir, op, {
    home, version: 1, op, account, device_id: device, resource: 'brief', request_id: `crash-${provider.random(8).toString('hex')}`, key_version: keyVersion,
  });
}

/** One crash point. Returns { point, pass, checks: [{name, pass, detail}] }. */
async function runPoint(home, env, point, marker) {
  const checks = [];
  const check = (name, pass, detail) => checks.push({ name, pass: !!pass, detail });
  const before = withRegistry(home, (db) => ({
    epoch: Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v),
    active: db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc('brief')).active_version,
    rotations: new Set(db.prepare('SELECT DISTINCT rotation_id FROM rotation_journal').all().map((r) => r.rotation_id)),
  }));
  const nodeBefore = Object.fromEntries(NODE_IDS.map((id) => [id, nodeState(home, id).applied_epoch]));

  // 1. CP with the crash point armed; ask it to rotate; it must die at that point.
  const armed = await supervisor.restartService(home, { ...env, KIG_CRASH_AT: point, KIG_CRASH_HARNESS: '1' }, 'cp');
  let answered = null;
  try { answered = await call(`${url(ports(env).cp)}${ROUTES.cp.rotate.split(' ')[1]}`, 'POST', { file_id: 'brief' }, { timeoutMs: 30000 }); } catch { /* expected: the CP died */ }
  const died = await until(() => !pidAlive(armed.pid), 10000);
  check('cp_killed_at_point', died && answered === null, died ? 'CP process gone, no answer to the rotate request' : 'CP still alive');
  const crashed = withRegistry(home, (db) => {
    const rows = db.prepare('SELECT rotation_id, phase, from_version, to_version FROM rotation_journal ORDER BY rowid').all().filter((r) => !before.rotations.has(r.rotation_id));
    if (!rows.length) return null;
    return { rotation_id: rows[0].rotation_id, from: rows[0].from_version, to: rows[0].to_version, last: rows.map((r) => r.phase).reduce((a, b) => (ORDER[b] > ORDER[a] ? b : a)) };
  });
  check('journal_at_crash', crashed && crashed.last === EXPECT[point].phase, crashed ? `last durable phase ${crashed.last}` : 'no rotation journalled');
  if (!crashed) return { point, pass: false, checks };

  // 2. Normal restart: recovery runs at CP start.
  await supervisor.restartService(home, env, 'cp');
  const terminal = await until(() => withRegistry(home, (db) => {
    const phases = db.prepare('SELECT phase FROM rotation_journal WHERE rotation_id=?').all(crashed.rotation_id).map((r) => r.phase);
    return phases.includes('COMPLETE') ? 'COMPLETE' : phases.includes('ABORTED') ? 'ABORTED' : null;
  }), 20000);
  const wantTerminal = EXPECT[point].action === 'abort' ? 'ABORTED' : 'COMPLETE';
  check('recovery_action', terminal === wantTerminal, `${EXPECT[point].action}: journal ${terminal || 'not terminal'}`);
  const expected = EXPECT[point].action === 'abort' ? before.active : crashed.to;

  // 3. One consistent active version at the CP …
  const cp = withRegistry(home, (db) => ({
    epoch: Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v),
    active: db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc('brief')).active_version,
    activeRows: db.prepare("SELECT version FROM file_versions WHERE file_id=? AND status='active'").all(ids.enc('brief')).map((r) => r.version),
    staged: db.prepare("SELECT count(*) AS n FROM file_versions WHERE status='staged'").get().n,
    phone: db.prepare('SELECT status FROM devices WHERE device_id=?').get(ids.enc('alice-phone')).status,
    verified: db.prepare("SELECT detail FROM audit_events WHERE kind='recovery' ORDER BY seq DESC LIMIT 1").get(),
    chain: audit.verifyChain(db),
  }));
  check('cp_one_active_version', cp.active === expected && cp.activeRows.length === 1 && cp.activeRows[0] === expected && cp.staged === 0,
    `active v${cp.active} (expected v${expected}); active rows [${cp.activeRows}]; staged ${cp.staged}`);
  // … and on every node, once they converge.
  const converged = await until(() => NODE_IDS.every((id) => {
    const s = nodeState(home, id);
    return s.lease_valid && s.applied_epoch >= cp.epoch && s.snapshot.files.find((f) => f.file_id === 'brief')?.active_version === expected;
  }), 10000);
  const nodeAfter = Object.fromEntries(NODE_IDS.map((id) => [id, nodeState(home, id)]));
  check('nodes_one_active_version', converged, NODE_IDS.map((id) => `${id}: epoch ${nodeAfter[id].applied_epoch} v${nodeAfter[id].snapshot?.files.find((f) => f.file_id === 'brief')?.active_version}`).join(', '));
  check('epoch_never_decreases', cp.epoch >= before.epoch && NODE_IDS.every((id) => nodeAfter[id].applied_epoch >= nodeBefore[id]),
    `CP ${before.epoch} -> ${cp.epoch}; nodes ${NODE_IDS.map((id) => `${id} ${nodeBefore[id]} -> ${nodeAfter[id].applied_epoch}`).join(', ')}`);

  // 4. The revoked device stays revoked everywhere.
  const phone = [];
  for (const id of NODE_IDS) phone.push((await request(home, env, id, 'alice-phone', 'alice', 'policy.probe', expected)).rule);
  check('revoked_stays_revoked', cp.phone === 'revoked' && phone.every((r) => r === 'device_revoked'), `CP ${cp.phone}; nodes ${phone.join(',')}`);

  // 5. Committed data decrypts for the remaining devices through every node.
  const reads = [];
  for (const id of NODE_IDS) {
    for (const [device, account] of [['bob-laptop', 'bob'], ['alice-laptop', 'alice']]) {
      let okRead = false;
      try {
        const r = await request(home, env, id, device, account, 'file.read', expected);
        okRead = r.decision === 'allow' && r.version === expected && deviceFiles.read(home, device, r).toString('utf8') === marker;
      } catch { okRead = false; }
      reads.push(okRead);
    }
  }
  check('committed_data_readable', reads.every(Boolean), `${reads.filter(Boolean).length}/${reads.length} reads decrypted v${expected}`);
  let detail = null;
  try { detail = JSON.parse(cp.verified.detail); } catch { /* reported below */ }
  check('custodian_test_decrypt', detail && detail.files_unreadable === 0 && detail.files_verified >= 1,
    detail ? `${detail.files_verified} verified, ${detail.files_unreadable} unreadable` : 'no recovery record');
  check('audit_chain_ok', cp.chain.ok, cp.chain.ok ? `${cp.chain.count} events` : `broken at seq ${cp.chain.seq}`);
  return { point, expected_action: EXPECT[point].action, rotation: { from: crashed.from, to: crashed.to }, active_after: cp.active, pass: checks.every((c) => c.pass), checks };
}

async function runAll(points) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-crash-test-'));
  const env = { ...process.env, KIG_HOME: home, KIG_PORT_BASE: String(await reserveBase()) };
  delete env.KIG_CRASH_AT;
  delete env.KIG_CRASH_HARNESS;
  const marker = `kig crash-test ${provider.random(12).toString('hex')}`;
  let started = false;
  try {
    const init = spawnSync(process.execPath, [KIG, 'init'], { cwd: os.tmpdir(), env, encoding: 'utf8', timeout: 30000 });
    if (init.status !== 0) throw new Error('temporary KIG home could not be initialized');
    await supervisor.start(home, env); started = true;
    setup(home, env, marker);
    const ready = await until(() => NODE_IDS.every((id) => nodeState(home, id).snapshot?.revoked_devices.includes('alice-phone')), 10000);
    if (!ready) throw new Error('nodes did not converge after setup');
    const results = [];
    for (const point of points) results.push(await runPoint(home, env, point, marker));
    return results;
  } finally {
    if (started) await supervisor.stop(home, env).catch(() => {});
    fs.rmSync(home, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'crash-test',
  describe: 'SIGKILL the control plane at each rotation phase, restart it, and check recovery invariants',
  usage: `usage: node kig.cjs crash-test [--point <${ROTATION.crashPoints.join('|')}>] [--json] [--out <report.json>]`,
  options: { point: { type: 'string' }, json: { type: 'boolean' }, out: { type: 'string' } },
  async run({ values, positionals, io }) {
    if (positionals.length) throw new UsageError('unexpected argument');
    if (values.point !== undefined && !ROTATION.crashPoints.includes(values.point)) throw new UsageError(`--point must be one of ${ROTATION.crashPoints.join(', ')}`);
    const points = values.point ? [values.point] : [...ROTATION.crashPoints];
    let results;
    try { results = await runAll(points); } catch (e) { throw new CommandError(`crash test could not run: ${String(e.message || e).split(/\r?\n/)[0]}`); }
    const report = { generated_at: new Date().toISOString(), runtime: { node: process.version, platform: process.platform, arch: process.arch },
      points: results, pass: results.every((r) => r.pass) };
    const file = values.out ? path.resolve(values.out) : path.join(REPO, 'evidence', `crash-test-${report.generated_at.replace(/[:.]/g, '-')}.json`);
    let saved;
    try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`); saved = `report: ${file}`; }
    catch (e) { saved = `report not saved (${e.code || 'error'}): ${file} is not writable here`; }
    if (values.json) { io.out(`${JSON.stringify(report, null, 2)}\n`); io.err(`${saved}\n`); }
    else {
      for (const r of results) {
        io.out(`${r.pass ? 'PASS' : 'FAIL'} ${r.point.padEnd(17)} ${r.expected_action ? `${r.expected_action.padEnd(12)} rotation v${r.rotation.from}->v${r.rotation.to}, active after recovery v${r.active_after}` : ''}\n`);
        for (const c of r.checks) io.out(`     ${c.pass ? 'ok  ' : 'FAIL'} ${c.name}: ${c.detail}\n`);
      }
      io.out(`${saved}\n`);
    }
    return report.pass ? 0 : 1;
  },
  EXPECT,
};
