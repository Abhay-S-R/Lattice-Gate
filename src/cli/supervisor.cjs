'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { ports, layout, kigHome, NODE_IDS, ROUTES, url } = require('../core/contracts.cjs');
const { call } = require('../core/http.cjs');
const cryptoProvider = require('../crypto/provider.cjs');

const ROOT = path.resolve(__dirname, '..', '..');
const SERVICES = ['cp', ...NODE_IDS];
const serviceKey = (id) => id === 'cp' ? 'cp' : id;
const healthRoute = (id) => id === 'cp' ? ROUTES.cp.health : ROUTES.node.health;
const endpoint = (id, ps) => url(ps[serviceKey(id)]);
const healthUrl = (id, ps) => `${endpoint(id, ps)}${healthRoute(id).slice(healthRoute(id).indexOf(' ') + 1)}`;
const pidFile = (L, id) => L.run.pid(id);
const controlFile = (L, id) => path.join(path.dirname(L.run.pid(id)), `${id}.control`);

function readRecord(file) {
  try {
    const x = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (Number.isInteger(x.pid) && typeof x.instance === 'string') return x;
  } catch {}
  return null;
}

async function probe(id, record, ps, timeoutMs = 350) {
  if (!record) return false;
  try {
    const r = await call(healthUrl(id, ps), 'GET', null, { timeoutMs });
    const serviceHealthy = r.status === 200 && r.json.status === 'ok' && r.json.instance === record.instance &&
      (id === 'cp' ? r.json.service === 'cp' : r.json.node_id === id);
    if (!serviceHealthy || id === 'cp') return serviceHealthy;
    const policy = await call(`${endpoint(id, ps)}${ROUTES.node.policyHead.split(' ')[1]}`, 'GET', null, { timeoutMs });
    return policy.status === 200 && Number.isSafeInteger(policy.json.epoch) && policy.json.epoch > 0 && policy.json.lease_valid === true;
  } catch { return false; }
}

async function status(home = kigHome(), env = process.env) {
  const L = layout(home), ps = ports(env);
  return Promise.all(SERVICES.map(async (id) => {
    const record = readRecord(pidFile(L, id));
    return { id, pid: record?.pid || null, healthy: await probe(id, record, ps) };
  }));
}

async function stop(home = kigHome(), env = process.env) {
  const L = layout(home), ps = ports(env);
  for (const id of [...SERVICES].reverse()) {
    const file = pidFile(L, id), record = readRecord(file);
    if (record && await probe(id, record, ps)) {
      try { process.kill(record.pid, 'SIGTERM'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
      const end = Date.now() + 3000;
      while (Date.now() < end && await probe(id, record, ps, 100)) await new Promise((r) => setTimeout(r, 40));
      if (await probe(id, record, ps, 100)) throw new Error(`${id} did not stop`);
    }
    try { fs.unlinkSync(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (id !== 'cp') try { fs.unlinkSync(controlFile(L, id)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}

/** Spawn one service and wait until it is healthy. Pushes {id, child, record} to launched before waiting. */
async function launch(home, env, id, launched) {
  const L = layout(home), ps = ports(env);
  const instance = cryptoProvider.random(16).toString('hex');
  const logfile = L.run.log(id);
  const fd = fs.openSync(logfile, 'a', 0o600);
  const childEnv = { ...env, KIG_HOME: path.resolve(home), KIG_PORT_BASE: String(ps.cp), KIG_INSTANCE_TOKEN: instance };
  const args = [path.join(ROOT, 'src', id === 'cp' ? 'cp/server.cjs' : 'node/server.cjs')];
  if (id !== 'cp') {
    childEnv.KIG_NODE_ID = id;
    const controlToken = cryptoProvider.random(32).toString('hex');
    fs.writeFileSync(controlFile(L, id), `${controlToken}\n`, { mode: 0o600 });
    childEnv.KIG_NODE_CONTROL_TOKEN = controlToken;
  }
  let child;
  // The service uses absolute module paths and KIG_HOME; a normal local cwd
  // also keeps Windows from trying to launch children from a UNC directory.
  try { child = spawn(process.execPath, args, { cwd: os.tmpdir(), env: childEnv, detached: true, stdio: ['ignore', fd, fd] }); }
  finally { fs.closeSync(fd); }
  child.unref();
  let launchError = null;
  child.once('error', (e) => { launchError = e; });
  const record = { pid: child.pid, instance };
  launched.push({ id, child, record });
  fs.writeFileSync(pidFile(L, id), `${JSON.stringify(record)}\n`, { mode: 0o600 });
  const readyBy = Date.now() + 5000;
  while (Date.now() < readyBy && !await probe(id, record, ps, 300)) {
    if (launchError) throw launchError;
    if (child.exitCode !== null) throw new Error(`${id} exited before becoming healthy (code ${child.exitCode})`);
    await new Promise((r) => setTimeout(r, 40));
  }
  if (!await probe(id, record, ps)) {
    let detail = 'no matching health response';
    try {
      const health = await call(healthUrl(id, ps), 'GET', null, { timeoutMs: 300 });
      detail = `health returned status ${health.status}: ${JSON.stringify(health.json)}`;
    } catch (e) { detail = String(e.message || e); }
    throw new Error(`${id} failed to become healthy (${detail})`);
  }
  return record;
}

/**
 * Restart ONE service (Phase 4 crash harness: the CP is restarted, with or without KIG_CRASH_AT,
 * while the nodes keep running). A healthy instance is stopped first with SIGTERM; it is identified
 * by its instance token, so an unrelated process that reused the pid is never signalled.
 */
async function restartService(home = kigHome(), env = process.env, id) {
  if (!SERVICES.includes(id)) throw new TypeError('invalid service');
  const L = layout(home), ps = ports(env);
  const record = readRecord(pidFile(L, id));
  if (record && await probe(id, record, ps)) {
    try { process.kill(record.pid, 'SIGTERM'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
    const end = Date.now() + 3000;
    while (Date.now() < end && await probe(id, record, ps, 100)) await new Promise((r) => setTimeout(r, 40));
    if (await probe(id, record, ps, 100)) throw new Error(`${id} did not stop`);
  }
  const launched = [];
  try { return await launch(home, env, id, launched); } catch (e) {
    for (const { child } of launched) if (child.exitCode === null) { try { child.kill('SIGTERM'); } catch {} }
    throw new Error(`${id} restart failed: ${String(e.message || e).split(/\r?\n/)[0]}`);
  }
}

async function start(home = kigHome(), env = process.env, { nodes = NODE_IDS } = {}) {
  const wanted = new Set(nodes);
  if ([...wanted].some((n) => !NODE_IDS.includes(n))) throw new TypeError('invalid node list');
  if (wanted.size !== NODE_IDS.length) throw new TypeError('M1 cluster requires nodes A, B and C');
  const L = layout(home), ps = ports(env);
  fs.mkdirSync(path.dirname(L.run.pid('cp')), { recursive: true });
  const existing = await status(home, env);
  if (existing.every((s) => s.healthy) && NODE_IDS.every((id) => fs.existsSync(controlFile(L, id)))) return existing;
  if (existing.some((s) => s.healthy || s.pid)) await stop(home, env);

  const launched = [];
  try {
    for (const id of SERVICES) await launch(home, env, id, launched);
    return status(home, env);
  } catch (e) {
    for (const { child } of launched.reverse()) {
      if (child.exitCode === null) {
        try { child.kill('SIGTERM'); } catch {}
      }
    }
    await stop(home, env).catch(() => {});
    throw new Error(`cluster start failed: ${String(e.message || e).split(/\r?\n/)[0]}`);
  }
}

const base = {
  options: {},
  run: async ({ io }) => {
    const rows = await status();
    for (const s of rows) io.out(`${s.id === 'cp' ? 'CP' : `Node ${s.id}`} ${s.healthy ? 'healthy' : 'stopped'}${s.pid ? ` pid=${s.pid}` : ''}\n`);
    return rows.every((s) => s.healthy) ? 0 : 1;
  },
};
const up = {
  ...base, name: 'up', describe: 'start the control plane and three local nodes', usage: 'usage: node kig.cjs up',
  run: async ({ io }) => {
    let rows;
    try { rows = await start(); }
    catch (e) {
      const { CommandError } = require('./main.cjs');
      throw new CommandError(String(e.message || e));
    }
    for (const s of rows) io.out(`${s.id === 'cp' ? 'CP' : `Node ${s.id}`} healthy pid=${s.pid}\n`);
    return 0;
  },
};
const down = {
  ...base, name: 'down', describe: 'stop the control plane and local nodes', usage: 'usage: node kig.cjs down',
  run: async ({ io }) => { await stop(); io.out('KIG stopped\n'); return 0; },
};
const statusCommand = { ...base, name: 'status', describe: 'show health of the control plane and local nodes', usage: 'usage: node kig.cjs status' };

module.exports = { name: 'supervisor', start, stop, status, restartService, up, down, statusCommand };
