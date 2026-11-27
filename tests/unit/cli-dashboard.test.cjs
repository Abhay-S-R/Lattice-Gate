'use strict';
// `kig dashboard` (docs/plans/cli_wrapper.md §6): flags, loopback server, route allowlist, PID lifecycle.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { runKig, ROOT } = require('../helpers/run-kig.cjs');
// Load through the router (as kig.cjs does) so the main.cjs ⇄ command require cycle resolves in order.
const dashboard = require('../../src/cli/main.cjs').COMMANDS.get('dashboard');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-dash-test-'));
const PIDFILE = path.join(tmp, 'dashboard.pid.json');
const env = { KIG_DASHBOARD_PIDFILE: PIDFILE };
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

async function freePort() {
  for (let i = 0; i < 20; i++) {
    const p = 10000 + Math.floor(Math.random() * 15000);
    const s = net.createServer();
    const ok = await new Promise((resolve) => { s.once('error', () => resolve(false)); s.listen(p, '127.0.0.1', () => s.close(() => resolve(true))); });
    if (ok) return p;
  }
  throw new Error('no free port');
}

/** Raw request: the path is sent exactly as given (no client-side dot-segment normalisation). */
function request(port, reqPath, { method = 'GET', host = `127.0.0.1:${port}` } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: reqPath, method, headers: { host }, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

function startServer(args) {
  const childEnv = { ...process.env, ...env };
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, ['kig.cjs', 'dashboard', '--no-open', ...args], { cwd: ROOT, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { err += c; });
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  const ready = new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`server did not start: ${out}${err}`)), 15000);
    child.stdout.on('data', () => { if (/Press Ctrl\+C/.test(out)) { clearTimeout(t); resolve(undefined); } });
    exited.then((code) => { clearTimeout(t); reject(new Error(`server exited ${code}: ${out}${err}`)); });
  });
  return { child, ready, exited, output: () => out + err };
}

test('--help exits 0 and prints usage', () => {
  const r = runKig(['dashboard', '--help'], { env });
  assert.equal(r.code, 0);
  assert.match(r.stdout, /usage: node kig\.cjs dashboard/);
  assert.match(r.stdout, /--no-open/);
});

test('dashboard is listed by kig help', () => {
  assert.match(runKig(['help']).stdout, /\bdashboard\b/);
});

test('--status reports stopped when nothing is running', () => {
  fs.rmSync(PIDFILE, { force: true });
  const r = runKig(['dashboard', '--status'], { env });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /stopped/);
});

test('--status cleans up a stale PID file', () => {
  fs.writeFileSync(PIDFILE, JSON.stringify({ pid: 2147483000, host: '127.0.0.1', port: 5410, evidenceDir: 'x', startedAt: 'y' }));
  const r = runKig(['dashboard', '--status'], { env });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /stopped/);
  assert.equal(fs.existsSync(PIDFILE), false);
});

test('--stop with no server is a clean no-op', () => {
  fs.rmSync(PIDFILE, { force: true });
  const r = runKig(['dashboard', '--stop'], { env });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /not running/);
});

test('invalid --port values exit 2', () => {
  for (const p of ['abc', '0', '70000', '-1', '80.5', '']) {
    const r = runKig(['dashboard', '--no-open', `--port=${p}`], { env });
    assert.equal(r.code, 2, `port ${JSON.stringify(p)}: ${r.stderr}`);
    assert.match(r.stderr, /usage: node kig\.cjs dashboard/);
  }
});

test('mutually exclusive flags exit 2', () => {
  for (const args of [['--status', '--stop'], ['--status', '--port', '5411'], ['--stop', '--no-open'], ['extra-arg']]) {
    const r = runKig(['dashboard', ...args], { env });
    assert.equal(r.code, 2, `${args.join(' ')}: ${r.stderr}`);
  }
});

test('resolveEvidence refuses traversal, odd names and unlisted extensions', () => {
  const { resolveEvidence } = dashboard._internal;
  const dir = path.join(ROOT, 'evidence', 'final-5410c49');
  assert.ok('file' in resolveEvidence(dir, 'demo.json'));
  for (const bad of ['../package.json', '%2e%2e/kig.cjs', '..%2fpackage.json', '..%5cpackage.json', 'a%00.json', '%E0%A4%A', '/etc/passwd',
    'sub/demo.json', '.hidden.json', 'test.cjs', 'x.db', '', 'C:%5cWindows%5cwin.ini']) {
    const r = resolveEvidence(dir, bad);
    assert.ok('status' in r && [400, 403, 404].includes(r.status), `${bad} → ${JSON.stringify(r)}`);
  }
});

test('server: routes, allowlist, health, status and stop', async (t) => {
  fs.rmSync(PIDFILE, { force: true });
  const port = await freePort();
  const srv = startServer(['--port', String(port)]);
  t.after(() => { if (srv.child.exitCode === null) srv.child.kill(); });
  await srv.ready;
  assert.match(srv.output(), new RegExp(`URL:\\s+http://127\\.0\\.0\\.1:${port}`));
  assert.match(srv.output(), /Evidence: evidence\/final-5410c49 \(verified\)/);

  const root = await request(port, '/');
  assert.equal(root.status, 200);
  assert.match(root.headers['content-type'], /^text\/html/);
  assert.equal(root.headers['cache-control'], 'no-store');
  assert.match(root.headers['content-security-policy'], /default-src 'none'/);
  assert.match(root.body, /KIG Trust Console/);
  assert.equal((await request(port, '/dashboard.html')).status, 200);
  const headRes = await request(port, '/', { method: 'HEAD' });
  assert.equal(headRes.status, 200);
  assert.equal(headRes.body, '');

  const health = await request(port, '/health');
  assert.equal(health.status, 200);
  const h = JSON.parse(health.body);
  assert.deepEqual({ ok: h.ok, service: h.service, port: h.port, evidence_dir: h.evidence_dir, evidence_present: h.evidence_present },
    { ok: true, service: 'kig-dashboard', port, evidence_dir: 'evidence/final-5410c49', evidence_present: true });
  assert.equal(h.pid, srv.child.pid);

  const demo = await request(port, '/evidence/demo.json');
  assert.equal(demo.status, 200);
  assert.match(demo.headers['content-type'], /^application\/json/);
  assert.equal(JSON.parse(demo.body).total_steps, 12);
  assert.match((await request(port, '/evidence/SUMMARY.md')).headers['content-type'], /^text\/plain/);

  for (const p of ['/evidence/../package.json', '/evidence/%2e%2e/kig.cjs', '/evidence/..%2f..%2fkig.cjs', '/evidence/%2e%2e%5cpackage.json',
    '/src/core/policy.cjs', '/evidence/', '/evidence', '/.git/config', '/package.json', '/evidence/nope.json', '/evidence/a%00.json', '//etc/passwd']) {
    const r = await request(port, p);
    assert.ok([400, 403, 404].includes(r.status), `${p} → ${r.status}`);
    assert.doesNotMatch(r.body, /"name"\s*:\s*"key-identity-guard"|require\(|at .*\.cjs:\d+/, `${p} leaked content`);
  }
  assert.equal((await request(port, '/', { method: 'POST' })).status, 405);
  assert.equal((await request(port, '/', { method: 'DELETE' })).status, 405);
  assert.equal((await request(port, '/', { host: 'evil.example:80' })).status, 403, 'DNS-rebinding Host is refused');
  assert.equal((await request(port, '/', { host: `localhost:${port}` })).status, 200);

  const pid = JSON.parse(fs.readFileSync(PIDFILE, 'utf8'));
  assert.equal(pid.pid, srv.child.pid);
  assert.equal(pid.port, port);

  const st = runKig(['dashboard', '--status'], { env });
  assert.equal(st.code, 0, st.stderr);
  assert.match(st.stdout, /running/);
  assert.match(st.stdout, new RegExp(`http://127\\.0\\.0\\.1:${port}`));
  assert.match(st.stdout, new RegExp(`PID:\\s+${srv.child.pid}`));

  const second = runKig(['dashboard', '--no-open', '--port', String(await freePort())], { env, timeoutMs: 15000 });
  assert.equal(second.code, 1, 'a second instance is refused');
  assert.match(second.stderr, /already running/);

  const stop = runKig(['dashboard', '--stop'], { env });
  assert.equal(stop.code, 0, stop.stderr);
  assert.match(stop.stdout, /stopped/);
  await srv.exited;
  assert.equal(fs.existsSync(PIDFILE), false, 'PID file removed');
  assert.match(runKig(['dashboard', '--status'], { env }).stdout, /stopped/);
});

test('port already in use exits 1 with a clear message', async (t) => {
  fs.rmSync(PIDFILE, { force: true });
  const port = await freePort();
  const blocker = net.createServer();
  await new Promise((resolve) => blocker.listen(port, '127.0.0.1', resolve));
  t.after(() => blocker.close());
  const r = runKig(['dashboard', '--no-open', '--port', String(port)], { env, timeoutMs: 15000 });
  assert.equal(r.code, 1);
  assert.match(r.stderr, new RegExp(`port ${port} is already in use`));
  assert.equal(fs.existsSync(PIDFILE), false);
});

test('missing evidence directory warns but still serves', async (t) => {
  fs.rmSync(PIDFILE, { force: true });
  const port = await freePort();
  const srv = startServer(['--port', String(port), '--evidence', path.join(tmp, 'no-such-dir')]);
  t.after(() => { if (srv.child.exitCode === null) srv.child.kill(); });
  await srv.ready;
  assert.match(srv.output(), /\(missing\)/);
  assert.equal(JSON.parse((await request(port, '/health')).body).evidence_present, false);
  assert.equal((await request(port, '/evidence/demo.json')).status, 404);
  assert.equal((await request(port, '/')).status, 200);
  assert.equal(runKig(['dashboard', '--stop'], { env }).code, 0);
  await srv.exited;
});
