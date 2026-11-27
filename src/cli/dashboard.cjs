'use strict';
// @ts-check
// `kig dashboard [--port <p>] [--no-open] [--evidence <dir>] | --status | --stop`
// Serves the static Trust & Verification Console (dashboard.html) and one
// evidence directory, read-only, on loopback only (docs/plans/cli_wrapper.md).
//
// Security boundaries:
//   - binds 127.0.0.1 only; requests whose Host is not 127.0.0.1/localhost:<port> are refused (DNS rebinding);
//   - GET/HEAD only; fixed routes: /, /dashboard.html, /health, /evidence/<file>;
//   - evidence files: one plain path segment, .json/.txt/.md only, must resolve (after symlinks)
//     inside the evidence directory and be a regular file; no listings, no stack traces.
// Round 1 isolation: nothing under src/adapter or track4_service.cjs requires this module.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { UsageError, CommandError } = require('./main.cjs');
const { safe } = require('./text.cjs');

const HOST = '127.0.0.1';
const DEFAULT_PORT = 5410;
const SERVICE = 'kig-dashboard';
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DASHBOARD_FILE = path.join(REPO_ROOT, 'dashboard.html');
const DEFAULT_EVIDENCE = path.join(REPO_ROOT, 'evidence', 'final-5410c49');
const EXPECTED_EVIDENCE = ['demo.json', 'bench-perf.json', 'bench-revocation.json', 'bench-detect.json', 'detect-practice.json', 'crash-test.json'];
const MIME = new Map([['.json', 'application/json; charset=utf-8'], ['.txt', 'text/plain; charset=utf-8'], ['.md', 'text/plain; charset=utf-8']]);
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;

const USAGE = 'usage: node kig.cjs dashboard [--port <port>] [--no-open] [--evidence <dir>]\n'
  + '       node kig.cjs dashboard --status\n'
  + '       node kig.cjs dashboard --stop\n'
  + '\n'
  + '  --port <port>     TCP port on 127.0.0.1 (1..65535, default 5410)\n'
  + '  --no-open         do not launch the system browser\n'
  + '  --evidence <dir>  evidence directory served read-only at /evidence/* (default evidence/final-5410c49)\n'
  + '  --status          report whether a dashboard server is running\n'
  + '  --stop            stop the running dashboard server\n'
  + '\n'
  + '  PID state: $KIG_DASHBOARD_PIDFILE, or <os tmpdir>/kig-dashboard.pid.json';

/** PID metadata lives outside the repo; the env override keeps tests isolated from a real server. */
const pidFile = () => process.env.KIG_DASHBOARD_PIDFILE || path.join(os.tmpdir(), 'kig-dashboard.pid.json');

/** Print a path; anything with control/bidi characters is shown in escaped, quoted form. */
const CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(0x1f)}${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}]`);
const showPath = (/** @type {string} */ p) => (CONTROL.test(p) || safe(p) !== JSON.stringify(p) ? safe(p) : p);

/** Repo-relative path with forward slashes when inside the repo, absolute otherwise. */
function displayDir(/** @type {string} */ dir) {
  const rel = path.relative(REPO_ROOT, dir);
  return rel && !rel.startsWith('..') && !path.isAbsolute(rel) ? rel.split(path.sep).join('/') : dir;
}

function parsePort(/** @type {unknown} */ v) {
  if (v === undefined) return DEFAULT_PORT;
  const s = String(v);
  if (!/^\d{1,5}$/.test(s)) throw new UsageError(`--port must be an integer 1..65535, got ${safe(s)}`);
  const n = Number(s);
  if (n < 1 || n > 65535) throw new UsageError(`--port must be an integer 1..65535, got ${n}`);
  return n;
}

/* ------------------------------------------------------------------ PID state */

/** @returns {{pid:number, host:string, port:number, evidenceDir:string, startedAt:string} | null} */
function readPid() {
  let raw;
  try { raw = fs.readFileSync(pidFile(), 'utf8'); } catch { return null; }
  try {
    const d = JSON.parse(raw);
    if (d && Number.isSafeInteger(d.pid) && d.pid > 0 && Number.isSafeInteger(d.port) && d.port >= 1 && d.port <= 65535) {
      return { pid: d.pid, host: HOST, port: d.port, evidenceDir: String(d.evidenceDir ?? ''), startedAt: String(d.startedAt ?? '') };
    }
  } catch { /* corrupt → treated as stale */ }
  return { pid: 0, host: HOST, port: 0, evidenceDir: '', startedAt: '' };
}

function writePid(/** @type {object} */ data) {
  const file = pidFile();
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function removePid(/** @type {number | null} */ onlyIfPid = null) {
  if (onlyIfPid !== null) { const cur = readPid(); if (!cur || cur.pid !== onlyIfPid) return; }
  try { fs.unlinkSync(pidFile()); } catch { /* already gone */ }
}

const alive = require('../core/proc.cjs').pidAlive;

/** GET /health on loopback; resolves to the parsed body or null. */
function probe(/** @type {number} */ port, timeoutMs = 1500) {
  const http = require('node:http');
  return new Promise((resolve) => {
    const req = http.get({ host: HOST, port, path: '/health', timeout: timeoutMs, headers: { host: `${HOST}:${port}` } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { if (body.length < 4096) body += c; });
      res.on('end', () => { try { resolve(res.statusCode === 200 ? JSON.parse(body) : null); } catch { resolve(null); } });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

/** The live dashboard described by the PID file, or null (stale state is cleaned up). */
async function current() {
  const st = readPid();
  if (!st) return null;
  if (!alive(st.pid)) { removePid(); return null; }
  const h = await probe(st.port);
  const ours = !!(h && h.service === SERVICE && h.pid === st.pid);
  return { ...st, healthy: ours };
}

/* ------------------------------------------------------------------ HTTP */

function evidenceState(/** @type {string} */ dir) {
  let isDir = false;
  try { isDir = fs.statSync(dir).isDirectory(); } catch { /* missing */ }
  const missing = isDir ? EXPECTED_EVIDENCE.filter((f) => !fs.existsSync(path.join(dir, f))) : EXPECTED_EVIDENCE.slice();
  return { present: isDir, missing };
}

/**
 * Map a request path under /evidence/ to a file inside `dir`, or an HTTP status to refuse with.
 * @returns {{ file: string, type: string } | { status: number }}
 */
function resolveEvidence(/** @type {string} */ dir, /** @type {string} */ rawRel) {
  let rel;
  try { rel = decodeURIComponent(rawRel); } catch { return { status: 400 }; }
  if (rel.includes('\0') || rel.includes('\\') || rel.split('/').some((s) => s === '..' || s === '.')) return { status: 400 };
  if (!SAFE_SEGMENT.test(rel)) return { status: 404 };   // one plain file name: no subdirectories, no dotfiles
  const type = MIME.get(path.extname(rel).toLowerCase());
  if (!type) return { status: 404 };
  const resolved = path.resolve(dir, rel);
  const within = (/** @type {string} */ base, /** @type {string} */ p) => { const r = path.relative(base, p); return r !== '' && !r.startsWith('..') && !path.isAbsolute(r); };
  if (!within(dir, resolved)) return { status: 403 };
  let real, realDir;
  try { real = fs.realpathSync(resolved); realDir = fs.realpathSync(dir); } catch { return { status: 404 }; }
  if (!within(realDir, real)) return { status: 403 };    // symlink escaping the evidence directory
  try { const st = fs.statSync(real); if (!st.isFile() || st.size > MAX_EVIDENCE_BYTES) return { status: 404 }; } catch { return { status: 404 }; }
  return { file: real, type };
}

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store',
};
// dashboard.html is fully self-contained (inline CSS/JS/SVG, no network); the CSP enforces that.
const HTML_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
  + "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** @param {{ port: number, evidenceDir: string }} cfg */
function createHandler(cfg) {
  const allowedHosts = new Set([`${HOST}:${cfg.port}`, `localhost:${cfg.port}`]);
  return async (/** @type {import('node:http').IncomingMessage} */ req, /** @type {import('node:http').ServerResponse} */ res) => {
    const head = req.method === 'HEAD';
    const send = (/** @type {number} */ status, /** @type {string | Buffer} */ body, /** @type {Record<string,string>} */ headers = {}) => {
      const buf = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
      res.writeHead(status, { ...BASE_HEADERS, 'Content-Length': String(buf.length), ...headers });
      res.end(head ? undefined : buf);
    };
    const text = (/** @type {number} */ status, /** @type {string} */ msg, /** @type {Record<string,string>} */ extra = {}) =>
      send(status, `${msg}\n`, { 'Content-Type': 'text/plain; charset=utf-8', ...extra });
    try {
      if (req.method !== 'GET' && !head) return text(405, 'Method Not Allowed', { Allow: 'GET, HEAD' });
      if (!allowedHosts.has(String(req.headers.host || '').toLowerCase())) return text(403, 'Forbidden');
      const url = String(req.url || '');
      if (!url.startsWith('/')) return text(400, 'Bad Request');
      const p = url.split('?')[0].split('#')[0];

      if (p === '/' || p === '/dashboard.html') {
        let html;
        try { html = await fs.promises.readFile(DASHBOARD_FILE); } catch { return text(404, 'Not Found'); }
        return send(200, html, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': HTML_CSP, 'X-Frame-Options': 'DENY' });
      }
      if (p === '/health') {
        const ev = evidenceState(cfg.evidenceDir);
        return send(200, JSON.stringify({ ok: true, service: SERVICE, pid: process.pid, port: cfg.port, evidence_dir: displayDir(cfg.evidenceDir), evidence_present: ev.present }),
          { 'Content-Type': 'application/json; charset=utf-8' });
      }
      if (p.startsWith('/evidence/')) {
        const r = resolveEvidence(cfg.evidenceDir, p.slice('/evidence/'.length));
        if ('status' in r) return text(r.status, r.status === 400 ? 'Bad Request' : r.status === 403 ? 'Forbidden' : 'Not Found');
        let body;
        try { body = await fs.promises.readFile(r.file); } catch { return text(404, 'Not Found'); }
        return send(200, body, { 'Content-Type': r.type });
      }
      return text(404, 'Not Found');
    } catch {
      if (!res.headersSent) text(500, 'Internal Server Error'); else res.destroy();
    }
  };
}

/* ------------------------------------------------------------------ browser */

function openBrowser(/** @type {string} */ url, /** @type {{ err: (s: string) => void }} */ io) {
  const { spawn } = require('node:child_process');
  /** @type {[string, string[], object]} */
  const cmd = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url], { windowsHide: true }]
    : process.platform === 'darwin' ? ['open', [url], {}]
      : ['xdg-open', [url], {}];
  try {
    const child = spawn(cmd[0], cmd[1], { detached: true, stdio: 'ignore', ...cmd[2] });
    child.on('error', () => io.err(`[WARN] could not launch a browser; open ${url} manually\n`));
    child.unref();
  } catch {
    io.err(`[WARN] could not launch a browser; open ${url} manually\n`);
  }
}

/* ------------------------------------------------------------------ subcommands */

async function status(/** @type {{ out: (s: string) => void }} */ io) {
  const cur = await current();
  if (!cur) { io.out('[KIG] Dashboard: stopped\n'); return 0; }
  if (!cur.healthy) {
    io.out(`[KIG] Dashboard: PID ${cur.pid} is alive but not answering /health on port ${cur.port}\n`);
    return 1;
  }
  io.out(`[KIG] Dashboard: running\n[KIG] URL:      http://${HOST}:${cur.port}\n[KIG] PID:      ${cur.pid}\n`
    + `[KIG] Evidence: ${showPath(cur.evidenceDir)}\n[KIG] Started:  ${showPath(cur.startedAt)}\n`);
  return 0;
}

async function stop(/** @type {{ out: (s: string) => void }} */ io) {
  const st = readPid();
  if (!st) { io.out('[KIG] Dashboard: not running\n'); return 0; }
  if (!alive(st.pid)) { removePid(); io.out('[KIG] Dashboard: not running (removed stale PID file)\n'); return 0; }
  // Guard against PID reuse: only signal a process that answers /health as this service with this PID.
  const h = await probe(st.port);
  if (!(h && h.service === SERVICE && h.pid === st.pid)) {
    throw new CommandError(`PID ${st.pid} does not answer as ${SERVICE} on port ${st.port}; not signalling it. Remove ${pidFile()} if it is stale`);
  }
  try { process.kill(st.pid, 'SIGTERM'); } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code !== 'ESRCH') throw new CommandError(`could not signal PID ${st.pid}`);
  }
  const deadline = Date.now() + 5000;
  while (alive(st.pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
  if (alive(st.pid)) throw new CommandError(`PID ${st.pid} did not exit within 5 s`);
  removePid(st.pid);   // the server removes it on graceful exit; on Windows SIGTERM is a hard kill
  io.out(`[KIG] Dashboard stopped (PID ${st.pid})\n`);
  return 0;
}

/**
 * @param {{ port: number, open: boolean, evidenceDir: string }} cfg
 * @param {{ out: (s: string) => void, err: (s: string) => void }} io
 */
async function serve(cfg, io) {
  if (!fs.existsSync(DASHBOARD_FILE)) throw new CommandError(`dashboard.html not found at ${DASHBOARD_FILE}; regenerate or restore it first`);
  const running = await current();
  if (running && running.healthy) throw new CommandError(`dashboard already running at http://${HOST}:${running.port} (PID ${running.pid}); use --status or --stop`);
  if (running) removePid();   // live PID that is not our service: PID reused by another process

  const ev = evidenceState(cfg.evidenceDir);
  const http = require('node:http');
  const server = http.createServer(createHandler(cfg));
  server.keepAliveTimeout = 2000;
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  await new Promise((resolve, reject) => {
    server.once('error', (e) => {
      const code = /** @type {NodeJS.ErrnoException} */ (e).code;
      if (code === 'EADDRINUSE') reject(new CommandError(`port ${cfg.port} is already in use; try --port <other> or: node kig.cjs dashboard --stop`));
      else if (code === 'EACCES') reject(new CommandError(`not permitted to listen on port ${cfg.port}; try --port <other>`));
      else reject(new CommandError(`could not start the dashboard server (${code || 'error'})`));
    });
    server.listen(cfg.port, HOST, () => resolve(undefined));
  });

  const url = `http://${HOST}:${cfg.port}`;
  writePid({ pid: process.pid, host: HOST, port: cfg.port, evidenceDir: displayDir(cfg.evidenceDir), startedAt: new Date().toISOString() });
  const evLine = !ev.present ? `${showPath(displayDir(cfg.evidenceDir))} (missing)`
    : ev.missing.length ? `${showPath(displayDir(cfg.evidenceDir))} (present; missing ${ev.missing.join(', ')})`
      : `${showPath(displayDir(cfg.evidenceDir))} (verified)`;
  io.out(`[KIG] Trust & Verification Console\n[KIG] URL:      ${url}\n[KIG] Evidence: ${evLine}\n[KIG] PID:      ${process.pid}\n`
    + '[KIG] Press Ctrl+C to stop, or run: node kig.cjs dashboard --stop\n');
  if (!ev.present) io.err('[WARN] evidence directory not found: the dashboard will use its embedded fallback data or files you drag and drop\n');
  else if (ev.missing.length) io.err(`[WARN] evidence directory lacks ${ev.missing.join(', ')}; /evidence/ requests for them return 404\n`);
  if (cfg.open) openBrowser(`${url}/`, io);

  return new Promise((resolve) => {
    let done = false;
    const shutdown = (/** @type {string} */ sig) => {
      if (done) return;
      done = true;
      process.off('SIGINT', onInt); process.off('SIGTERM', onTerm);
      server.close(() => {
        removePid(process.pid);
        io.out(`[KIG] Dashboard stopped (${sig})\n`);
        resolve(0);
      });
      server.closeAllConnections();
    };
    const onInt = () => shutdown('SIGINT');
    const onTerm = () => shutdown('SIGTERM');
    process.on('SIGINT', onInt);
    process.on('SIGTERM', onTerm);
  });
}

module.exports = {
  name: 'dashboard',
  describe: 'serve the Trust & Verification Console (dashboard.html) on 127.0.0.1',
  usage: USAGE,
  options: {
    port: { type: 'string' },
    'no-open': { type: 'boolean' },
    evidence: { type: 'string' },
    status: { type: 'boolean' },
    stop: { type: 'boolean' },
  },
  async run({ values, positionals, io }) {
    if (positionals.length) throw new UsageError(`unexpected argument ${safe(positionals[0])}`);
    const serveFlags = ['port', 'no-open', 'evidence'].filter((k) => values[k] !== undefined);
    if (values.status && values.stop) throw new UsageError('--status and --stop are mutually exclusive');
    if ((values.status || values.stop) && serveFlags.length) {
      throw new UsageError(`--${values.status ? 'status' : 'stop'} cannot be combined with --${serveFlags[0]}`);
    }
    if (values.status) return status(io);
    if (values.stop) return stop(io);
    const port = parsePort(values.port);
    if (values.evidence !== undefined && (values.evidence === '' || values.evidence.includes('\0'))) throw new UsageError('--evidence needs a directory path');
    const evidenceDir = values.evidence !== undefined ? path.resolve(values.evidence) : DEFAULT_EVIDENCE;
    return serve({ port, open: !values['no-open'], evidenceDir }, io);
  },
  // exported for unit tests
  _internal: { resolveEvidence, parsePort, pidFile },
};
