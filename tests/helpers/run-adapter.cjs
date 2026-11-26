'use strict';
// Spawn the Round 1 adapter exactly like the worker / validate.py: a fresh
// `node track4_service.cjs` per request, cwd = repo root, one JSON object on
// stdin then EOF, state dir via TRACK4_STATE_DIR and the temp-dir variables.
const { spawn } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const ENTRY = path.join(ROOT, 'track4_service.cjs');
const FAIL_LINE = 'Request failed; inspect team application locally.\n';

/**
 * @param {string|null} stateDir null → TRACK4_STATE_DIR is not set (os.tmpdir() fallback)
 * @param {object|Buffer|string} input object → JSON; Buffer/string sent as-is
 * @param {{ timeoutMs?: number, env?: Record<string,string> }} [o]
 * @returns {Promise<{ code: number|null, signal: string|null, stdout: string, stderr: string,
 *                     json: any, timedOut: boolean, ms: number }>}
 */
function runAdapter(stateDir, input, { timeoutMs = 8000, env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const childEnv = { ...process.env, ...env };
    delete childEnv.TRACK4_STATE_DIR;
    delete childEnv.NODE_TEST_CONTEXT; // don't let the child think it's a node:test worker
    if (stateDir !== null) Object.assign(childEnv, { TRACK4_STATE_DIR: stateDir, TMPDIR: stateDir, TEMP: stateDir, TMP: stateDir });

    const t0 = Date.now();
    const child = spawn(process.execPath, [ENTRY], { cwd: ROOT, env: childEnv, stdio: ['pipe', 'pipe', 'pipe'] });
    const out = [], err = [];
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.stdin.on('error', () => { /* EPIPE if the adapter stops reading early */ });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString('utf8');
      const stderr = Buffer.concat(err).toString('utf8');
      let json = null;
      try { json = JSON.parse(stdout); } catch { /* not JSON */ }
      resolve({ code, signal, stdout, stderr, json, timedOut, ms: Date.now() - t0 });
    });
    const data = Buffer.isBuffer(input) ? input : Buffer.from(typeof input === 'string' ? input : JSON.stringify(input));
    child.stdin.end(data);
  });
}

module.exports = { runAdapter, ROOT, ENTRY, FAIL_LINE };
