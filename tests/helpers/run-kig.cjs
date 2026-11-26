'use strict';
// Spawn the operator CLI: node kig.cjs <args...>, cwd = repo root.
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

/**
 * @param {string[]} args
 * @param {{ env?: Record<string,string>, timeoutMs?: number }} [o]
 * @returns {{ code: number|null, stdout: string, stderr: string }}
 */
function runKig(args, { env = {}, timeoutMs = 60000 } = {}) {
  const childEnv = { ...process.env, ...env };
  delete childEnv.NODE_TEST_CONTEXT;
  const r = spawnSync(process.execPath, ['kig.cjs', ...args], {
    cwd: ROOT, env: childEnv, encoding: 'utf8', timeout: timeoutMs,
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

module.exports = { runKig, ROOT };
