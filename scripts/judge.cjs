'use strict';
// Run a command inside the judging-container replica (Windows, WSL, Linux, macOS):
//   linux/amd64 (x86-64), Node 24.11.1, --read-only root, --network none, tmpfs /tmp,
//   repo copied (not mounted) to /app, toolkit to /toolkit.
// Usage: node scripts/judge.cjs <command...>    e.g. node scripts/judge.cjs node kig.cjs compat
// Needs Docker (Docker Desktop on Windows/macOS). Native on x86-64 hosts; on ARM hosts
// (e.g. Apple Silicon) Docker emulates amd64: correct but slow, never use its timings.
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const TOOLKIT_DIR = path.resolve(REPO, process.env.TOOLKIT_DIR || path.join('..', 'Track-4-Toolkit'));
const IMAGE = process.env.KIG_JUDGE_IMAGE || 'kig-judge-run';

const args = process.argv.slice(2);
if (args.length === 0) {
  process.stderr.write('usage: node scripts/judge.cjs <command...>\n');
  process.exit(2);
}
if (!fs.existsSync(path.join(TOOLKIT_DIR, 'validate.py'))) {
  process.stderr.write(`toolkit not found at ${TOOLKIT_DIR} (set TOOLKIT_DIR)\n`);
  process.exit(2);
}

const docker = (argv, opts = {}) => spawnSync('docker', argv, { stdio: 'inherit', ...opts });

const build = docker([
  'build', '--quiet', '--platform', 'linux/amd64',
  '-f', path.join(REPO, 'tools', 'judge', 'Dockerfile'),
  '--build-context', `toolkit=${TOOLKIT_DIR}`,
  '-t', IMAGE, REPO,
], { stdio: ['ignore', 'ignore', 'inherit'] });
if (build.error) {
  process.stderr.write('docker not found: install/start Docker Desktop\n');
  process.exit(2);
}
if (build.status !== 0) process.exit(build.status || 2);

const run = docker([
  'run', '--rm', '-i',
  '--platform', 'linux/amd64',
  '--read-only',
  '--network', 'none',
  '--tmpfs', '/tmp:rw,exec,mode=1777',
  '-e', 'HOME=/tmp',
  IMAGE, ...args,
]);
process.exit(run.status === null ? 1 : run.status);
