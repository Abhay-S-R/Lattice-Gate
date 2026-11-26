'use strict';
// Run the organizer toolkit's validate.py against the root adapter and keep the
// output as evidence (features P0-09). Cross-platform (Windows/WSL/Linux/container).
// Exit status is validate.py's: 0 pass, 1 behaviour, 2 setup/execution, 3 format.
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const TOOLKIT_DIR = path.resolve(REPO, process.env.TOOLKIT_DIR ||
  (fs.existsSync('/toolkit/validate.py') ? '/toolkit' : path.join('..', 'Track-4-Toolkit')));
const VALIDATE = path.join(TOOLKIT_DIR, 'validate.py');
if (!fs.existsSync(VALIDATE)) {
  process.stderr.write(`validate.py not found in ${TOOLKIT_DIR} (set TOOLKIT_DIR)\n`);
  process.exit(2);
}

// python3 on Linux/macOS, python (or the py launcher) on Windows.
const candidates = process.platform === 'win32' ? [['python'], ['py', '-3'], ['python3']] : [['python3'], ['python']];
const python = candidates.find(([cmd, ...rest]) =>
  spawnSync(cmd, [...rest, '-c', 'import sys; sys.exit(sys.version_info < (3, 10))']).status === 0);
if (!python) {
  process.stderr.write('Python 3.10+ not found (needed only for the toolkit validator)\n');
  process.exit(2);
}

const [cmd, ...pre] = python;
const r = spawnSync(cmd, [...pre, VALIDATE, '--entry', path.join(REPO, 'track4_service.cjs')], { encoding: 'utf8' });
const output = (r.stdout || '') + (r.stderr || '');
process.stdout.write(output);
const status = r.status === null ? 2 : r.status;

const commit = spawnSync('git', ['-C', REPO, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' });
const outDir = process.env.KIG_EVIDENCE_DIR || path.join(REPO, 'evidence');
try {
  fs.mkdirSync(outDir, { recursive: true });
  const file = path.join(outDir, `validate-${commit.status === 0 ? commit.stdout.trim() : 'nogit'}.txt`);
  fs.writeFileSync(file, output);
  process.stdout.write(`evidence: ${file} (exit ${status})\n`);
} catch {
  // Read-only checkout (judging replica): output printed only.
}
process.exit(status);
