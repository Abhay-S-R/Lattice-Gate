'use strict';
// Host-side evidence collector (Phase 7 Task 7.0, P7-D1).
// Runs verification checks inside the native linux/amd64 judging replica (or locally
// with --no-judge) and writes outputs + SUMMARY.md to evidence/final-<commit>/.
//
// Usage:
//   node scripts/collect-evidence.cjs [--only <id1,id2,...>] [--out <dir>] [--no-judge] [--allow-dirty]
const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const TOOLKIT_DIR = path.resolve(REPO, process.env.TOOLKIT_DIR || path.join('..', 'Track-4-Toolkit'));
const IMAGE = process.env.KIG_JUDGE_IMAGE || 'kig-judge-run';

function git(args) {
  const r = spawnSync('git', ['-C', REPO, ...args], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : '';
}

function buildChecks(inJudge) {
  const practiceDir = inJudge ? '/toolkit/practice' : path.join(TOOLKIT_DIR, 'practice');
  return [
    { id: 'compat', ext: 'txt', cmd: ['node', 'kig.cjs', 'compat'] },
    { id: 'validate', ext: 'txt', cmd: ['node', 'scripts/validate.cjs'] },
    { id: 'test', ext: 'txt', cmd: ['npm', 'test'] },
    { id: 'adapter-walkthrough', ext: 'txt', cmd: ['node', 'scripts/walkthrough-adapter.cjs'] },
    { id: 'demo', ext: 'json', cmd: ['node', 'kig.cjs', 'demo', '--json'] },
    { id: 'bench-perf', ext: 'json', cmd: ['node', 'kig.cjs', 'bench', 'perf', '--json'] },
    { id: 'bench-revocation', ext: 'json', cmd: ['node', 'kig.cjs', 'bench', 'revocation', '--n', '100', '--seed', '2026', '--out', '/tmp/kig-revocation-bench.json', '--json'] },
    { id: 'crash-test', ext: 'json', cmd: ['node', 'kig.cjs', 'crash-test', '--json'] },
    { id: 'detect-practice', ext: 'json', cmd: ['node', 'kig.cjs', 'detect', '--events', `${practiceDir}/events.csv`, '--approvals', `${practiceDir}/approvals.json`, '--json'] },
    { id: 'bench-detect', ext: 'json', cmd: ['node', 'kig.cjs', 'bench', 'detect', '--seeds', '101,102,103', '--holdout', '201-205', '--out', '/tmp/kig-detect-bench.json', '--json'] },
    { id: 'msg-demo', ext: 'txt', cmd: ['node', 'kig.cjs', 'msg', 'demo', '--seed', '2026'] },
  ];
}

function ensureJudgeImage() {
  if (!fs.existsSync(path.join(TOOLKIT_DIR, 'validate.py'))) {
    process.stderr.write(`collect-evidence: toolkit not found at ${TOOLKIT_DIR} (set TOOLKIT_DIR)\n`);
    process.exit(2);
  }
  process.stdout.write(`Building ${IMAGE} (linux/amd64 judging replica)...\n`);
  const build = spawnSync('docker', [
    'build', '--quiet', '--platform', 'linux/amd64',
    '-f', path.join(REPO, 'tools', 'judge', 'Dockerfile'),
    '--build-context', `toolkit=${TOOLKIT_DIR}`,
    '-t', IMAGE, REPO,
  ], { stdio: ['ignore', 'ignore', 'inherit'] });
  if (build.error || build.status !== 0) {
    process.stderr.write('collect-evidence: docker build failed (is Docker Desktop running?)\n');
    process.exit(2);
  }
}

function runCheck(check, inJudge) {
  const t0 = Date.now();
  let r;
  if (inJudge) {
    r = spawnSync('docker', [
      'run', '--rm', '-i',
      '--platform', 'linux/amd64',
      '--read-only',
      '--network', 'none',
      '--tmpfs', '/tmp:rw,exec,mode=1777',
      '-e', 'HOME=/tmp',
      IMAGE, ...check.cmd,
    ], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } else {
    const [bin, ...rest] = check.cmd;
    const exe = bin === 'node' ? process.execPath : bin;
    r = spawnSync(exe, rest, {
      cwd: REPO, encoding: 'utf8', shell: bin === 'npm' && process.platform === 'win32',
      maxBuffer: 64 * 1024 * 1024,
    });
  }
  const durationMs = Date.now() - t0;
  const code = r.status === null ? 1 : r.status;
  return { code, stdout: r.stdout || '', stderr: r.stderr || '', durationMs };
}

function main() {
  let parsed;
  try {
    parsed = parseArgs({
      options: {
        only: { type: 'string' },
        out: { type: 'string' },
        'no-judge': { type: 'boolean', default: false },
        'allow-dirty': { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
      strict: true,
    });
  } catch (e) {
    process.stderr.write(`collect-evidence: ${e.message}\n`);
    process.exit(2);
  }
  if (parsed.values.help) {
    process.stdout.write('usage: node scripts/collect-evidence.cjs [--only <id1,id2,...>] [--out <dir>] [--no-judge] [--allow-dirty]\n');
    process.exit(0);
  }

  const dirty = git(['status', '--porcelain', '-uno']);
  if (dirty && !parsed.values['allow-dirty']) {
    process.stderr.write('collect-evidence: working tree has uncommitted tracked changes (commit first or pass --allow-dirty)\n');
    process.exit(2);
  }

  const inJudge = !parsed.values['no-judge'];
  const allChecks = buildChecks(inJudge);
  let selected = allChecks;
  if (parsed.values.only) {
    const want = parsed.values.only.split(',').map((s) => s.trim()).filter(Boolean);
    const byId = new Map(allChecks.map((c) => [c.id, c]));
    for (const id of want) {
      if (!byId.has(id)) {
        process.stderr.write(`collect-evidence: unknown check '${id}' (valid: ${allChecks.map((c) => c.id).join(', ')})\n`);
        process.exit(2);
      }
    }
    selected = want.map((id) => byId.get(id));
  }

  const commit = git(['rev-parse', '--short', 'HEAD']) || 'nogit';
  const outDir = parsed.values.out ? path.resolve(parsed.values.out) : path.join(REPO, 'evidence', `final-${commit}`);
  fs.mkdirSync(outDir, { recursive: true });

  if (inJudge) ensureJudgeImage();

  const startedUtc = new Date().toISOString();
  const rows = [];
  for (const check of selected) {
    process.stdout.write(`[RUN ] ${check.id} (${check.cmd.join(' ')})...\n`);
    const res = runCheck(check, inJudge);
    const file = `${check.id}.${check.ext}`;
    const body = check.ext === 'json' ? res.stdout : `${res.stdout}${res.stderr}`;
    fs.writeFileSync(path.join(outDir, file), body, 'utf8');
    let jsonValid = true;
    if (check.ext === 'json' && res.code === 0) {
      try { JSON.parse(res.stdout); } catch { jsonValid = false; }
    }
    const pass = res.code === 0 && jsonValid;
    const status = pass ? 'PASS' : 'FAIL';
    process.stdout.write(`[${status}] ${check.id} (${(res.durationMs / 1000).toFixed(1)} s, exit ${res.code}) -> ${file}\n`);
    rows.push({
      id: check.id,
      cmd: check.cmd.join(' '),
      exit: res.code,
      seconds: (res.durationMs / 1000).toFixed(1),
      file,
      status,
    });
  }

  const failed = rows.filter((r) => r.status !== 'PASS').length;
  const summaryLines = [
    `# Evidence Summary (\`${commit}\`)`,
    '',
    `- **Commit:** \`${commit}\`${dirty ? ' *(dirty working tree — `--allow-dirty`)*' : ''}`,
    `- **Started (UTC):** \`${startedUtc}\``,
    `- **Completed (UTC):** \`${new Date().toISOString()}\``,
    `- **Environment:** ${inJudge ? 'linux/amd64 judging replica (`--read-only`, `--network none`, Node 24.11.1, Python 3.12 + pqcrypto 0.4.0)' : '**native host (not the judging replica)**'}`,
    `- **Checks Passed:** ${rows.length - failed} / ${rows.length}`,
    '',
    '| Check | Command | Exit | Duration (s) | Artifact | Status |',
    '|---|---|---:|---:|---|---|',
    ...rows.map((r) => `| \`${r.id}\` | \`${r.cmd}\` | ${r.exit} | ${r.seconds} | [${r.file}](${r.file}) | **${r.status}** |`),
    '',
  ];
  fs.writeFileSync(path.join(outDir, 'SUMMARY.md'), summaryLines.join('\n'), 'utf8');
  process.stdout.write(`Summary written to ${path.join(outDir, 'SUMMARY.md')} (${failed} failed)\n`);
  process.exit(failed);
}

main();
