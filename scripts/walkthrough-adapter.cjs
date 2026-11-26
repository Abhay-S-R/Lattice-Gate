'use strict';
// Self-contained Round 1 adapter + Phase 2 operator audit walkthrough (Task 7.0).
// Runs cleanly inside the read-only judging replica using os.tmpdir() only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const REPO = path.resolve(__dirname, '..');
const SERVICE = path.join(REPO, 'track4_service.cjs');
const KIG = path.join(REPO, 'kig.cjs');
const MARKER = 'SYNTHETIC-MARKER-NEVER-PERSIST-701';

function walkFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-walkthrough-'));
  const stateDir = path.join(root, 'state');
  const keyDir = path.join(root, 'opkeys');
  const anchorFile = path.join(root, 'adapter-anchor.json');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const captured = [];

  const callAdapter = (label, req) => {
    const r = spawnSync(process.execPath, [SERVICE], {
      cwd: REPO,
      env: { ...process.env, TRACK4_STATE_DIR: stateDir },
      input: JSON.stringify(req),
      encoding: 'utf8',
      timeout: 15000,
    });
    captured.push(r.stdout || '', r.stderr || '');
    assert.equal(r.status, 0, `${label} exited ${r.status}: ${r.stderr}`);
    assert.equal(r.stderr, '', `${label} wrote unexpected stderr: ${r.stderr}`);
    const json = JSON.parse(r.stdout);
    process.stdout.write(`ADAPTER ${label.padEnd(20)} -> ${r.stdout.trim()}\n`);
    return json;
  };

  const callKig = (label, args) => {
    const r = spawnSync(process.execPath, [KIG, ...args], {
      cwd: REPO,
      env: { ...process.env },
      encoding: 'utf8',
      timeout: 15000,
    });
    captured.push(r.stdout || '', r.stderr || '');
    assert.equal(r.status, 0, `${label} exited ${r.status}: ${r.stderr}`);
    const line = (r.stdout || '').trim();
    process.stdout.write(`CLI     ${label.padEnd(20)} -> ${line}\n`);
    return line;
  };

  try {
    assert.deepEqual(callAdapter('setup', {
      op: 'setup',
      owners: { brief: 'alice', doc2: 'bob' },
      contents: { brief: 'classified-brief-v1', doc2: 'peer-shared-note' },
      disabled: [],
      key_material: MARKER,
    }), { ready: true });

    assert.deepEqual(callAdapter('read (owner allow)', {
      op: 'read', actor: 'alice', asset: 'brief', request_id: 'req-01',
    }), { decision: 'allow', body: 'classified-brief-v1' });

    assert.deepEqual(callAdapter('revoke alice', {
      op: 'revoke', actor: 'alice',
    }), {});

    assert.deepEqual(callAdapter('read (revoked deny)', {
      op: 'read', actor: 'alice', asset: 'brief', request_id: 'req-02',
    }), { decision: 'deny' });

    assert.deepEqual(callAdapter('audit req-02', {
      op: 'audit', request_id: 'req-02',
    }), { request_id: 'req-02', decision: 'deny' });

    assert.deepEqual(callAdapter('read (peer allow)', {
      op: 'read', actor: 'bob', asset: 'doc2', request_id: 'req-03',
    }), { decision: 'allow', body: 'peer-shared-note' });

    callKig('keys init', ['keys', 'init', '--out', keyDir]);
    const cpOut = callKig('checkpoint', [
      'checkpoint', '--adapter', stateDir,
      '--key', path.join(keyDir, 'audit-signing.key'),
      '--anchor', anchorFile,
    ]);
    assert.match(cpOut, /^CHECKPOINT seq=\d+/);

    const verifyOut = callKig('verify-log', [
      'verify-log', '--adapter', stateDir, '--anchor', anchorFile,
    ]);
    assert.match(verifyOut, /^OK \d+ [0-9a-f]{64}$/);

    const alertsOut = callKig('alerts', ['alerts', '--adapter', stateDir]);
    assert.match(alertsOut, /A-REVOKED-RETRY/);

    // Scan stdout, stderr, and every persisted byte under stateDir (including -wal/-shm).
    const markerBytes = Buffer.from(MARKER, 'utf8');
    let leaks = captured.some((s) => s.includes(MARKER)) ? 1 : 0;
    for (const f of walkFiles(stateDir)) {
      if (fs.readFileSync(f).includes(markerBytes)) leaks++;
    }
    assert.equal(leaks, 0, 'key_material marker leaked');
    process.stdout.write('PASS marker_scan: 0 occurrences in stdout, stderr, and state directory\n');
    process.stdout.write('WALKTHROUGH PASS\n');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main();
