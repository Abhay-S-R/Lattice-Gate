'use strict';
// Task 4.3 / Gate 4: `kig crash-test` SIGKILLs the control plane at every rotation phase and checks
// recovery (features P1-06; architecture §12.3).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runKig } = require('../helpers/run-kig.cjs');
const { ROTATION } = require('../../src/core/contracts.cjs');

const CHECKS = ['cp_killed_at_point', 'journal_at_crash', 'recovery_action', 'cp_one_active_version', 'nodes_one_active_version',
  'epoch_never_decreases', 'revoked_stays_revoked', 'committed_data_readable', 'custodian_test_decrypt', 'audit_chain_ok'];

test('kig crash-test passes at all five crash points', { timeout: 600000 }, (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-crash-report-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const out = path.join(dir, 'report.json');
  const r = runKig(['crash-test', '--json', '--out', out], { timeoutMs: 540000 });
  const report = JSON.parse(fs.readFileSync(out, 'utf8'));
  for (const p of report.points) for (const c of p.checks) assert.ok(c.pass, `${p.point}: ${c.name}: ${c.detail}`);
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(report.points.map((p) => p.point), [...ROTATION.crashPoints]);
  for (const p of report.points) {
    assert.deepEqual(p.checks.map((c) => c.name), CHECKS, p.point);
    const rollForward = p.point === 'after_commit' || p.point === 'during_distribute';
    assert.equal(p.expected_action, rollForward ? 'roll_forward' : 'abort');
    assert.equal(p.active_after, rollForward ? p.rotation.to : p.rotation.from, p.point);
  }
  assert.equal(report.pass, true);
});

test('crash injection is ignored unless NODE_ENV=test or the crash harness enables it', () => {
  const { crashPoint } = require('../../src/cp/rotate.cjs');
  // Would SIGKILL this test process if honoured.
  assert.doesNotThrow(() => crashPoint({ KIG_CRASH_AT: 'after_prepare' }, 'after_prepare'));
  assert.doesNotThrow(() => crashPoint({ KIG_CRASH_AT: 'after_prepare', NODE_ENV: 'production' }, 'after_prepare'));
  assert.doesNotThrow(() => crashPoint({ KIG_CRASH_AT: 'after_prepare', KIG_CRASH_HARNESS: '0' }, 'after_prepare'));
  assert.doesNotThrow(() => crashPoint({ KIG_CRASH_AT: 'not_a_point', NODE_ENV: 'test' }, 'not_a_point'));
  assert.doesNotThrow(() => crashPoint({ KIG_CRASH_AT: 'after_stage', NODE_ENV: 'test' }, 'after_prepare'));
  const bad = runKig(['crash-test', '--point', 'nowhere']);
  assert.equal(bad.code, 2);
});
