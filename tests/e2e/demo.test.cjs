'use strict';
// E2E test for `kig demo` (Phase 7 Task 7.2, architecture §17.2).
// Uses --fast so `npm test` skips only the 30 s idle sleep (and verifies that skip is reported honestly).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runKig } = require('../helpers/run-kig.cjs');

test('kig demo --fast --json passes all 12 narrated steps cleanly', { timeout: 180000 }, () => {
  const r = runKig(['demo', '--fast', '--seed', '2026', '--json'], { timeoutMs: 150000 });
  assert.equal(r.code, 0, `demo exited ${r.code}:\nSTDERR: ${r.stderr}\nSTDOUT: ${r.stdout}`);
  const report = JSON.parse(r.stdout);
  assert.equal(report.pass, true);
  assert.equal(report.fast, true);
  assert.equal(report.passed_steps, 12);
  assert.equal(report.total_steps, 12);
  assert.equal(report.steps.length, 12);
  for (let i = 0; i < 12; i++) {
    assert.equal(report.steps[i].n, i + 1);
    assert.equal(report.steps[i].status, 'PASS', `step ${i + 1} failed: ${JSON.stringify(report.steps[i])}`);
    assert.ok(report.steps[i].details.length >= 1, `step ${i + 1} missing narration details`);
  }
  // Honesty check (P7-D7): --fast must state grace expiry wait was skipped, and Step 11 must state D-05 not supported.
  assert.ok(report.steps[3].details.some((d) => d.includes('not waited (--fast)')));
  assert.ok(report.steps[10].details.some((d) => d.includes('NOT SUPPORTED (D-05)')));
});
