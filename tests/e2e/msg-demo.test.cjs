'use strict';
// Goals 9–12 regression test via `kig msg demo` across deterministic seeds (Phase 7 Task 7.0).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runKig } = require('../helpers/run-kig.cjs');

const EXPECTED_SUBSTRINGS = [
  'temporary Alice/Bob identities are enrolled and pinned to the signed policy',
  'tampered M1 and unregistered peer are rejected',
  'tampered M2 signature transcript and key-confirmation MAC are rejected',
  'wrong initiator key-confirmation MAC is rejected',
  'authenticated ephemeral KEM handshake, transcript signatures, and mutual key confirmation',
  'tampered recipient-device field is rejected',
  'wrong recipient, altered AAD, and duplicate record are rejected',
  'transport receipt:',
  'reassembly complete: 1 message',
  'application delivery: exact message delivered once despite loss, duplication, and reordering',
  'incomplete message expires; message-size and buffer limits fail closed',
  'forward secrecy: recorded ciphertext remains unreadable after signing-key exposure and session close',
  'revoked device cannot establish or continue a session',
];

for (const seed of [2026, 42]) {
  test(`kig msg demo passes all Goals 9-12 checks (seed ${seed})`, { timeout: 60000 }, () => {
    const res = runKig(['msg', 'demo', '--seed', String(seed)], { timeoutMs: 45000 });
    assert.equal(res.code, 0, `exit ${res.code}: ${res.stderr || res.stdout}`);
    assert.equal(res.stderr, '');
    const lines = res.stdout.trim().split(/\r?\n/);
    const passLines = lines.filter((l) => l.startsWith('PASS '));
    const failLines = lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failLines.length, 0, `unexpected FAIL lines: ${failLines.join('; ')}`);
    assert.equal(passLines.length, 13, `expected 13 PASS lines, got ${passLines.length}:\n${res.stdout}`);
    for (const sub of EXPECTED_SUBSTRINGS) {
      assert.ok(passLines.some((l) => l.includes(sub)), `missing check "${sub}" in:\n${res.stdout}`);
    }
    assert.ok(lines.includes('Session resumption: NOT SUPPORTED (D-05)'), 'must explicitly state D-05 resumption status');
  });
}
