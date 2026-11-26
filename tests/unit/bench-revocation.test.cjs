'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { seededDeviceId, summarize } = require('../../src/cli/bench-revocation.cjs');

test('revocation benchmark IDs are stable for a seed and unique by sample', () => {
  const first = Array.from({ length: 5 }, (_, i) => seededDeviceId(23, i));
  assert.deepEqual(first, Array.from({ length: 5 }, (_, i) => seededDeviceId(23, i)));
  assert.equal(new Set(first).size, first.length);
  assert.notEqual(first[0], seededDeviceId(24, 0));
});

test('revocation summaries use nearest-rank p50 and p95 in milliseconds', () => {
  assert.deepEqual(summarize([1, 2, 3, 4, 100]), { p50: 3, p95: 100, max: 100 });
  assert.deepEqual(summarize([4]), { p50: 4, p95: 4, max: 4 });
  assert.throws(() => summarize([]), /non-empty/);
});
