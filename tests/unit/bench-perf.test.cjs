'use strict';
// Unit tests for `kig bench perf` (Phase 7 Task 7.1, features P1-20).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { stats } = require('../../src/cli/bench-perf.cjs');
const { runKig } = require('../helpers/run-kig.cjs');

test('stats computes nearest-rank p50/p95, max and mean', () => {
  const samples = Array.from({ length: 20 }, (_, i) => i + 1); // 1..20
  const s = stats(samples);
  assert.equal(s.n, 20);
  assert.equal(s.p50_ms, 10);
  assert.equal(s.p95_ms, 19);
  assert.equal(s.max_ms, 20);
  assert.equal(s.mean_ms, 10.5);
});

test('kig bench perf --runs 3 --no-cluster --json produces complete measured report', { timeout: 120000 }, () => {
  const r = runKig(['bench', 'perf', '--runs', '3', '--no-cluster', '--seed', '2026', '--json'], { timeoutMs: 90000 });
  assert.equal(r.code, 0, `exit ${r.code}: ${r.stderr || r.stdout}`);
  const report = JSON.parse(r.stdout);
  assert.equal(report.environment.node, process.version);
  assert.equal(report.environment.arch, process.arch);
  assert.equal(report.config.runs, 3);
  assert.equal(report.config.seed, 2026);
  assert.equal(report.config.cluster, false);
  assert.equal(report.results.cluster_round2, null);

  const checkTiming = (obj, label) => {
    assert.ok(obj && typeof obj === 'object', `missing timing ${label}`);
    for (const k of ['n', 'p50_ms', 'p95_ms', 'max_ms', 'mean_ms']) {
      assert.equal(typeof obj[k], 'number', `${label}.${k} not a number`);
      assert.ok(Number.isFinite(obj[k]) && obj[k] >= 0, `${label}.${k} invalid: ${obj[k]}`);
    }
    assert.ok(obj.n >= 1, `${label}.n < 1`);
    assert.ok(obj.p50_ms <= obj.p95_ms && obj.p95_ms <= obj.max_ms, `${label} percentile order broken`);
  };

  checkTiming(report.results.process_baseline.empty_node, 'empty_node');
  for (const k of [
    'setup_small', 'read_allow', 'read_deny', 'revoke',
    'audit_hit', 'audit_miss', 'protected_read_allow', 'protected_read_invalid_key',
    'setup_1mib', 'setup_near_4mib_cap',
  ]) {
    checkTiming(report.results.adapter_whole_process[k], `adapter.${k}`);
  }
  for (const k of [
    'ml_kem_768_keygen', 'ml_kem_768_encapsulate', 'ml_kem_768_decapsulate',
    'ml_dsa_65_keygen', 'ml_dsa_65_sign', 'ml_dsa_65_verify',
    'aes_256_gcm_seal_1kib', 'aes_256_gcm_open_1kib',
    'aes_256_gcm_seal_64kib', 'aes_256_gcm_open_64kib',
    'aes_256_gcm_seal_256kib', 'aes_256_gcm_open_256kib',
    'hkdf_sha256_32b', 'hmac_sha256_1kib', 'kem_wrap_dek', 'kem_unwrap_dek',
  ]) {
    checkTiming(report.results.crypto_in_process[k], `crypto.${k}`);
  }
  checkTiming(report.results.storage_in_process.audit_append_tx, 'audit_append_tx');
  checkTiming(report.results.storage_in_process.verify_chain_1000, 'verify_chain_1000');
  checkTiming(report.results.detector_in_process.detect_synthetic_dataset, 'detect_synthetic');
  assert.ok(report.results.detector_in_process.p50_events_per_sec > 0);
  checkTiming(report.results.messaging_in_process.handshake_m1_m3, 'handshake_m1_m3');
  checkTiming(report.results.messaging_in_process.record_seal_16kib, 'record_seal_16kib');
  checkTiming(report.results.messaging_in_process.record_open_16kib, 'record_open_16kib');

  const sz = report.results.sizes_bytes;
  for (const [k, v] of Object.entries(sz)) {
    assert.ok(Number.isInteger(v) && v > 0, `size ${k}=${v} must be positive integer`);
  }
  assert.equal(sz.ml_kem_768_pk_raw, 1184);
  assert.equal(sz.ml_kem_768_ct, 1088);
  assert.equal(sz.ml_kem_768_ss, 32);
  assert.equal(sz.ml_dsa_65_pk_raw, 1952);
  assert.equal(sz.ml_dsa_65_sig, 3309);
  assert.equal(sz.aes_256_gcm_nonce, 12);
  assert.equal(sz.aes_256_gcm_tag, 16);
  assert.ok(Array.isArray(report.limits) && report.limits.length >= 3);
});

test('kig bench perf unwritable --out still prints and exits 0', { timeout: 120000 }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-bench-ro-'));
  try {
    // Point --out inside a path where parent is a regular file so write fails everywhere (even as root).
    const blocker = path.join(dir, 'not-a-dir');
    fs.writeFileSync(blocker, 'x');
    const outPath = path.join(blocker, 'report.json');
    const r = runKig(['bench', 'perf', '--runs', '2', '--no-cluster', '--out', outPath, '--json'], { timeoutMs: 90000 });
    assert.equal(r.code, 0, `exit ${r.code}: ${r.stderr}`);
    assert.ok(JSON.parse(r.stdout).results.sizes_bytes.ml_kem_768_ct === 1088);
    assert.match(r.stderr, /not writable|not saved/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('kig bench perf rejects invalid --runs or --seed with exit 2', () => {
  for (const bad of [['bench', 'perf', '--runs', '0'], ['bench', 'perf', '--runs', 'abc'], ['bench', 'perf', '--seed', '-1']]) {
    const r = runKig(bad);
    assert.equal(r.code, 2, `${bad.join(' ')} exited ${r.code}`);
  }
});
