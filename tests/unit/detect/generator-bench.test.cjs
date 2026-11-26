'use strict';
// Task 5.5: seeded generator, benchmark scorer and `kig bench detect` (P1-18).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { mulberry32, generateDataset, generateWarmupCorpus, PROBE_EDGES, ROUTINE } = require('../../../src/detect/generator.cjs');
const { score, runBenchmark, median } = require('../../../src/detect/bench.cjs');
const { Baseline } = require('../../../src/detect/baseline.cjs');
const { parseSeeds } = require('../../../src/cli/bench-detect.cjs');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const snapshot = (d) => JSON.stringify({ csv: d.csv, approvals: d.approvals, incidents: d.incidents, labels: [...d.eventLabels], summary: d.summary });

test('mulberry32 is deterministic and in [0, 1)', () => {
  const a = mulberry32(42), b = mulberry32(42);
  const xs = Array.from({ length: 1000 }, () => a());
  assert.deepEqual(xs, Array.from({ length: 1000 }, () => b()));
  assert.ok(xs.every((x) => x >= 0 && x < 1));
  assert.notDeepEqual(xs.slice(0, 5), Array.from({ length: 5 }, mulberry32(43)));
});

test('deterministic per seed', () => {
  assert.equal(snapshot(generateDataset(201)), snapshot(generateDataset(201)));
  assert.deepEqual(generateDataset(201).events, generateDataset(201).events);
});

test('different seeds produce different datasets', () => {
  assert.notEqual(generateDataset(201).csv, generateDataset(202).csv);
});

test('dataset shape: size, scenario mix, clock stress, ground truth consistent', () => {
  const d = generateDataset(201);
  assert.ok(d.summary.events >= 1000, `${d.summary.events} events`);
  assert.ok(d.summary.benign_events >= 1000);
  assert.ok(d.incidents.length >= 18 && d.incidents.length <= 25, `${d.incidents.length} incidents`);
  assert.ok(d.incidents.some((i) => i.evasive) && d.incidents.some((i) => !i.evasive));
  for (const v of ['chain_3_edges_denied', 'one_edge_allowed_sensitive', 'two_edge_allowed', 'deny_burst_2_targets', 'low_and_slow_3_edges', 'two_edge_denied', 'expired_approval']) {
    assert.ok(d.summary.incidents_by_variant[v] > 0, v);
  }
  assert.ok(Object.keys(d.summary.incidents_by_variant).some((v) => v.startsWith('unapproved_escalation')));
  assert.ok(d.summary.clock.skewed_within_range > 0);
  assert.ok(d.summary.clock.skew_out_of_range > 0);
  assert.ok(d.summary.clock.delayed_1_to_4_s > 0);
  assert.equal(d.events.length, d.summary.events);
  const ids = new Set(d.events.map((e) => e.id));
  for (const inc of d.incidents) {
    assert.ok(inc.event_ids.length > 0);
    for (const id of inc.event_ids) { assert.ok(ids.has(id)); assert.equal(d.eventLabels.get(id), inc.incident_id); }
  }
  // receipt order differs from event order somewhere (reordering is exercised)
  assert.ok(d.events.some((e, i) => i > 0 && e.eventTimeMs - e.offsetMs < d.events[i - 1].eventTimeMs - d.events[i - 1].offsetMs));
});

test('warm-up corpus covers every routine edge and no probe edge', () => {
  const b = Baseline.fromDocumented();
  b.addCorpus(generateWarmupCorpus(1), { seed: 1 });
  for (const edges of Object.values(ROUTINE)) for (const [s, d] of edges) assert.ok(b.has(s, d), `${s}->${d}`);
  for (const [s, d] of PROBE_EDGES) assert.equal(b.has(s, d), false, `${s}->${d} must stay unseen`);
});

test('disjoint seed enforcement', () => {
  assert.throws(() => runBenchmark({ tuningSeeds: [101, 201], holdoutSeeds: [201, 202] }), /disjoint/);
  assert.throws(() => runBenchmark({ tuningSeeds: [101], holdoutSeeds: [201], warmupSeed: 201 }), /warm-up/);
  assert.throws(() => runBenchmark({ tuningSeeds: [], holdoutSeeds: [201] }), /tuning/);
  assert.throws(() => runBenchmark({ tuningSeeds: [101, 101], holdoutSeeds: [201] }), /duplicate/);
});

test('score: one-to-one matching, false alerts, misses, event level kept separate', () => {
  const dataset = {
    incidents: [
      { incident_id: 'i1', variant: 'v1', evasive: false, event_ids: ['a', 'b'] },
      { incident_id: 'i2', variant: 'v2', evasive: true, event_ids: ['c'] },
      { incident_id: 'i3', variant: 'v3', evasive: false, event_ids: ['d'] },
    ],
    eventLabels: new Map([['a', 'i1'], ['b', 'i1'], ['c', 'i2'], ['d', 'i3'], ...Array.from({ length: 996 }, (_, k) => [`n${k}`, 'benign'])]),
  };
  const alerts = [
    { alert_id: 'alert-001', rule_id: 'LM-1', event_ids: ['a', 'b'], tta_ms: 4000 },
    { alert_id: 'alert-002', rule_id: 'LM-2', event_ids: ['a'], tta_ms: 100 }, // same incident again → false alert
    { alert_id: 'alert-003', rule_id: 'LM-3', event_ids: ['n1'], tta_ms: 10 },
  ];
  const s = score(alerts, dataset, { processingMsPerEvent: 0.5 });
  assert.deepEqual([s.incident.tp, s.incident.fp, s.incident.fn], [1, 2, 2]);
  assert.equal(s.incident.precision, 1 / 3);
  assert.equal(s.incident.recall, 1 / 3);
  assert.equal(s.incident.recall_detectable, 1 / 2);
  assert.equal(s.false_alerts_per_1000_benign, 2 / 996 * 1000);
  assert.deepEqual(s.missed_detectable.map((m) => m.incident_id), ['i3']);
  assert.deepEqual(s.missed_evasive.map((m) => m.incident_id), ['i2']);
  assert.deepEqual(s.tta_ms, [4000.5]);
  assert.deepEqual([s.event.tp, s.event.fp, s.event.fn], [2, 1, 2]);
  assert.deepEqual(s.matched, [{ alert_id: 'alert-001', rule_id: 'LM-1', incident_id: 'i1', variant: 'v1' }]);
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 2, 3]), 2.5);
  assert.equal(median([]), null);
});

test('held-out benchmark quality gate', () => {
  const r = runBenchmark({ tuningSeeds: [101, 102, 103], holdoutSeeds: [201, 202, 203, 204, 205], warmupSeed: 1 });
  const h = r.holdout;
  assert.deepEqual(h.seeds, [201, 202, 203, 204, 205]);
  assert.ok(h.benign_events >= 5000, `${h.benign_events} benign events`);
  assert.ok(h.incident.f1 >= 0.85, `F1 ${h.incident.f1}`);
  assert.ok(h.incident.recall_detectable >= 0.95, `detectable recall ${h.incident.recall_detectable}`);
  assert.ok(h.false_alerts_per_1000_benign <= 2.0, `FA/1000 ${h.false_alerts_per_1000_benign}`);
  assert.ok(Number.isFinite(h.median_tta_ms) && h.median_tta_ms > 0, `median TTA ${h.median_tta_ms}`);
  assert.ok(h.median_tta_ms <= r.config.latenessMs + 1000, 'TTA bounded by the watermark wait plus processing');
  // evasions are reported, not hidden
  assert.ok(h.incident.evasive_incidents > 0);
  assert.ok(Array.isArray(h.missed_evasive));
  assert.equal(h.missed_evasive.length + h.detection_by_variant.low_and_slow_3_edges.detected + h.detection_by_variant.two_edge_denied.detected, h.incident.evasive_incidents);
  // provenance
  assert.equal(r.data_origin.startsWith('synthetic'), true);
  assert.deepEqual(r.seeds, { tuning: [101, 102, 103], holdout: [201, 202, 203, 204, 205], warmup: 1 });
  assert.equal(r.baseline.source, 'documented+warmup');
  assert.equal(r.baseline.seed, 1);
  assert.equal(r.config.lm3DenyThreshold, 3);
  for (const k of ['precision', 'recall', 'f1', 'false_alerts_per_1000_benign', 'tta_ms', 'event_level', 'evasive']) assert.ok(r.definitions[k], k);
  assert.equal(r.per_seed.holdout.length, 5);
});

test('benchmark is reproducible from its seeds', () => {
  const strip = (r) => JSON.stringify({ h: { ...r.holdout, median_tta_ms: null, max_tta_ms: null }, t: { ...r.tuning, median_tta_ms: null, max_tta_ms: null } });
  const a = runBenchmark({ tuningSeeds: [7], holdoutSeeds: [8], warmupSeed: 9 });
  const b = runBenchmark({ tuningSeeds: [7], holdoutSeeds: [8], warmupSeed: 9 });
  assert.equal(strip(a), strip(b));
});

test('parseSeeds accepts lists and ranges', () => {
  assert.deepEqual(parseSeeds('101,102,103', 'seeds'), [101, 102, 103]);
  assert.deepEqual(parseSeeds('201-205', 'holdout'), [201, 202, 203, 204, 205]);
  assert.deepEqual(parseSeeds('1, 5-6', 'x'), [1, 5, 6]);
  for (const bad of ['', 'a', '5-1', '1.5', '-3']) assert.throws(() => parseSeeds(bad, 'x'));
});

test('CLI node kig.cjs bench detect --seeds 101,102 --holdout 201,202 --out <tmp> --json', () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kig-bench-')), 'report.json');
  const r = spawnSync(process.execPath, ['kig.cjs', 'bench', 'detect', '--seeds', '101,102', '--holdout', '201,202', '--out', out, '--json'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const printed = JSON.parse(r.stdout);
  const saved = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.deepEqual(saved, printed);
  assert.deepEqual(saved.seeds.holdout, [201, 202]);
  assert.ok(typeof saved.holdout.incident.f1 === 'number');
  assert.ok(saved.generated_at);
  assert.match(r.stderr, /report: /);
});

test('CLI human output prints the held-out metrics', () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kig-bench-')), 'r.json');
  const r = spawnSync(process.execPath, ['kig.cjs', 'bench', 'detect', '--seeds', '101', '--holdout', '201', '--out', out], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  for (const re of [/HELD-OUT seeds 201/, /precision/, /recall/, /F1/, /median time-to-alert/, /false alerts per 1,000 benign events/, /evasive/]) assert.match(r.stdout, re);
});

test('CLI rejects bad seeds and overlapping sets with exit 2', () => {
  const run = (args) => spawnSync(process.execPath, ['kig.cjs', 'bench', 'detect', ...args], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(run(['--seeds', '101']).status, 2);
  assert.equal(run(['--seeds', 'x', '--holdout', '201']).status, 2);
  const overlap = run(['--seeds', '101,201', '--holdout', '201']);
  assert.equal(overlap.status, 2);
  assert.match(overlap.stderr, /disjoint/);
  assert.equal(spawnSync(process.execPath, ['kig.cjs', 'bench', 'nothing'], { cwd: ROOT, encoding: 'utf8' }).status, 2);
});

test('CLI on an unwritable output location still prints and exits 0', { skip: process.platform === 'win32' || (process.getuid && process.getuid() === 0) ? 'needs a non-root POSIX user' : false }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-bench-ro-'));
  fs.chmodSync(dir, 0o500);
  try {
    const r = spawnSync(process.execPath, ['kig.cjs', 'bench', 'detect', '--seeds', '101', '--holdout', '201', '--out', path.join(dir, 'x', 'r.json')], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /report not saved/);
  } finally {
    fs.chmodSync(dir, 0o700);
  }
});
