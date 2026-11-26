'use strict';
// Task 5.3: service-edge baseline and lateral-movement rules (P1-10, D-09).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCsv, loadEventsFile, COLUMNS } = require('../../../src/detect/ingest.cjs');
const { correct } = require('../../../src/detect/clock.cjs');
const { ReorderBuffer } = require('../../../src/detect/reorder.cjs');
const { mergeConfig, DOCUMENTED_PRACTICE_EDGES } = require('../../../src/detect/config.cjs');
const { loadApprovals } = require('../../../src/detect/approvals.cjs');
const { evaluatePrivilege } = require('../../../src/detect/rules-priv.cjs');
const { Baseline, edgeKey } = require('../../../src/detect/baseline.cjs');
const { evaluateLateralMovement } = require('../../../src/detect/rules-lm.cjs');
const { practiceEventsPath, practiceApprovals } = require('../../helpers/practice.cjs');

function ordered(events, cfg) {
  const buf = new ReorderBuffer(cfg);
  const out = [];
  for (const e of events) out.push(...buf.push(correct(e, cfg)));
  out.push(...buf.flush());
  return out;
}

/** Run privilege + lateral rules like the pipeline. */
function runLm(events, { cfg = mergeConfig(), approvals = { changes: [] }, baseline = Baseline.fromDocumented() } = {}) {
  const ev = ordered(events, cfg);
  const priv = evaluatePrivilege(ev, loadApprovals(approvals), cfg);
  return { ...evaluateLateralMovement(ev, baseline, priv.tracker, cfg), events: ev };
}
const practiceLm = (opts = {}) => runLm(loadEventsFile(practiceEventsPath()).events, { approvals: practiceApprovals(), ...opts });

const T0 = Date.parse('2026-01-15T10:00:00.000Z');
/** Synthetic events: [atSeconds, src, dst, outcome, extra] */
function mk(specs, base = {}) {
  const iso = (s) => new Date(T0 + s * 1000).toISOString();
  const line = (o) => COLUMNS.map((c) => o[c] ?? '').join(',');
  const rows = specs.map(([at, src, dst, outcome, extra = {}], i) => line({
    event_id: `x${i}`, event_time_utc: iso(at), received_time_utc: iso(at + 0.1), source_clock_offset_ms: '0',
    actor: 'mallory', source_service: src, target_service: dst, action: 'read', role_before: 'viewer', role_after: 'viewer',
    outcome, session_id: 'sm', correlation_id: 'fm', ...base, ...extra,
  }));
  const res = parseCsv([COLUMNS.join(','), ...rows].join('\n'));
  assert.deepEqual(res.rejects, []);
  return res.events;
}

// ---- baseline ----

test('edgeKey cannot collide on delimiters', () => {
  assert.notEqual(edgeKey('a->b', 'c'), edgeKey('a', 'b->c'));
  assert.notEqual(edgeKey('a|b', 'c'), edgeKey('a', 'b|c'));
});

test('Baseline from documented edges, corpus and file; summary', () => {
  const b = Baseline.fromDocumented();
  assert.equal(b.has('portal', 'catalog'), true);
  assert.equal(b.has('catalog', 'portal'), false, 'edges are directed');
  assert.equal(b.has('reports', 'billing'), false);
  assert.deepEqual(b.summary(), { source: 'documented', edgeCount: DOCUMENTED_PRACTICE_EDGES.length, documentedEdgeCount: 7, corpusEdgeCount: 0, seed: null });
  b.addCorpus(mk([[0, 'portal', 'search', 'allow'], [1, 'search', 'catalog', 'allow'], [2, 'portal', 'catalog', 'allow']]), { seed: 9 });
  assert.equal(b.has('portal', 'search'), true);
  assert.deepEqual(b.summary(), { source: 'documented+warmup', edgeCount: 9, documentedEdgeCount: 7, corpusEdgeCount: 2, seed: 9 });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-base-'));
  const f = path.join(dir, 'b.json');
  fs.writeFileSync(f, JSON.stringify({ edges: [['a', 'b'], { src: 'b', dst: 'c' }], source: 'site-x' }));
  const fb = Baseline.fromFile(f);
  assert.equal(fb.has('a', 'b') && fb.has('b', 'c'), true);
  assert.equal(fb.summary().source, 'site-x');
  fs.writeFileSync(f, JSON.stringify({ edges: [['a']] }));
  assert.throws(() => Baseline.fromFile(f), /edge/);
});

// ---- practice set ----

test('evt-010..012 grouped as ONE LM-1 candidate lateral-movement alert', () => {
  const { alerts } = practiceLm();
  assert.equal(alerts.length, 1);
  const [a] = alerts;
  assert.equal(a.rule_id, 'LM-1');
  assert.equal(a.severity, 'medium');
  assert.equal(a.classification, 'candidate_lateral_movement');
  assert.equal(a.identity, 'svc-report-worker');
  assert.deepEqual(a.event_ids, ['evt-010', 'evt-011', 'evt-012']);
  assert.deepEqual(a.path, ['reports->billing', 'billing->archive', 'archive->identity']);
  assert.deepEqual(a.services, ['reports', 'billing', 'archive', 'identity']);
  assert.deepEqual(a.outcomes.map((o) => o.outcome), ['deny', 'deny', 'deny']);
  assert.deepEqual(a.also_matched, ['LM-3'], 'the deny burst is folded into the sequence, not a second alert');
  assert.match(a.reason, /candidate lateral movement/i);
  assert.match(a.reason, /denied/);
  assert.doesNotMatch(a.reason, /compromise|successful/i);
  assert.equal(a.window.start_utc, '2026-01-15T09:04:00.000Z');
  assert.equal(a.window.end_utc, '2026-01-15T09:04:03.000Z');
});

test('evt-007..009 produce ZERO LM alerts', () => {
  const { alerts } = practiceLm();
  assert.equal(alerts.filter((a) => a.event_ids.some((id) => ['evt-007', 'evt-008', 'evt-009'].includes(id))).length, 0);
});

test('evt-017 and evt-018 classified expected_enforcement, ZERO LM alerts', () => {
  const { alerts, eventMeta } = practiceLm();
  for (const id of ['evt-017', 'evt-018']) {
    assert.equal(eventMeta.get(id).classification, 'expected_enforcement');
    assert.equal(eventMeta.get(id).revocation_approval_id, 'change-101');
  }
  assert.equal(alerts.filter((a) => a.event_ids.some((id) => ['evt-017', 'evt-018'].includes(id))).length, 0);
  // Even with a baseline that lacks the reports nodes, revocation context still excludes them.
  const thin = Baseline.fromDocumented(DOCUMENTED_PRACTICE_EDGES.filter(([, d]) => !d.startsWith('reports-node')));
  const r = practiceLm({ baseline: thin });
  assert.equal(r.alerts.filter((a) => a.event_ids.some((id) => ['evt-017', 'evt-018'].includes(id))).length, 0);
  assert.equal(r.eventMeta.get('evt-017').classification, 'expected_enforcement');
});

test('evt-020 single isolated denial produces ZERO alerts', () => {
  const { alerts, eventMeta } = practiceLm();
  assert.equal(alerts.filter((a) => a.event_ids.includes('evt-020')).length, 0);
  assert.equal(eventMeta.get('evt-020').classification, 'unseen_edge');
});

test('window invariance', () => {
  const shape = (r) => r.alerts.map((a) => [a.rule_id, a.event_ids, a.path]);
  const ref = shape(practiceLm());
  for (const lmWindowMs of [30000, 60000, 120000]) assert.deepEqual(shape(practiceLm({ cfg: mergeConfig({ lmWindowMs }) })), ref, `window ${lmWindowMs}`);
});

// ---- synthetic cases ----

test('LM-2 fires on single allowed unseen edge to billing/archive/identity', () => {
  for (const dst of ['billing', 'archive', 'identity']) {
    const { alerts } = runLm(mk([[0, 'reports', dst, 'allow']]));
    assert.equal(alerts.length, 1, dst);
    assert.deepEqual([alerts[0].rule_id, alerts[0].severity, alerts[0].classification], ['LM-2', 'medium', 'novel_sensitive_access']);
    assert.match(alerts[0].reason, /allowed/);
  }
  // 'success' counts as allowed too
  assert.equal(runLm(mk([[0, 'reports', 'billing', 'success']])).alerts.length, 1);
  // not sensitive → no alert; denied → no LM-2
  assert.equal(runLm(mk([[0, 'reports', 'analytics', 'allow']])).alerts.length, 0);
  assert.equal(runLm(mk([[0, 'reports', 'billing', 'deny']])).alerts.length, 0);
  // known edge into a sensitive service is routine
  assert.equal(runLm(mk([[0, 'portal', 'identity', 'allow']])).alerts.length, 0);
});

test('LM-2: a two-edge allowed path in one session is one alert', () => {
  const { alerts } = runLm(mk([[0, 'portal', 'archive', 'allow'], [5, 'archive', 'identity', 'allow']]));
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].rule_id, 'LM-2');
  assert.deepEqual(alerts[0].event_ids, ['x0', 'x1']);
});

test('LM-1 with an allowed edge is high severity and says what succeeded', () => {
  const { alerts } = runLm(mk([[0, 'reports', 'billing', 'deny'], [2, 'billing', 'archive', 'allow'], [3, 'archive', 'identity', 'deny']]));
  const lm1 = alerts.filter((a) => a.rule_id === 'LM-1');
  assert.equal(lm1.length, 1);
  assert.equal(lm1[0].severity, 'high');
  assert.match(lm1[0].reason, /1 of 3 requests were allowed/);
});

test('LM-3 fires on 3 denials across 2 distinct unseen targets', () => {
  const { alerts } = runLm(mk([[0, 'portal', 'billing', 'deny'], [10, 'portal', 'archive', 'deny'], [20, 'portal', 'billing', 'deny']]));
  assert.equal(alerts.length, 1);
  assert.deepEqual([alerts[0].rule_id, alerts[0].severity, alerts[0].classification], ['LM-3', 'low', 'unseen_deny_burst']);
  assert.deepEqual(alerts[0].event_ids, ['x0', 'x1', 'x2']);
});

test('LM-3 does NOT fire on 2 denials', () => {
  assert.equal(runLm(mk([[0, 'portal', 'billing', 'deny'], [10, 'portal', 'archive', 'deny']])).alerts.length, 0);
});

test('LM-3 needs 2 distinct targets', () => {
  assert.equal(runLm(mk([[0, 'portal', 'billing', 'deny'], [5, 'portal', 'billing', 'deny'], [9, 'portal', 'billing', 'deny']])).alerts.length, 0);
});

test('LM-1 respects the window: low-and-slow is not a sequence', () => {
  const slow = mk([[0, 'reports', 'billing', 'deny'], [90, 'billing', 'archive', 'deny'], [180, 'archive', 'identity', 'deny']]);
  assert.equal(runLm(slow).alerts.length, 0);
  assert.equal(runLm(slow, { cfg: mergeConfig({ lmWindowMs: 200000 }) }).alerts.length, 1);
});

test('LM-1 groups per actor/session/flow; other identities do not combine', () => {
  const ev = mk([
    [0, 'reports', 'billing', 'deny', { actor: 'a1' }],
    [1, 'billing', 'archive', 'deny', { actor: 'a2' }],
    [2, 'archive', 'identity', 'deny', { actor: 'a3' }],
  ]);
  assert.equal(runLm(ev).alerts.length, 0);
});

test('later unseen edges extend the open LM-1 alert instead of opening another', () => {
  const { alerts } = runLm(mk([
    [0, 'reports', 'billing', 'deny'], [1, 'billing', 'archive', 'deny'], [2, 'archive', 'identity', 'deny'],
    [3, 'catalog', 'billing', 'deny'],
  ]));
  assert.equal(alerts.length, 1);
  assert.deepEqual(alerts[0].event_ids, ['x0', 'x1', 'x2', 'x3']);
});

test('order_uncertain propagates from supporting events to alert', () => {
  const { alerts } = runLm(mk([[0, 'reports', 'billing', 'deny'], [0.2, 'billing', 'archive', 'deny'], [3, 'archive', 'identity', 'deny']]));
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].order_uncertain, true);
  const clean = runLm(mk([[0, 'reports', 'billing', 'deny'], [2, 'billing', 'archive', 'deny'], [4, 'archive', 'identity', 'deny']]));
  assert.equal(clean.alerts[0].order_uncertain, false);
});

test('prototype-named identities and services are ordinary keys', () => {
  const { alerts } = runLm(mk([
    [0, '__proto__', 'constructor', 'deny'], [1, 'constructor', 'toString', 'deny'], [2, 'toString', 'billing', 'deny'],
  ], { actor: '__proto__', session_id: 'hasOwnProperty', correlation_id: 'valueOf' }));
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].identity, '__proto__');
});

test('alert carries last evidence receipt and simulated emission time', () => {
  const { alerts, events } = runLm(mk([[0, 'reports', 'billing', 'deny'], [1, 'billing', 'archive', 'deny'], [2, 'archive', 'identity', 'deny']]));
  const third = events.find((e) => e.id === 'x2');
  assert.equal(alerts[0].last_evidence_received_ms, third.receivedMs);
  assert.equal(alerts[0].emitted_sim_ms, third.releasedAtMs);
  assert.ok(alerts[0].emitted_sim_ms >= alerts[0].last_evidence_received_ms);
});
