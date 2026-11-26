'use strict';
// Task 5.4: full detector pipeline on the 22-event practice set, and `kig detect`.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { detect } = require('../../../src/detect/index.cjs');
const { loadEventsFile, COLUMNS } = require('../../../src/detect/ingest.cjs');
const { loadApprovalsFile } = require('../../../src/detect/approvals.cjs');
const { practiceEventsPath, practiceApprovalsPath } = require('../../helpers/practice.cjs');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const runPractice = (cfg) => {
  const { events, rejects } = loadEventsFile(practiceEventsPath());
  return { ...detect(events, loadApprovalsFile(practiceApprovalsPath()), undefined, cfg), rejects };
};
const kig = (args, opts = {}) => spawnSync(process.execPath, ['kig.cjs', ...args], { cwd: ROOT, encoding: 'utf8', ...opts });
/** Drop the fields that depend on wall-clock processing time. */
function stable(r) {
  const c = JSON.parse(JSON.stringify(r));
  for (const a of c.alerts) delete a.emitted_at_mono_ns;
  delete c.stats.processing_ns;
  return c;
}

test('full 22-event practice regression', () => {
  const r = runPractice();
  assert.equal(r.rejects.length, 0);
  assert.equal(r.timeline.length, 22);
  assert.equal(r.alerts.length, 2);

  const [priv, lm] = r.alerts;
  assert.equal(priv.alert_id, 'alert-001');
  assert.equal(priv.rule_id, 'PRIV-1');
  assert.equal(priv.severity, 'high');
  assert.equal(priv.identity, 'user-blair');
  assert.deepEqual(priv.event_ids, ['evt-008', 'evt-009']);
  assert.deepEqual(priv.related_rules, ['PRIV-2']);

  assert.equal(lm.alert_id, 'alert-002');
  assert.equal(lm.rule_id, 'LM-1');
  assert.equal(lm.severity, 'medium');
  assert.equal(lm.classification, 'candidate_lateral_movement');
  assert.equal(lm.identity, 'svc-report-worker');
  assert.deepEqual(lm.event_ids, ['evt-010', 'evt-011', 'evt-012']);
  assert.deepEqual(lm.path, ['reports->billing', 'billing->archive', 'archive->identity']);
  assert.deepEqual(lm.outcomes.map((o) => o.outcome), ['deny', 'deny', 'deny']);

  for (const a of r.alerts) {
    for (const k of ['alert_id', 'rule_id', 'severity', 'classification', 'identity', 'services', 'path', 'event_ids', 'outcomes', 'reason', 'order_uncertain', 'window', 'last_evidence_received_ms', 'emitted_sim_ms', 'tta_ms', 'emitted_at_mono_ns']) {
      assert.ok(Object.prototype.hasOwnProperty.call(a, k), `${a.alert_id} missing ${k}`);
    }
    assert.ok(!Object.keys(a).some((k) => k.startsWith('_')), 'no internal fields leak');
    assert.ok(a.tta_ms >= 0 && a.tta_ms <= 5000 + 1000, `tta ${a.tta_ms} includes the watermark wait`);
  }

  const tl = new Map(r.timeline.map((e, i) => [e.event_id, { ...e, pos: i }]));
  assert.ok(tl.get('evt-013').pos < tl.get('evt-014').pos, 'event-time order');
  assert.ok(tl.get('evt-014').ingest_idx < tl.get('evt-013').ingest_idx, 'ingest order kept');
  const e15 = tl.get('evt-015');
  assert.equal(e15.corrected_ms, Date.parse('2026-01-15T09:06:01.000Z'));
  assert.equal(e15.corrected_time_utc, '2026-01-15T09:06:01.000Z');
  assert.equal(e15.delivery_delay_ms, 200);
  assert.equal(e15.event_time_utc, '2026-01-15T09:06:03.000Z', 'raw preserved');
  assert.equal(e15.received_time_utc, '2026-01-15T09:06:01.200Z', 'raw preserved');
  assert.equal(e15.source_clock_offset_ms, 2000);
  for (const id of ['evt-017', 'evt-018']) assert.equal(tl.get(id).classification, 'expected_enforcement');
  assert.deepEqual(tl.get('evt-020').alert_ids, []);
  for (const id of ['evt-003', 'evt-004', 'evt-016']) assert.equal(tl.get(id).classification, 'approved_change', id);
  assert.equal(tl.get('evt-008').classification, 'alert:alert-001');
  assert.equal(tl.get('evt-009').classification, 'alert:alert-001');
  for (const id of ['evt-010', 'evt-011', 'evt-012']) assert.equal(tl.get(id).classification, 'alert:alert-002');
  for (const id of ['evt-001', 'evt-002', 'evt-005', 'evt-006', 'evt-007', 'evt-013', 'evt-014', 'evt-015', 'evt-019', 'evt-021', 'evt-022']) {
    assert.equal(tl.get(id).classification, 'routine', id);
  }
  assert.equal(r.notices.length, 0);
  assert.equal(r.stats.events, 22);
  assert.equal(r.stats.late, 0);
  assert.equal(r.stats.clock_unsupported, 0);
  assert.deepEqual(r.baseline, { source: 'documented', edgeCount: 7, documentedEdgeCount: 7, corpusEdgeCount: 0, seed: null });
  assert.equal(r.config.lmWindowMs, 60000);
});

test('window invariance 30 s / 60 s / 120 s', () => {
  const shape = (r) => r.alerts.map((a) => [a.alert_id, a.rule_id, a.event_ids]);
  const ref = shape(runPractice());
  for (const lmWindowMs of [30000, 60000, 120000]) assert.deepEqual(shape(runPractice({ lmWindowMs })), ref, `${lmWindowMs}`);
});

test('detect is deterministic apart from processing time', () => {
  assert.deepEqual(stable(runPractice()), stable(runPractice()));
});

test('detect accepts a plain approvals object and defaults', () => {
  const { events } = loadEventsFile(practiceEventsPath());
  const r = detect(events, JSON.parse(fs.readFileSync(practiceApprovalsPath(), 'utf8')));
  assert.equal(r.alerts.length, 2);
  const none = detect(events);
  // without approvals, alex's approved change becomes unapproved too
  assert.ok(none.alerts.some((a) => a.rule_id === 'PRIV-1' && a.event_ids.includes('evt-004')));
});

test('CLI node kig.cjs detect --events ... --approvals ... --json', () => {
  const r = kig(['detect', '--events', practiceEventsPath(), '--approvals', practiceApprovalsPath(), '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stderr, '');
  const out = JSON.parse(r.stdout);
  const api = runPractice();
  assert.deepEqual(stable(out).alerts, stable(api).alerts);
  assert.deepEqual(out.timeline, api.timeline);
  assert.deepEqual(out.rejects, []);
});

test('CLI human output names the alerts and the timeline', () => {
  const r = kig(['detect', '--events', practiceEventsPath(), '--approvals', practiceApprovalsPath()]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /alert-001 +PRIV-1 +high/);
  assert.match(r.stdout, /alert-002 +LM-1 +medium/);
  assert.match(r.stdout, /evt-015/);
  assert.match(r.stdout, /expected_enforcement/);
});

test('CLI --window-ms changes the config and is validated', () => {
  const ok = kig(['detect', '--events', practiceEventsPath(), '--approvals', practiceApprovalsPath(), '--window-ms', '30000', '--json']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).config.lmWindowMs, 30000);
  const bad = kig(['detect', '--events', practiceEventsPath(), '--window-ms', 'soon']);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /window-ms/);
});

test('CLI exits 2 on missing or unreadable input', () => {
  assert.equal(kig(['detect']).status, 2);
  assert.equal(kig(['detect', '--events', path.join(os.tmpdir(), 'no-such-file.csv')]).status, 2);
  assert.equal(kig(['detect', '--events', practiceEventsPath(), '--approvals', practiceEventsPath()]).status, 2, 'approvals not JSON');
  assert.equal(kig(['detect', '--events', practiceEventsPath(), '--bogus']).status, 2);
});

test('CLI control-character escaping', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-detect-'));
  const f = path.join(dir, 'evil.csv');
  const rec = {
    event_id: 'evt-\u001b]0;x\u0007', event_time_utc: '2026-01-15T09:00:00.000Z', received_time_utc: '2026-01-15T09:00:00.100Z',
    source_clock_offset_ms: '0', actor: '\u001b[31mFAKE\u001b[0m\u202e', source_service: 'reports', target_service: 'billing',
    action: 'read', role_before: 'viewer', role_after: 'viewer', outcome: 'allow', approval_id: '', session_id: 's\u009b', correlation_id: 'f',
  };
  fs.writeFileSync(f, COLUMNS.join(',') + '\n' + COLUMNS.map((c) => rec[c]).join(',') + '\n');
  for (const extra of [[], ['--json']]) {
    const r = kig(['detect', '--events', f, ...extra]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /LM-2/);
    for (const ch of ['\u001b', '\u0007', '\u009b', '\u202e']) assert.ok(!r.stdout.includes(ch), `raw ${JSON.stringify(ch)} in ${extra.join(' ') || 'human'} output`);
  }
});

test('kig help lists detect', () => {
  const r = kig(['help']);
  assert.match(r.stdout + r.stderr, /detect/);
});
