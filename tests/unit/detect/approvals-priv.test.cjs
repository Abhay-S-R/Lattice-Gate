'use strict';
// Task 5.2: approvals, role tracking, PRIV-1 / PRIV-2 (P1-09).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseCsv, loadEventsFile, COLUMNS } = require('../../../src/detect/ingest.cjs');
const { correct } = require('../../../src/detect/clock.cjs');
const { ReorderBuffer } = require('../../../src/detect/reorder.cjs');
const { mergeConfig } = require('../../../src/detect/config.cjs');
const { loadApprovals, matchGrant, matchRevoke } = require('../../../src/detect/approvals.cjs');
const { RoleTracker } = require('../../../src/detect/roles.cjs');
const { evaluatePrivilege } = require('../../../src/detect/rules-priv.cjs');
const { practiceEventsPath, practiceApprovals } = require('../../helpers/practice.cjs');

const cfg = mergeConfig();

/** Parse, correct and reorder, like the pipeline does. */
function ordered(events) {
  const buf = new ReorderBuffer(cfg);
  const out = [];
  for (const e of events) out.push(...buf.push(correct(e, cfg)));
  out.push(...buf.flush());
  return out;
}
const practice = () => ordered(loadEventsFile(practiceEventsPath()).events);
const byId = (events) => new Map(events.map((e) => [e.id, e]));

function csvEvents(rows) {
  const line = (o) => COLUMNS.map((c) => o[c] ?? '').join(',');
  const base = { source_clock_offset_ms: '0', source_service: 'admin-console', target_service: 'identity', session_id: 's', correlation_id: 'f' };
  const text = [COLUMNS.join(','), ...rows.map((r) => line({ ...base, received_time_utc: r.event_time_utc, ...r }))].join('\n');
  const res = parseCsv(text);
  assert.deepEqual(res.rejects, []);
  return ordered(res.events);
}

// ---- approval store ----

test('loadApprovals indexes both shapes in Maps and parses times', () => {
  const store = loadApprovals(practiceApprovals());
  assert.ok(store.byId instanceof Map);
  const g = store.byId.get('change-100');
  assert.equal(g.operation, 'grant_role');
  assert.equal(g.validFromMs, Date.parse('2026-01-15T09:01:00Z'));
  assert.equal(g.validUntilMs, Date.parse('2026-01-15T09:07:00Z'));
  assert.deepEqual(g.scope, ['reports', 'reports-node-a', 'reports-node-b']);
  const r = store.byId.get('change-101');
  assert.equal(r.operation, 'revoke_role');
  assert.equal(r.effectiveAtMs, Date.parse('2026-01-15T09:07:00Z'));
});

test('loadApprovals rejects malformed approvals loudly', () => {
  const g = practiceApprovals().changes[0];
  assert.throws(() => loadApprovals({ changes: [{ ...g, operation: 'make_admin' }] }), /operation/);
  assert.throws(() => loadApprovals({ changes: [{ ...g, valid_until_utc: 'soon' }] }), /valid_until_utc/);
  assert.throws(() => loadApprovals({ changes: [{ ...g, valid_until_utc: g.valid_from_utc }] }), /before/);
  assert.throws(() => loadApprovals({ changes: [g, g] }), /duplicate/);
  assert.throws(() => loadApprovals({ changes: [{ ...g, scope: 'reports' }] }), /scope/);
  assert.throws(() => loadApprovals({}), /changes/);
  assert.equal(loadApprovals({ changes: [] }).byId.size, 0);
});

// ---- practice-set behaviour ----

test('evt-003..005 approved', () => {
  const events = practice();
  const store = loadApprovals(practiceApprovals());
  const e = byId(events);
  const m = matchGrant(store, e.get('evt-004'), new Map([['change-100', e.get('evt-003')]]));
  assert.equal(m.matched, true);
  assert.equal(m.approval.approvalId, 'change-100');
  assert.equal(e.get('evt-004').actor, 'user-alex');
  assert.equal(m.approval.approvedBy, 'user-admin', 'actor need not be the approver');

  const tracker = new RoleTracker(store, cfg);
  const kinds = new Map(events.map((ev) => [ev.id, tracker.process(ev).kind]));
  assert.equal(kinds.get('evt-003'), 'approved_admin');
  assert.equal(kinds.get('evt-004'), 'approved_grant');
  assert.equal(kinds.get('evt-005'), 'none');

  const res = evaluatePrivilege(events, store, cfg);
  assert.equal(res.alerts.filter((a) => a.event_ids.some((id) => ['evt-003', 'evt-004', 'evt-005'].includes(id))).length, 0);
});

test('evt-008 unapproved escalation links evt-009', () => {
  const res = evaluatePrivilege(practice(), loadApprovals(practiceApprovals()), cfg);
  assert.equal(res.alerts.length, 1);
  const [a] = res.alerts;
  assert.equal(a.rule_id, 'PRIV-1');
  assert.equal(a.severity, 'high');
  assert.equal(a.classification, 'unexpected_privilege_change');
  assert.equal(a.identity, 'user-blair');
  assert.deepEqual(a.event_ids, ['evt-008', 'evt-009']);
  assert.deepEqual(a.outcomes.map((o) => [o.event_id, o.outcome]), [['evt-008', 'success'], ['evt-009', 'allow']]);
  assert.deepEqual(a.related_rules, ['PRIV-2']);
  assert.deepEqual(a.linked.map((l) => [l.rule_id, l.event_id]), [['PRIV-2', 'evt-009']]);
  assert.match(a.reason, /viewer -> operator/);
  assert.match(a.reason, /no approval/i);
  assert.match(a.reason, /evt-009/);
  assert.doesNotMatch(a.reason, /malicious|attack|compromise|intent(?!ion)/i, 'never infers intent');
  assert.equal(res.eventMeta.get('evt-009').classification, 'access_after_unexpected_privilege');
  assert.equal(a.last_evidence_received_ms, Date.parse('2026-01-15T09:03:05.200Z'), 'emission evidence is evt-008 only');
});

test('evt-016 revoke_role matches change-101', () => {
  const events = practice();
  const store = loadApprovals(practiceApprovals());
  const e = byId(events);
  const m = matchRevoke(store, e.get('evt-016'));
  assert.equal(m.matched, true);
  assert.deepEqual(m.revokedScope, ['reports', 'reports-node-a', 'reports-node-b']);

  const tracker = new RoleTracker(store, cfg);
  const results = new Map(events.map((ev) => [ev.id, tracker.process(ev)]));
  assert.equal(results.get('evt-016').kind, 'approved_revoke');
  assert.equal(tracker.expectedRole('user-alex'), 'viewer');
  const rev = results.get('evt-016').revocationRecord;
  assert.equal(rev.subject, 'user-alex');
  assert.equal(rev.role, 'report-reader');
  assert.deepEqual([...rev.scope], ['reports', 'reports-node-a', 'reports-node-b']);
  assert.equal(rev.approvalId, 'change-101');
  assert.equal(evaluatePrivilege(events, store, cfg).alerts.filter((a) => a.event_ids.includes('evt-016')).length, 0);
});

test('isExpectedEnforcementDenial true for evt-017 and evt-018, false for unrelated target billing', () => {
  const events = practice();
  const { tracker } = evaluatePrivilege(events, loadApprovals(practiceApprovals()), cfg);
  const e = byId(events);
  assert.equal(tracker.isExpectedEnforcementDenial(e.get('evt-017')).matched, true);
  assert.equal(tracker.isExpectedEnforcementDenial(e.get('evt-018')).matched, true);
  assert.equal(tracker.isExpectedEnforcementDenial(e.get('evt-018')).revocation.approvalId, 'change-101');
  // same actor, unrelated sensitive target, no approval reference
  const billing = { ...e.get('evt-018'), id: 'x', dst: 'billing', approvalId: null };
  assert.equal(tracker.isExpectedEnforcementDenial(billing).matched, false);
  // allowed requests are never "expected enforcement"
  assert.equal(tracker.isExpectedEnforcementDenial({ ...e.get('evt-018'), outcome: 'allow' }).matched, false);
  // other actors are unaffected; casey's billing denial is not enforcement of alex's revocation
  assert.equal(tracker.isExpectedEnforcementDenial(e.get('evt-020')).matched, false);
  // outside the context window
  const tooLate = { ...e.get('evt-018'), correctedMs: e.get('evt-016').correctedMs + cfg.revocationContextWindowMs + 1 };
  tooLate.orderMs = tooLate.correctedMs;
  assert.equal(tracker.isExpectedEnforcementDenial(tooLate).matched, false);
  // before the revocation
  const before = { ...e.get('evt-018'), correctedMs: e.get('evt-016').correctedMs - 1 };
  before.orderMs = before.correctedMs;
  assert.equal(tracker.isExpectedEnforcementDenial(before).matched, false);
});

// ---- edge cases ----

const T = (s) => `2026-01-15T${s}Z`;
const APPROVALS = {
  changes: [
    { approval_id: 'g1', approved_by: 'boss', subject: 'sam', operation: 'grant_role', role: 'report-reader', scope: ['reports'], valid_from_utc: T('09:01:00'), valid_until_utc: T('09:07:00') },
    { approval_id: 'r1', approved_by: 'boss', subject: 'sam', operation: 'revoke_role', role: 'report-reader', effective_at_utc: T('09:30:00') },
  ],
};
const roleChange = (o) => ({ event_id: 'rc', event_time_utc: T('09:02:00.000'), actor: 'sam', action: 'role_change', role_before: 'viewer', role_after: 'report-reader', outcome: 'success', approval_id: 'g1', ...o });

test('valid_until_utc is exclusive', () => {
  const store = loadApprovals(APPROVALS);
  const [atEnd] = csvEvents([roleChange({ event_time_utc: T('09:07:00.000') })]);
  const m = matchGrant(store, atEnd, new Map());
  assert.deepEqual([m.matched, m.reason], [false, 'outside_validity_window']);
  const [justBefore] = csvEvents([roleChange({ event_time_utc: T('09:06:59.999') })]);
  assert.equal(matchGrant(store, justBefore, new Map()).matched, true);
  const [atStart] = csvEvents([roleChange({ event_time_utc: T('09:01:00.000') })]);
  assert.equal(matchGrant(store, atStart, new Map()).matched, true, 'valid_from is inclusive');
  const res = evaluatePrivilege(csvEvents([roleChange({ event_time_utc: T('09:07:00.000') })]), store, cfg);
  assert.equal(res.alerts.length, 1);
  assert.equal(res.alerts[0].rule_id, 'PRIV-1');
  assert.match(res.alerts[0].reason, /validity window/);
});

test('validity uses corrected time, not raw source time', () => {
  // raw 09:07:01 with +2000 ms source offset → corrected 09:06:59, inside the window
  const [e] = csvEvents([roleChange({ event_time_utc: T('09:07:01.000'), received_time_utc: T('09:06:59.100'), source_clock_offset_ms: '2000' })]);
  assert.equal(matchGrant(loadApprovals(APPROVALS), e, new Map()).matched, true);
});

test('subject mismatch and role mismatch rejected with explicit reason', () => {
  const store = loadApprovals(APPROVALS);
  const [other] = csvEvents([roleChange({ actor: 'pat' })]);
  assert.deepEqual(matchGrant(store, other, new Map()), { matched: false, reason: 'subject_mismatch' });
  const [wrongRole] = csvEvents([roleChange({ role_after: 'operator' })]);
  assert.deepEqual(matchGrant(store, wrongRole, new Map()), { matched: false, reason: 'role_mismatch' });
  const [none] = csvEvents([roleChange({ approval_id: '' })]);
  assert.deepEqual(matchGrant(store, none, new Map()), { matched: false, reason: 'no_approval_id' });
  const [unknown] = csvEvents([roleChange({ approval_id: 'nope' })]);
  assert.deepEqual(matchGrant(store, unknown, new Map()), { matched: false, reason: 'unknown_approval' });
  const [notGrant] = csvEvents([roleChange({ approval_id: 'r1' })]);
  assert.deepEqual(matchGrant(store, notGrant, new Map()), { matched: false, reason: 'not_a_grant' });
  for (const [ev, word] of [[other, /subject/], [wrongRole, /role/]]) {
    const res = evaluatePrivilege([ev], store, cfg);
    assert.equal(res.alerts.length, 1);
    assert.match(res.alerts[0].reason, word);
  }
});

test('approver cross-check against a prior approve_role_change event', () => {
  const store = loadApprovals(APPROVALS);
  const events = csvEvents([
    { event_id: 'ap', event_time_utc: T('09:01:30.000'), actor: 'mallory', action: 'approve_role_change', role_before: 'operator', role_after: 'operator', outcome: 'success', approval_id: 'g1' },
    roleChange({}),
  ]);
  const res = evaluatePrivilege(events, store, cfg);
  assert.equal(res.alerts.length, 1);
  assert.match(res.alerts[0].reason, /approved_by/);
  const ok = csvEvents([
    { event_id: 'ap', event_time_utc: T('09:01:30.000'), actor: 'boss', action: 'approve_role_change', role_before: 'operator', role_after: 'operator', outcome: 'success', approval_id: 'g1' },
    roleChange({}),
  ]);
  assert.equal(evaluatePrivilege(ok, store, cfg).alerts.length, 0);
});

test('role decrease without approval never raises high alert', () => {
  const store = loadApprovals(APPROVALS);
  const res = evaluatePrivilege(csvEvents([roleChange({ role_before: 'operator', role_after: 'viewer', approval_id: '' })]), store, cfg);
  assert.equal(res.alerts.length, 0);
  assert.equal(res.notices.length, 1);
  assert.equal(res.notices[0].severity, 'low');
  assert.equal(res.notices[0].classification, 'unrecorded_role_decrease');
  // an approved decrease by the subject is fine
  const ok = evaluatePrivilege(csvEvents([roleChange({ event_time_utc: T('09:31:00.000'), role_before: 'report-reader', role_after: 'viewer', approval_id: 'r1' })]), store, cfg);
  assert.deepEqual([ok.alerts.length, ok.notices.length], [0, 0]);
});

test('a denied role change is not an escalation', () => {
  const res = evaluatePrivilege(csvEvents([roleChange({ approval_id: '', role_after: 'operator', outcome: 'deny' })]), loadApprovals(APPROVALS), cfg);
  assert.equal(res.alerts.length, 0);
});

test('a change into an unknown role is treated as an increase', () => {
  const res = evaluatePrivilege(csvEvents([roleChange({ approval_id: '', role_after: 'superuser' })]), loadApprovals(APPROVALS), cfg);
  assert.equal(res.alerts.length, 1);
  assert.match(res.alerts[0].reason, /unknown role/);
});

test('PRIV-2 links only allowed accesses in the same session or flow, within the link window', () => {
  const events = csvEvents([
    roleChange({ event_id: 'esc', approval_id: '', role_after: 'operator', session_id: 's1', correlation_id: 'f1' }),
    { event_id: 'same-session', event_time_utc: T('09:02:05.000'), actor: 'sam', source_service: 'portal', target_service: 'reports', action: 'read', role_before: 'operator', role_after: 'operator', outcome: 'allow', session_id: 's1', correlation_id: 'fx' },
    { event_id: 'same-flow', event_time_utc: T('09:02:06.000'), actor: 'sam', source_service: 'portal', target_service: 'reports', action: 'read', role_before: 'operator', role_after: 'operator', outcome: 'success', session_id: 'sx', correlation_id: 'f1' },
    { event_id: 'denied', event_time_utc: T('09:02:07.000'), actor: 'sam', source_service: 'portal', target_service: 'billing', action: 'read', role_before: 'operator', role_after: 'operator', outcome: 'deny', session_id: 's1', correlation_id: 'f1' },
    { event_id: 'other-session', event_time_utc: T('09:02:08.000'), actor: 'sam', source_service: 'portal', target_service: 'reports', action: 'read', role_before: 'operator', role_after: 'operator', outcome: 'allow', session_id: 's9', correlation_id: 'f9' },
    { event_id: 'other-actor', event_time_utc: T('09:02:09.000'), actor: 'pat', source_service: 'portal', target_service: 'reports', action: 'read', role_before: 'viewer', role_after: 'viewer', outcome: 'allow', session_id: 's1', correlation_id: 'f1' },
    { event_id: 'too-late', event_time_utc: T('09:40:00.000'), actor: 'sam', source_service: 'portal', target_service: 'reports', action: 'read', role_before: 'operator', role_after: 'operator', outcome: 'allow', session_id: 's1', correlation_id: 'f1' },
  ]);
  const res = evaluatePrivilege(events, loadApprovals(APPROVALS), cfg);
  assert.equal(res.alerts.length, 1);
  assert.deepEqual(res.alerts[0].event_ids, ['esc', 'same-session', 'same-flow']);
});

test('prototype-key actor/approval_id (__proto__, constructor) handled safely via Map', () => {
  const store = loadApprovals({
    changes: [
      { approval_id: '__proto__', approved_by: 'constructor', subject: '__proto__', operation: 'grant_role', role: 'report-reader', scope: ['toString'], valid_from_utc: T('09:00:00'), valid_until_utc: T('10:00:00') },
      { approval_id: 'constructor', approved_by: 'constructor', subject: '__proto__', operation: 'revoke_role', role: 'report-reader', effective_at_utc: T('09:30:00') },
    ],
  });
  assert.equal(store.byId.get('__proto__').subject, '__proto__');
  const events = csvEvents([
    roleChange({ event_id: 'a', actor: '__proto__', approval_id: '__proto__', session_id: '__proto__' }),
    { event_id: 'b', event_time_utc: T('09:31:00.000'), actor: 'constructor', action: 'revoke_role', role_before: 'operator', role_after: 'operator', outcome: 'success', approval_id: 'constructor', session_id: 'constructor' },
    { event_id: 'c', event_time_utc: T('09:31:05.000'), actor: '__proto__', source_service: 'portal', target_service: 'toString', action: 'read', role_before: 'viewer', role_after: 'viewer', outcome: 'deny', approval_id: '', session_id: 'hasOwnProperty' },
  ]);
  const res = evaluatePrivilege(events, store, cfg);
  assert.equal(res.alerts.length, 0);
  assert.equal(res.tracker.expectedRole('__proto__'), 'viewer');
  assert.equal(res.tracker.isExpectedEnforcementDenial(events[2]).matched, true);
  assert.equal(({}).polluted, undefined);
});
