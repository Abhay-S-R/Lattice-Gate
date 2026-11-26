'use strict';
// @ts-check
// Privilege-change rules (P1-09, architecture §15.2).
//   PRIV-1  role increase without a matching approval → high alert that names
//           the missing or mismatched condition. No intent is inferred.
//   PRIV-2  later allowed accesses by that identity in the same session/flow
//           are linked into the PRIV-1 alert (they are not separate alerts).
// An unapproved role decrease is never an escalation alert: it becomes a
// low-severity notice (unrecorded_role_decrease).

const { RoleTracker } = require('./roles.cjs');
const { timeOf } = require('./approvals.cjs');

const iso = (/** @type {number} */ ms) => new Date(ms).toISOString();

/** Words for a failed grant match. @param {string} reason @param {any} ev @param {any} approval */
function explainGrant(reason, ev, approval) {
  const id = ev.approvalId;
  switch (reason) {
    case 'no_approval_id': return 'no approval is referenced by the event';
    case 'unknown_approval': return `approval ${id} is not in the change-control store`;
    case 'not_a_grant': return `approval ${id} is not a grant_role approval`;
    case 'subject_mismatch': return `approval ${id} is for a different subject, not ${ev.actor}`;
    case 'role_mismatch': return `approval ${id} grants a different role, not ${ev.roleAfter}`;
    case 'outside_validity_window':
      return `the change at ${iso(timeOf(ev))} is outside approval ${id}'s validity window `
        + `[${iso(approval.validFromMs)}, ${iso(approval.validUntilMs)}) (valid_until is exclusive)`;
    case 'approver_mismatch':
      return `the approve_role_change event for ${id} was performed by a different identity than approved_by (${approval.approvedBy})`;
    default: return reason;
  }
}

/** @param {any[]} events */
function windowOf(events) {
  const ts = events.map(timeOf);
  const start = Math.min(...ts);
  const end = Math.max(...ts);
  return { start_utc: iso(start), end_utc: iso(end), window_ms: end - start };
}

const edge = (/** @type {any} */ ev) => `${ev.src}->${ev.dst}`;

/** Recompute the derived fields of a privilege alert from its events. @param {any} a */
function refresh(a) {
  const services = [];
  for (const ev of a._events) for (const s of [ev.src, ev.dst]) if (!services.includes(s)) services.push(s);
  a.services = services;
  a.path = a._events.map(edge);
  a.event_ids = a._events.map((/** @type {any} */ e) => e.id);
  a.outcomes = a._events.map((/** @type {any} */ e) => ({ event_id: e.id, outcome: e.outcome, src: e.src, dst: e.dst }));
  a.order_uncertain = a._events.some((/** @type {any} */ e) => e.orderUncertain);
  a.window = windowOf(a._events);
  a.reason = a.linked.length
    ? `${a._baseReason} Linked later allowed access in the same session/flow (PRIV-2): ${a.linked.map((/** @type {any} */ l) => `${l.event_id} (${l.outcome})`).join(', ')}.`
    : a._baseReason;
}

/**
 * Run the role tracker over events in event-time order and produce PRIV alerts.
 * @param {any[]} events released (event-time ordered) events
 * @param {import('./approvals.cjs').ApprovalStore} approvals
 * @param {import('./config.cjs').DetectConfig} cfg
 * @param {{ mono?: () => bigint }} [hooks]
 */
function evaluatePrivilege(events, approvals, cfg, hooks = {}) {
  const tracker = new RoleTracker(approvals, cfg);
  const alerts = [];
  const notices = [];
  /** @type {Map<string, object>} */
  const eventMeta = new Map();

  for (const ev of events) {
    const r = tracker.process(ev);
    switch (r.kind) {
      case 'approved_admin':
      case 'approved_grant':
      case 'approved_revoke':
        eventMeta.set(ev.id, { classification: 'approved_change', kind: r.kind, approval_id: r.approval.approvalId });
        break;
      case 'unapproved_increase': {
        const roleNote = r.unknownRole ? ` (${ev.roleAfter} is an unknown role, treated as an increase)` : '';
        const a = {
          rule_id: 'PRIV-1',
          severity: 'high',
          classification: 'unexpected_privilege_change',
          identity: ev.actor,
          session: ev.session,
          correlation: ev.correlation,
          related_rules: [],
          linked: [],
          last_evidence_received_ms: ev.receivedMs,
          emitted_sim_ms: ev.releasedAtMs ?? ev.receivedMs,
          emitted_at_mono_ns: hooks.mono ? hooks.mono() : null,
          _events: [ev],
          _baseReason: `PRIV-1: role increase ${ev.roleBefore} -> ${ev.roleAfter}${roleNote} for ${ev.actor} has no matching approval: `
            + `${explainGrant(/** @type {string} */ (r.reason), ev, r.approval)}. The records show the change succeeded; they do not show why.`,
        };
        refresh(a);
        alerts.push(a);
        tracker.openEscalation(ev, a);
        eventMeta.set(ev.id, { classification: 'unexpected_privilege_change' });
        break;
      }
      case 'follow_up_access': {
        const a = r.linkedEscalation.alert;
        a._events.push(ev);
        a.linked.push({ rule_id: 'PRIV-2', event_id: ev.id, outcome: ev.outcome });
        if (!a.related_rules.includes('PRIV-2')) a.related_rules.push('PRIV-2');
        refresh(a);
        eventMeta.set(ev.id, { classification: 'access_after_unexpected_privilege', linked_to_event: r.linkedEscalation.priv1Event.id });
        break;
      }
      case 'unapproved_decrease': {
        const subject = ev.action === 'revoke_role' && r.approval ? r.approval.subject : ev.actor;
        notices.push({
          rule_id: 'PRIV-DEC',
          severity: 'low',
          classification: 'unrecorded_role_decrease',
          identity: subject,
          event_ids: [ev.id],
          reason: `Role decrease ${ev.action === 'revoke_role' ? `by ${ev.actor} for ${subject}` : `${ev.roleBefore} -> ${ev.roleAfter} for ${ev.actor}`} `
            + `has no matching revoke_role approval (${r.reason}). A decrease is never treated as an escalation.`,
        });
        eventMeta.set(ev.id, { classification: 'unrecorded_role_decrease' });
        break;
      }
      default:
        break;
    }
  }
  return { alerts, notices, tracker, eventMeta };
}

module.exports = { evaluatePrivilege };
