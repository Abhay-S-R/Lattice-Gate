'use strict';
// @ts-check
// Role tracker (P1-09, architecture §15.2). Replays role changes and approved
// grants/revocations in event-time order, so the detector knows each subject's
// expected role, which revocations happened recently (revocation context for
// the lateral-movement rules) and which unapproved escalations are open (PRIV-2).
// All per-identity state lives in Maps keyed by the raw strings or by
// JSON-encoded tuples; client strings never become plain-object keys.

const { matchGrant, matchRevoke, timeOf } = require('./approvals.cjs');

const ALLOWED = new Set(['allow', 'success']);
const isAllowed = (/** @type {string} */ outcome) => ALLOWED.has(outcome);
const isDenied = (/** @type {string} */ outcome) => outcome === 'deny';

/**
 * @typedef {{ subject: string, role: string, scope: Set<string>, approvalId: string, atMs: number, eventId: string }} Revocation
 * @typedef {{ kind: 'none'|'approved_admin'|'approved_grant'|'approved_revoke'|'unapproved_increase'|'unapproved_decrease'|'follow_up_access',
 *   approval?: any, reason?: string, revocationRecord?: Revocation, linkedEscalation?: any, unknownRole?: boolean }} RoleResult
 */

class RoleTracker {
  /**
   * @param {import('./approvals.cjs').ApprovalStore} approvals
   * @param {import('./config.cjs').DetectConfig} cfg
   */
  constructor(approvals, cfg) {
    this.approvals = approvals;
    this.cfg = cfg;
    /** @type {Map<string, any>} approve_role_change events by approval ID */
    this.approvedEventsById = new Map();
    /** @type {Map<string, string>} */
    this.expectedRoleByActor = new Map();
    /** @type {Map<string, string>} role held before an approved grant, keyed by [subject, role] */
    this.roleBeforeGrant = new Map();
    /** @type {Map<string, Revocation[]>} */
    this.recentRevocationsByActor = new Map();
    /** @type {Map<string, any>} open escalations keyed by [actor, 'session'|'flow', id] */
    this.activeEscalations = new Map();
  }

  /** @param {string} role */
  rankOf(role) {
    const r = this.cfg.roleRanks.get(role);
    return r === undefined ? 0 : r;
  }

  /** @param {string} role */
  isKnownRole(role) { return this.cfg.roleRanks.has(role); }

  /**
   * True when `after` grants more privilege than `before`. A change into a
   * role the configuration does not rank cannot be shown to be a decrease, so
   * it is treated as an increase (and the alert says the role is unknown).
   * @param {string} before @param {string} after
   */
  isRoleIncrease(before, after) {
    if (before === after) return false;
    if (!this.isKnownRole(after)) return true;
    return this.rankOf(after) > this.rankOf(before);
  }

  /** @param {string} actor @returns {string|undefined} */
  expectedRole(actor) { return this.expectedRoleByActor.get(actor); }

  /** @param {any} ev */
  _escalationKeys(ev) {
    const keys = [];
    if (ev.session !== '') keys.push(JSON.stringify([ev.actor, 'session', ev.session]));
    if (ev.correlation !== '') keys.push(JSON.stringify([ev.actor, 'flow', ev.correlation]));
    return keys;
  }

  /**
   * Record an open escalation so later accesses in its session/flow can be linked.
   * @param {any} ev the PRIV-1 event @param {any} alert the alert object to link to
   */
  openEscalation(ev, alert) {
    const rec = { priv1Event: ev, alert, escalatedRole: ev.roleAfter, atMs: timeOf(ev) };
    for (const k of this._escalationKeys(ev)) this.activeEscalations.set(k, rec);
  }

  /**
   * Classify one event (in event-time order) and update the tracked state.
   * @param {any} ev
   * @returns {RoleResult}
   */
  process(ev) {
    const t = timeOf(ev);
    if (!this.expectedRoleByActor.has(ev.actor) && ev.roleBefore !== '') this.expectedRoleByActor.set(ev.actor, ev.roleBefore);

    if (ev.action === 'approve_role_change') {
      if (ev.approvalId) this.approvedEventsById.set(ev.approvalId, ev);
      const a = ev.approvalId ? this.approvals.byId.get(ev.approvalId) : undefined;
      if (a && a.approvedBy === ev.actor) return { kind: 'approved_admin', approval: a };
      return { kind: 'none', reason: a ? 'approver_mismatch' : 'unknown_approval' };
    }

    if (ev.action === 'revoke_role') {
      if (!isAllowed(ev.outcome)) return { kind: 'none', reason: 'revoke_not_applied' };
      const m = matchRevoke(this.approvals, ev);
      if (!m.matched) return { kind: 'unapproved_decrease', reason: m.reason, approval: m.approval };
      return { kind: 'approved_revoke', approval: m.approval, revocationRecord: this._applyRevocation(m.approval, m.revokedScope, t, ev.id) };
    }

    if (ev.action === 'role_change') {
      if (!isAllowed(ev.outcome)) return { kind: 'none', reason: 'role_change_not_applied' };
      if (ev.roleBefore === ev.roleAfter) return { kind: 'none' };
      if (this.isRoleIncrease(ev.roleBefore, ev.roleAfter)) {
        const unknownRole = !this.isKnownRole(ev.roleAfter);
        const m = matchGrant(this.approvals, ev, this.approvedEventsById);
        this.expectedRoleByActor.set(ev.actor, ev.roleAfter);
        if (m.matched) {
          this.roleBeforeGrant.set(JSON.stringify([ev.actor, ev.roleAfter]), ev.roleBefore);
          return { kind: 'approved_grant', approval: m.approval };
        }
        return { kind: 'unapproved_increase', reason: m.reason, approval: m.approval, unknownRole };
      }
      // decrease
      const m = matchRevoke(this.approvals, ev);
      this.expectedRoleByActor.set(ev.actor, ev.roleAfter);
      if (m.matched) {
        return { kind: 'approved_revoke', approval: m.approval, revocationRecord: this._recordRevocation(m.approval, m.revokedScope, t, ev.id) };
      }
      return { kind: 'unapproved_decrease', reason: m.reason, approval: m.approval };
    }

    // Any other event: an allowed access in the session/flow of an open escalation is linked (PRIV-2).
    if (isAllowed(ev.outcome)) {
      for (const k of this._escalationKeys(ev)) {
        const esc = this.activeEscalations.get(k);
        if (esc && t >= esc.atMs && t - esc.atMs <= this.cfg.privLinkWindowMs) {
          return { kind: 'follow_up_access', linkedEscalation: esc };
        }
      }
    }
    return { kind: 'none' };
  }

  /** Operator revoke: the subject falls back to the role held before the grant. */
  _applyRevocation(/** @type {any} */ a, /** @type {string[]} */ scope, /** @type {number} */ t, /** @type {string} */ eventId) {
    const current = this.expectedRoleByActor.get(a.subject);
    if (current === undefined || current === a.role) {
      const prev = this.roleBeforeGrant.get(JSON.stringify([a.subject, a.role]));
      if (prev !== undefined) this.expectedRoleByActor.set(a.subject, prev);
      else this.expectedRoleByActor.delete(a.subject);
    }
    return this._recordRevocation(a, scope, t, eventId);
  }

  _recordRevocation(/** @type {any} */ a, /** @type {string[]} */ scope, /** @type {number} */ t, /** @type {string} */ eventId) {
    /** @type {Revocation} */
    const rec = { subject: a.subject, role: a.role, scope: new Set(scope), approvalId: a.approvalId, atMs: t, eventId };
    this.recentRevocationsByActor.set(a.subject, [...(this.recentRevocationsByActor.get(a.subject) || []), rec]);
    return rec;
  }

  /**
   * A denial explained by a recent approved revocation of this actor's role, on
   * a service that role covered (or citing the revocation's approval ID).
   * @param {any} ev
   * @returns {{ matched: boolean, revocation?: Revocation }}
   */
  isExpectedEnforcementDenial(ev) {
    if (!isDenied(ev.outcome)) return { matched: false };
    const t = timeOf(ev);
    for (const rev of this.recentRevocationsByActor.get(ev.actor) || []) {
      if (t >= rev.atMs && t - rev.atMs <= this.cfg.revocationContextWindowMs
          && (rev.scope.has(ev.dst) || (ev.approvalId !== null && ev.approvalId === rev.approvalId))) {
        return { matched: true, revocation: rev };
      }
    }
    return { matched: false };
  }
}

module.exports = { RoleTracker, isAllowed, isDenied };
