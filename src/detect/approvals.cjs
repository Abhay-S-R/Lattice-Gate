'use strict';
// @ts-check
// Change-control store and matching (P1-09, architecture §15.2).
// Two approval shapes: grant_role (scope + [valid_from, valid_until), the end
// exclusive) and revoke_role (effective_at). The store is the authority: the
// actor performing a role_change need not be the approver (practice evt-004).

const fs = require('node:fs');
const { parseUtc } = require('./ingest.cjs');

/**
 * @typedef {{ approvalId: string, approvedBy: string, subject: string, operation: 'grant_role'|'revoke_role',
 *   role: string, scope: string[], validFromMs: number|null, validUntilMs: number|null, effectiveAtMs: number|null }} Approval
 * @typedef {{ byId: Map<string, Approval>, grantsBySubjectRole: Map<string, Approval[]>, size: number }} ApprovalStore
 */

const subjectRoleKey = (/** @type {string} */ subject, /** @type {string} */ role) => JSON.stringify([subject, role]);

/** Time used for matching: corrected time, or receipt time when the source clock is unsupported. */
const timeOf = (/** @type {any} */ ev) => (typeof ev.orderMs === 'number' ? ev.orderMs : ev.correctedMs);

/** @param {unknown} obj parsed approvals.json ({ changes: [...] }) @returns {ApprovalStore} */
function loadApprovals(obj) {
  if (obj === null || typeof obj !== 'object' || !Array.isArray(/** @type {any} */ (obj).changes)) {
    throw new TypeError('approvals must be an object with a "changes" array');
  }
  /** @type {Map<string, Approval>} */
  const byId = new Map();
  /** @type {Map<string, Approval[]>} */
  const grantsBySubjectRole = new Map();
  /** @type {any[]} */
  const changes = /** @type {any} */ (obj).changes;
  changes.forEach((c, i) => {
    const where = `approvals.changes[${i}]`;
    if (c === null || typeof c !== 'object' || Array.isArray(c)) throw new TypeError(`${where} must be an object`);
    const str = (/** @type {string} */ k) => {
      const v = Object.prototype.hasOwnProperty.call(c, k) ? c[k] : undefined;
      if (typeof v !== 'string' || v === '') throw new TypeError(`${where}.${k} must be a non-empty string`);
      return v;
    };
    const time = (/** @type {string} */ k) => {
      const ms = parseUtc(str(k));
      if (Number.isNaN(ms)) throw new TypeError(`${where}.${k} is not an ISO-8601 UTC time`);
      return ms;
    };
    const approvalId = str('approval_id');
    if (byId.has(approvalId)) throw new TypeError(`${where}: duplicate approval_id`);
    const operation = str('operation');
    /** @type {Approval} */
    let a;
    if (operation === 'grant_role') {
      const scope = Object.prototype.hasOwnProperty.call(c, 'scope') ? c.scope : undefined;
      if (!Array.isArray(scope) || !scope.every((s) => typeof s === 'string' && s !== '')) {
        throw new TypeError(`${where}.scope must be an array of service names`);
      }
      const validFromMs = time('valid_from_utc');
      const validUntilMs = time('valid_until_utc');
      if (!(validFromMs < validUntilMs)) throw new RangeError(`${where}: valid_from_utc must be before valid_until_utc`);
      a = { approvalId, approvedBy: str('approved_by'), subject: str('subject'), operation, role: str('role'), scope: [...scope], validFromMs, validUntilMs, effectiveAtMs: null };
      const key = subjectRoleKey(a.subject, a.role);
      grantsBySubjectRole.set(key, [...(grantsBySubjectRole.get(key) || []), a]);
    } else if (operation === 'revoke_role') {
      a = { approvalId, approvedBy: str('approved_by'), subject: str('subject'), operation, role: str('role'), scope: [], validFromMs: null, validUntilMs: null, effectiveAtMs: time('effective_at_utc') };
    } else {
      throw new TypeError(`${where}.operation must be grant_role or revoke_role`);
    }
    byId.set(approvalId, a);
  });
  return { byId, grantsBySubjectRole, size: byId.size };
}

/** @param {string} filePath */
function loadApprovalsFile(filePath) {
  return loadApprovals(JSON.parse(fs.readFileSync(filePath, 'utf8')));
}

/**
 * Does an approval authorize this role increase? Checks, in order: approval ID
 * present, known, a grant, subject, role, time (valid_until exclusive), and that
 * any approve_role_change event seen for it was performed by the approver.
 * @param {ApprovalStore} store
 * @param {any} ev role_change event
 * @param {Map<string, any>} approvedEventsById approve_role_change events seen so far
 * @returns {{ matched: true, approval: Approval } | { matched: false, reason: string, approval?: Approval }}
 */
function matchGrant(store, ev, approvedEventsById) {
  if (!ev.approvalId) return { matched: false, reason: 'no_approval_id' };
  const a = store.byId.get(ev.approvalId);
  if (!a) return { matched: false, reason: 'unknown_approval' };
  if (a.operation !== 'grant_role') return { matched: false, reason: 'not_a_grant' };
  if (a.subject !== ev.actor) return { matched: false, reason: 'subject_mismatch' };
  if (a.role !== ev.roleAfter) return { matched: false, reason: 'role_mismatch' };
  const t = timeOf(ev);
  if (!(/** @type {number} */ (a.validFromMs) <= t && t < /** @type {number} */ (a.validUntilMs))) {
    return { matched: false, reason: 'outside_validity_window', approval: a };
  }
  const approveEv = approvedEventsById.get(ev.approvalId);
  if (approveEv && approveEv.actor !== a.approvedBy) return { matched: false, reason: 'approver_mismatch', approval: a };
  return { matched: true, approval: a };
}

/**
 * Service scope that the subject's grants of this role covered (union of the
 * grants that started no later than `atMs`).
 * @param {ApprovalStore} store @param {string} subject @param {string} role @param {number} atMs
 */
function grantedScope(store, subject, role, atMs) {
  const grants = store.grantsBySubjectRole.get(subjectRoleKey(subject, role)) || [];
  const scope = new Set();
  for (const g of grants) if (/** @type {number} */ (g.validFromMs) <= atMs) for (const s of g.scope) scope.add(s);
  return [...scope];
}

/**
 * Does an approval authorize this revocation? For an operator's revoke_role
 * event the actor must be the approver; for a subject's own role_change
 * decrease the actor must be the subject and role_before the revoked role.
 * @param {ApprovalStore} store
 * @param {any} ev revoke_role or decreasing role_change event
 * @returns {{ matched: true, approval: Approval, revokedScope: string[] } | { matched: false, reason: string, approval?: Approval }}
 */
function matchRevoke(store, ev) {
  if (!ev.approvalId) return { matched: false, reason: 'no_approval_id' };
  const a = store.byId.get(ev.approvalId);
  if (!a) return { matched: false, reason: 'unknown_approval' };
  if (a.operation !== 'revoke_role') return { matched: false, reason: 'not_a_revoke' };
  const t = timeOf(ev);
  if (!(t >= /** @type {number} */ (a.effectiveAtMs))) return { matched: false, reason: 'before_effective_time', approval: a };
  if (ev.action === 'revoke_role') {
    if (ev.actor !== a.approvedBy) return { matched: false, reason: 'approver_mismatch', approval: a };
  } else {
    if (ev.actor !== a.subject) return { matched: false, reason: 'subject_mismatch', approval: a };
    if (ev.roleBefore !== a.role) return { matched: false, reason: 'role_mismatch', approval: a };
  }
  return { matched: true, approval: a, revokedScope: grantedScope(store, a.subject, a.role, t) };
}

module.exports = { loadApprovals, loadApprovalsFile, matchGrant, matchRevoke, grantedScope, timeOf };
