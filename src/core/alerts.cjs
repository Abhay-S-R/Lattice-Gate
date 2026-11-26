'use strict';
// @ts-check
// Adapter self-monitoring alerts (P0-10, architecture §5.7, Task 1.13).
//
// Evaluated inside the same transaction as the decision; each alert is an
// audit_events row with kind='alert'. Alerts never change a response, never
// print anything and never lock anyone out. detail is { severity, reason }
// with fixed reason text: client values appear only in the (encoded) actor,
// asset and request_id columns, never in detail.

const { BURST_N, BURST_WINDOW_MS } = require('./limits.cjs');
const audit = require('./audit.cjs');

/**
 * @typedef {{ op: string, actor?: string, asset?: string, decision?: 'allow'|'deny', rule?: string,
 *             invalidInput?: boolean, invalidKey?: boolean, hostile?: string[] }} AlertContext
 * @typedef {{ rule: string, severity: 'info'|'low'|'medium'|'high', reason: string }} Alert
 */

/**
 * Which rules fire for this event. Call after the access event is appended
 * (A-BURST counts it).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {number} gen
 * @param {AlertContext} c
 * @returns {Alert[]}
 */
function evaluate(db, gen, c) {
  /** @type {Alert[]} */
  const out = [];
  if (c.rule === 'actor_revoked' && (c.op === 'read' || c.op === 'protected_read')) {
    out.push({ rule: 'A-REVOKED-RETRY', severity: 'medium', reason: 'revoked or disabled actor attempted access' });
  }
  if (c.rule === 'not_owner') {
    out.push({ rule: 'A-CROSS-OWNER', severity: 'low', reason: 'actor requested an asset it does not own' });
  }
  if (c.invalidInput) {
    out.push({ rule: 'A-INVALID-INPUT', severity: 'low', reason: 'request failed validation' });
  }
  if (c.invalidKey) {
    out.push({ rule: 'A-INVALID-KEY', severity: 'medium', reason: 'ML-KEM public key failed the FIPS 203 import check' });
  }
  if (c.hostile && c.hostile.length > 0) {
    out.push({ rule: 'A-HOSTILE-ID', severity: 'info', reason: `${c.hostile.length} identifier(s) with control characters, lone surrogates, path segments or prototype names` });
  }
  if (c.decision === 'deny' && typeof c.actor === 'string'
      && audit.countRecentDenies(db, gen, c.actor, Date.now() - BURST_WINDOW_MS) === BURST_N) {
    out.push({ rule: 'A-BURST', severity: 'high', reason: `${BURST_N} denials for one actor within ${BURST_WINDOW_MS / 1000} s` });
  }
  return out;
}

/**
 * One kind='alert' event per alert. Must run inside a tx.
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {number} gen
 * @param {{ op?: string, request_id?: string|null, actor?: string, asset?: string }} base
 * @param {Alert[]} list
 */
function appendAlerts(db, gen, base, list) {
  for (const a of list) {
    audit.append(db, {
      gen, kind: 'alert', op: base.op, request_id: base.request_id ?? undefined,
      actor: base.actor, asset: base.asset, rule: a.rule, detail: { severity: a.severity, reason: a.reason },
    });
  }
}

/**
 * evaluate + appendAlerts inside a SAVEPOINT: if anything about alerting
 * fails, its rows are rolled back and the surrounding decision still commits.
 * Must run inside a tx. Returns the alerts written ([] on failure).
 * @param {import('node:sqlite').DatabaseSync} db
 * @param {number} gen
 * @param {{ op?: string, request_id?: string|null, actor?: string, asset?: string }} base
 * @param {AlertContext} c
 * @returns {Alert[]}
 */
function record(db, gen, base, c) {
  db.exec('SAVEPOINT kig_alerts');
  try {
    const list = module.exports.evaluate(db, gen, c); // via exports so tests can stub it
    appendAlerts(db, gen, base, list);
    db.exec('RELEASE kig_alerts');
    return list;
  } catch {
    try {
      db.exec('ROLLBACK TO kig_alerts');
      db.exec('RELEASE kig_alerts');
    } catch { /* the outer tx fails closed */ }
    return [];
  }
}

module.exports = { evaluate, appendAlerts, record };
