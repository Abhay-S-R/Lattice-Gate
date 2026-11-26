'use strict';
// @ts-check
// Detector pipeline (architecture §15.1): ingest → clock → reorder → role
// tracker → rules → alerts + timeline. Deterministic and rule-based; it reads
// only events, approvals, a baseline and a config.

const { mergeConfig, configSummary } = require('./config.cjs');
const { correct } = require('./clock.cjs');
const { ReorderBuffer } = require('./reorder.cjs');
const { loadApprovals, timeOf } = require('./approvals.cjs');
const { Baseline } = require('./baseline.cjs');
const { evaluatePrivilege } = require('./rules-priv.cjs');
const { evaluateLateralMovement } = require('./rules-lm.cjs');

const RULE_ORDER = ['PRIV-1', 'PRIV-2', 'LM-1', 'LM-2', 'LM-3'];
const iso = (/** @type {number} */ ms) => new Date(ms).toISOString();

/** @param {any} a */
const firstTime = (a) => Math.min(...a._events.map(timeOf));

/** Public view of an alert: fixed field order, no internal fields. @param {any} a @param {string} id */
function finalize(a, id) {
  /** @type {Record<string, unknown>} */
  const out = {
    alert_id: id,
    rule_id: a.rule_id,
    severity: a.severity,
    classification: a.classification,
    identity: a.identity,
    session: a.session,
    correlation: a.correlation,
    services: a.services,
    path: a.path,
    event_ids: a.event_ids,
    outcomes: a.outcomes,
    reason: a.reason,
    order_uncertain: a.order_uncertain,
    window: a.window,
  };
  if (a.related_rules) out.related_rules = a.related_rules;
  if (a.linked) out.linked = a.linked;
  if (a.also_matched) out.also_matched = a.also_matched;
  out.last_evidence_received_ms = a.last_evidence_received_ms;
  out.emitted_sim_ms = a.emitted_sim_ms;
  // Time-to-alert on the simulated collector clock, including the watermark wait.
  out.tta_ms = a.emitted_sim_ms - a.last_evidence_received_ms;
  out.emitted_at_mono_ns = a.emitted_at_mono_ns === null ? null : Number(a.emitted_at_mono_ns);
  return out;
}

/** @param {unknown} approvals */
function toStore(approvals) {
  if (approvals && typeof approvals === 'object' && /** @type {any} */ (approvals).byId instanceof Map) return /** @type {any} */ (approvals);
  return loadApprovals(approvals ?? { changes: [] });
}

/**
 * @param {import('./ingest.cjs').DetectEvent[]} rawEvents parsed events (any order; processed by ingestIdx)
 * @param {unknown} [approvals] ApprovalStore or parsed approvals.json
 * @param {Baseline} [baseline] defaults to the documented practice edges
 * @param {Record<string, unknown>} [cfgOverrides]
 */
function detect(rawEvents, approvals, baseline, cfgOverrides = {}) {
  const cfg = mergeConfig(cfgOverrides);
  const store = toStore(approvals);
  const base = baseline || Baseline.fromDocumented();
  const t0 = process.hrtime.bigint();
  const hooks = { mono: () => process.hrtime.bigint() - t0 };

  // Clock correction and reordering, fed in arrival order.
  const buf = new ReorderBuffer(cfg);
  const released = [];
  for (const ev of [...rawEvents].sort((a, b) => a.ingestIdx - b.ingestIdx)) released.push(...buf.push(correct(ev, cfg)));
  released.push(...buf.flush());

  const priv = evaluatePrivilege(released, store, cfg, hooks);
  const lm = evaluateLateralMovement(released, base, priv.tracker, cfg, hooks);
  const processingNs = process.hrtime.bigint() - t0;

  const raw = [...priv.alerts, ...lm.alerts].sort((a, b) => firstTime(a) - firstTime(b)
    || a.emitted_sim_ms - b.emitted_sim_ms || RULE_ORDER.indexOf(a.rule_id) - RULE_ORDER.indexOf(b.rule_id));
  const alerts = raw.map((a, i) => finalize(a, `alert-${String(i + 1).padStart(3, '0')}`));
  const notices = priv.notices.map((n, i) => ({ notice_id: `notice-${String(i + 1).padStart(3, '0')}`, ...n }));

  /** @type {Map<string, string[]>} */
  const alertIdsByEvent = new Map();
  for (const a of alerts) for (const id of /** @type {string[]} */ (a.event_ids)) {
    alertIdsByEvent.set(id, [...(alertIdsByEvent.get(id) || []), /** @type {string} */ (a.alert_id)]);
  }

  const timeline = released.map((ev, orderIdx) => {
    const alertIds = alertIdsByEvent.get(ev.id) || [];
    const pm = /** @type {any} */ (priv.eventMeta.get(ev.id));
    const lmm = /** @type {any} */ (lm.eventMeta.get(ev.id));
    let classification = 'routine';
    if (alertIds.length) classification = `alert:${alertIds[0]}`;
    else if (lmm && lmm.classification === 'expected_enforcement') classification = 'expected_enforcement';
    else if (pm && pm.classification === 'approved_change') classification = 'approved_change';
    else if (pm && pm.classification === 'unrecorded_role_decrease') classification = 'unrecorded_role_decrease';
    return {
      event_id: ev.id,
      order_idx: orderIdx,
      ingest_idx: ev.ingestIdx,
      event_time_utc: ev.rawEventTimeUtc,
      received_time_utc: ev.rawReceivedTimeUtc,
      source_clock_offset_ms: ev.offsetMs,
      corrected_ms: ev.correctedMs,
      corrected_time_utc: iso(/** @type {number} */ (ev.correctedMs)),
      delivery_delay_ms: ev.deliveryDelayMs,
      released_at_ms: ev.releasedAtMs,
      late: ev.late,
      clock_unsupported: ev.clockUnsupported,
      order_uncertain: ev.orderUncertain,
      actor: ev.actor,
      session: ev.session,
      correlation: ev.correlation,
      src: ev.src,
      dst: ev.dst,
      action: ev.action,
      role_before: ev.roleBefore,
      role_after: ev.roleAfter,
      outcome: ev.outcome,
      approval_id: ev.approvalId,
      classification,
      alert_ids: alertIds,
      revocation_approval_id: lmm?.revocation_approval_id ?? null,
    };
  });

  /** @type {Record<string, number>} */
  const byRule = {};
  for (const a of alerts) byRule[/** @type {string} */ (a.rule_id)] = (byRule[/** @type {string} */ (a.rule_id)] || 0) + 1;
  const stats = {
    events: released.length,
    late: released.filter((e) => e.late).length,
    clock_unsupported: released.filter((e) => e.clockUnsupported).length,
    order_uncertain: released.filter((e) => e.orderUncertain).length,
    reordered: released.filter((e, i) => i > 0 && e.ingestIdx < released[i - 1].ingestIdx).length,
    alerts: alerts.length,
    alerts_by_rule: byRule,
    notices: notices.length,
    processing_ns: Number(processingNs),
  };

  return { alerts, notices, timeline, stats, config: configSummary(cfg), baseline: base.summary() };
}

module.exports = { detect };
