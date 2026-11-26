'use strict';
// @ts-check
// Lateral-movement rules (P1-10, D-09, architecture §15.2). Evaluated in
// event-time order over edges that are NOT in the baseline.
//   LM-1  ≥ N distinct unseen directed edges for one actor/session/flow within
//         the window → one grouped candidate-lateral-movement alert (medium;
//         high if any request was allowed). Later unseen edges extend it.
//   LM-2  an allowed request over an unseen edge into a sensitive service →
//         medium (catches one- and two-edge successful paths LM-1 misses).
//   LM-3  ≥ N denied unseen requests across ≥ M distinct targets for one
//         actor/session within the window → low; folded into an LM-1 alert
//         instead when that alert already covers every one of the denials.
// Denials explained by a recent approved revocation (revocation context) are
// classified expected_enforcement and excluded. Denied requests are described
// as attempts; nothing here claims an access succeeded unless it was allowed.

const { edgeKey } = require('./baseline.cjs');
const { timeOf } = require('./approvals.cjs');
const { isAllowed, isDenied } = require('./roles.cjs');

const iso = (/** @type {number} */ ms) => new Date(ms).toISOString();
const edge = (/** @type {any} */ ev) => `${ev.src}->${ev.dst}`;

const RULES = Object.freeze({
  'LM-1': { classification: 'candidate_lateral_movement' },
  'LM-2': { classification: 'novel_sensitive_access' },
  'LM-3': { classification: 'unseen_deny_burst' },
});

/** @param {any} a @param {import('./config.cjs').DetectConfig} cfg */
function refresh(a, cfg) {
  const evs = a._events;
  const services = [];
  for (const ev of evs) for (const s of [ev.src, ev.dst]) if (!services.includes(s)) services.push(s);
  const ts = evs.map(timeOf);
  const start = Math.min(...ts);
  const end = Math.max(...ts);
  a.services = services;
  a.path = evs.map(edge);
  a.event_ids = evs.map((/** @type {any} */ e) => e.id);
  a.outcomes = evs.map((/** @type {any} */ e) => ({ event_id: e.id, outcome: e.outcome, src: e.src, dst: e.dst }));
  a.order_uncertain = evs.some((/** @type {any} */ e) => e.orderUncertain);
  a.window = { start_utc: iso(start), end_utc: iso(end), window_ms: end - start };

  const who = `${a.identity} (session ${a.session || '-'}, flow ${a.correlation || '-'})`;
  const steps = evs.map((/** @type {any} */ e) => `${edge(e)} [${e.id}: ${e.outcome}]`).join(', ');
  const allowed = evs.filter((/** @type {any} */ e) => isAllowed(e.outcome)).length;
  const within = `within ${cfg.lmWindowMs / 1000} s`;
  if (a.rule_id === 'LM-1') {
    const distinct = new Set(evs.map((/** @type {any} */ e) => edgeKey(e.src, e.dst))).size;
    a.severity = allowed > 0 ? 'high' : 'medium';
    a.reason = `LM-1: ${distinct} previously unseen service edges for ${who} ${within}: ${steps}. Candidate lateral movement; `
      + (allowed === 0 ? 'all requests were denied, so no access succeeded.' : `${allowed} of ${evs.length} requests were allowed.`);
  } else if (a.rule_id === 'LM-2') {
    a.severity = 'medium';
    a.reason = `LM-2: allowed request over a previously unseen edge into a sensitive service by ${who}: ${steps}. `
      + 'Novel sensitive access; the edge is not in the baseline.';
  } else {
    const targets = [...new Set(evs.map((/** @type {any} */ e) => e.dst))];
    a.severity = 'low';
    a.reason = `LM-3: ${evs.length} denied requests to ${targets.length} previously unseen target services (${targets.join(', ')}) by ${who} ${within}: ${steps}. `
      + 'Candidate probing; every request was denied.';
  }
}

/**
 * @param {any[]} events released (event-time ordered) events
 * @param {import('./baseline.cjs').Baseline} baseline
 * @param {import('./roles.cjs').RoleTracker} roleTracker state after the privilege pass
 * @param {import('./config.cjs').DetectConfig} cfg
 * @param {{ mono?: () => bigint }} [hooks]
 */
function evaluateLateralMovement(events, baseline, roleTracker, cfg, hooks = {}) {
  /** @type {any[]} */
  const alerts = [];
  /** @type {Map<string, object>} */
  const eventMeta = new Map();
  /** @type {Map<string, any[]>} */ const lm1Window = new Map();
  /** @type {Map<string, any>} */ const lm1Open = new Map();
  /** @type {Map<string, any>} */ const lm2Open = new Map();
  /** @type {Map<string, any[]>} */ const lm3Window = new Map();
  /** @type {Map<string, any>} */ const lm3Open = new Map();
  /** @type {Map<string, any>} event id → LM-1 alert containing it */
  const lm1ByEvent = new Map();

  const create = (/** @type {string} */ rule, /** @type {any[]} */ evs, /** @type {any} */ ev) => {
    const a = {
      rule_id: rule,
      severity: 'low',
      classification: /** @type {any} */ (RULES)[rule].classification,
      identity: ev.actor,
      session: ev.session,
      correlation: ev.correlation,
      also_matched: [],
      last_evidence_received_ms: Math.max(...evs.map((e) => e.receivedMs)),
      emitted_sim_ms: Math.max(...evs.map((e) => e.releasedAtMs ?? e.receivedMs)),
      emitted_at_mono_ns: hooks.mono ? hooks.mono() : null,
      _events: [...evs],
    };
    refresh(a, cfg);
    alerts.push(a);
    return a;
  };
  const extend = (/** @type {any} */ a, /** @type {any} */ ev) => {
    if (!a._events.includes(ev)) { a._events.push(ev); refresh(a, cfg); }
  };
  const fresh = (/** @type {any} */ a, /** @type {number} */ t) => a && t - timeOf(a._events[a._events.length - 1]) <= cfg.lmWindowMs;

  for (const ev of events) {
    const t = timeOf(ev);
    const enf = roleTracker.isExpectedEnforcementDenial(ev);
    if (enf.matched) {
      eventMeta.set(ev.id, {
        classification: 'expected_enforcement',
        revocation_approval_id: enf.revocation?.approvalId,
        revocation_event_id: enf.revocation?.eventId,
      });
      continue;
    }
    if (baseline.has(ev.src, ev.dst)) continue;
    eventMeta.set(ev.id, { classification: 'unseen_edge' });

    // LM-1: distinct unseen edges per actor/session/flow.
    const k1 = JSON.stringify([ev.actor, ev.session, ev.correlation]);
    const w1 = (lm1Window.get(k1) || []).filter((e) => t - timeOf(e) <= cfg.lmWindowMs);
    w1.push(ev);
    lm1Window.set(k1, w1);
    let lm1 = null;
    const open1 = lm1Open.get(k1);
    if (fresh(open1, t)) {
      extend(open1, ev);
      lm1 = open1;
    } else if (new Set(w1.map((e) => edgeKey(e.src, e.dst))).size >= cfg.lm1EdgeThreshold) {
      lm1 = create('LM-1', w1, ev);
      lm1Open.set(k1, lm1);
    }
    if (lm1) for (const e of lm1._events) lm1ByEvent.set(e.id, lm1);

    // LM-2: allowed unseen edge into a sensitive service (unless already in an LM-1 sequence).
    const k2 = JSON.stringify([ev.actor, ev.session]);
    if (!lm1ByEvent.has(ev.id) && isAllowed(ev.outcome) && cfg.sensitiveSet.has(ev.dst)) {
      const open2 = lm2Open.get(k2);
      if (fresh(open2, t)) extend(open2, ev);
      else lm2Open.set(k2, create('LM-2', [ev], ev));
    }

    // LM-3: denied unseen requests across distinct targets.
    if (isDenied(ev.outcome)) {
      const w3 = (lm3Window.get(k2) || []).filter((e) => t - timeOf(e) <= cfg.lmWindowMs);
      w3.push(ev);
      lm3Window.set(k2, w3);
      const open3 = lm3Open.get(k2);
      if (fresh(open3, t)) {
        extend(open3, ev);
      } else if (w3.length >= cfg.lm3DenyThreshold && new Set(w3.map((e) => e.dst)).size >= cfg.lm3TargetThreshold) {
        if (w3.every((e) => lm1ByEvent.has(e.id))) {
          for (const a of new Set(w3.map((e) => lm1ByEvent.get(e.id)))) if (!a.also_matched.includes('LM-3')) a.also_matched.push('LM-3');
        } else {
          lm3Open.set(k2, create('LM-3', w3, ev));
        }
      }
    }
  }
  return { alerts, eventMeta };
}

module.exports = { evaluateLateralMovement };
