'use strict';
// @ts-check
// Seeded synthetic event generator for the detection benchmark (P1-18,
// architecture §15.3). SIMULATION ONLY: mulberry32 is a small deterministic
// PRNG for reproducible test data and is never used for anything security
// relevant. The generator labels its own output; the detector never sees
// those labels (only bench.cjs reads them).
//
// Output goes through CSV text and the real ingest, so the benchmark exercises
// the same parsing, clock and reordering path as `kig detect`.

const { COLUMNS, parseCsv } = require('./ingest.cjs');

/** mulberry32: 32-bit seeded PRNG. Simulation only, never cryptographic. @param {number} seed */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Rng {
  /** @param {number} seed */
  constructor(seed) { this.next = mulberry32(seed); }
  /** inclusive integer range @param {number} lo @param {number} hi */
  int(lo, hi) { return lo + Math.floor(this.next() * (hi - lo + 1)); }
  /** @template T @param {readonly T[]} arr @returns {T} */
  pick(arr) { return arr[Math.floor(this.next() * arr.length)]; }
  /** @param {number} p */
  chance(p) { return this.next() < p; }
  /** @template T @param {readonly T[]} arr @param {number} n @returns {T[]} n distinct items */
  sample(arr, n) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(this.next() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a.slice(0, n);
  }
}

// ---- the simulated estate ----

/** Routine (benign) edges per role; everything here is in the documented baseline or the warm-up corpus. */
const ROUTINE = Object.freeze({
  viewer: [['portal', 'catalog'], ['portal', 'search'], ['search', 'catalog']],
  'report-reader': [['portal', 'catalog'], ['portal', 'search'], ['search', 'catalog'], ['portal', 'reports'],
    ['portal', 'reports-node-a'], ['portal', 'reports-node-b'], ['reports', 'analytics']],
});
const REPORT_SCOPE = ['reports', 'reports-node-a', 'reports-node-b'];
const SERVICES = Object.freeze([
  { actor: 'svc-report-worker', role: 'service-reader', edges: [['reports', 'catalog']] },
  { actor: 'svc-indexer', role: 'service-reader', edges: [['search', 'catalog']] },
]);
/** Edges no benign scenario uses. */
const PROBE_EDGES = Object.freeze([
  ['reports', 'billing'], ['billing', 'archive'], ['archive', 'identity'], ['catalog', 'billing'], ['search', 'archive'],
  ['analytics', 'billing'], ['reports', 'archive'], ['catalog', 'archive'], ['portal', 'billing'], ['portal', 'archive'],
  ['analytics', 'identity'], ['search', 'identity'],
]);
const SENSITIVE_PROBES = PROBE_EDGES.filter(([, d]) => ['identity', 'billing', 'archive'].includes(d));

const DEFAULT_MIX = Object.freeze({
  routineSessions: 140,
  serviceRuns: 30,
  approvedAdmin: 4,
  approvedDecrease: 2,
  newHires: 4,
  isolatedDenials: 6,
  privUnapproved: 4,
  privExpired: 2,
  lmChain3: 4,
  lmAllowed: 4,
  lmDenyBurst: 3,
  evasiveLowSlow: 2,
  evasiveTwoEdge: 2,
});

const HOUR = 3600000;
const iso = (/** @type {number} */ ms) => new Date(ms).toISOString();

/** CSV field quoting (RFC 4180). @param {string} v */
const q = (v) => (/[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);

/**
 * @typedef {{ trueMs: number, actor: string, src: string, dst: string, action: string, roleBefore: string, roleAfter: string,
 *   outcome: string, approvalId: string, session: string, correlation: string, tag: string, seq: number }} Rec
 */

/**
 * Generate one labelled dataset.
 * @param {number} seed
 * @param {Partial<typeof DEFAULT_MIX>} [mixOverrides]
 */
function generateDataset(seed, mixOverrides = {}) {
  if (!Number.isSafeInteger(seed) || seed < 0) throw new RangeError('seed must be a non-negative integer');
  const mix = { ...DEFAULT_MIX, ...mixOverrides };
  const rng = new Rng(seed);
  const day0 = Date.UTC(2026, 1, 1) + (seed % 200) * 24 * HOUR;
  const t0 = day0 + 8 * HOUR; // working hours start
  const spanMs = 4 * HOUR;

  /** @type {Rec[]} */ const recs = [];
  /** @type {any[]} */ const changes = [];
  /** @type {Array<{ incident_id: string, kind: string, variant: string, evasive: boolean, actor: string, tag: string }>} */
  const groundTruth = [];
  let seq = 0;
  let sessionNo = 0;
  let approvalNo = 0;
  const newSession = () => { sessionNo += 1; return { session: `sess-${seed}-${sessionNo}`, correlation: `flow-${seed}-${sessionNo}` }; };
  const newApprovalId = () => `chg-${seed}-${++approvalNo}`;
  /** @param {Omit<Rec, 'seq'|'tag'> & { tag?: string }} r */
  const add = (r) => { recs.push({ tag: 'benign', ...r, seq: seq++ }); };
  const startAt = () => t0 + rng.int(0, spanMs);
  const users = Array.from({ length: 50 }, (_, i) => ({ actor: `user-${String(i + 1).padStart(3, '0')}`, role: rng.chance(0.3) ? 'report-reader' : 'viewer' }));
  const admins = ['user-admin-1', 'user-admin-2'];
  // Fresh identities share one numbering, so names say nothing about benign vs attack.
  let freshNo = 0;
  const freshUser = () => `user-${String(500 + ++freshNo)}`;
  const attacker = freshUser;

  /** Routine session: sign-in, reads over routine edges, sign-out. */
  const routineSession = (/** @type {string} */ actor, /** @type {'viewer'|'report-reader'} */ role, /** @type {number} */ at, reads = rng.int(3, 9)) => {
    const s = newSession();
    let t = at;
    add({ trueMs: t, actor, src: 'portal', dst: 'identity', action: 'sign_in', roleBefore: role, roleAfter: role, outcome: 'success', approvalId: '', ...s });
    for (let k = 0; k < reads; k++) {
      t += rng.int(2000, 30000);
      const [src, dst] = rng.pick(ROUTINE[role]);
      add({ trueMs: t, actor, src, dst, action: 'read', roleBefore: role, roleAfter: role, outcome: 'allow', approvalId: '', ...s });
    }
    t += rng.int(2000, 20000);
    add({ trueMs: t, actor, src: 'portal', dst: 'identity', action: 'sign_out', roleBefore: role, roleAfter: role, outcome: 'success', approvalId: '', ...s });
    return t;
  };

  /** Approved grant (approve event + role change + in-scope reads), later an approved operator revoke + expected denials. */
  const approvedAdmin = (/** @type {number} */ at) => {
    const admin = rng.pick(admins);
    const subject = freshUser();
    const grant = newApprovalId();
    const validFrom = at - rng.int(30, 300) * 1000;
    changes.push({ approval_id: grant, approved_by: admin, subject, operation: 'grant_role', role: 'report-reader', scope: REPORT_SCOPE, valid_from_utc: iso(validFrom), valid_until_utc: iso(validFrom + 2 * HOUR) });
    const sa = newSession();
    add({ trueMs: at, actor: admin, src: 'admin-console', dst: 'identity', action: 'approve_role_change', roleBefore: 'operator', roleAfter: 'operator', outcome: 'success', approvalId: grant, ...sa });
    const s = newSession();
    let t = at + rng.int(5000, 60000);
    add({ trueMs: t, actor: subject, src: 'portal', dst: 'identity', action: 'sign_in', roleBefore: 'viewer', roleAfter: 'viewer', outcome: 'success', approvalId: '', ...s });
    t += rng.int(2000, 10000);
    add({ trueMs: t, actor: subject, src: 'admin-console', dst: 'identity', action: 'role_change', roleBefore: 'viewer', roleAfter: 'report-reader', outcome: 'success', approvalId: grant, ...s });
    for (let k = rng.int(2, 4); k > 0; k--) {
      t += rng.int(2000, 60000);
      add({ trueMs: t, actor: subject, src: 'portal', dst: rng.pick(REPORT_SCOPE), action: 'read', roleBefore: 'report-reader', roleAfter: 'report-reader', outcome: 'allow', approvalId: grant, ...s });
    }
    // revocation by an operator, then the old role's reads are denied (expected enforcement)
    const revoke = newApprovalId();
    let r = t + rng.int(10, 40) * 60000;
    changes.push({ approval_id: revoke, approved_by: admin, subject, operation: 'revoke_role', role: 'report-reader', effective_at_utc: iso(r - rng.int(0, 5000)) });
    add({ trueMs: r, actor: admin, src: 'admin-console', dst: 'identity', action: 'revoke_role', roleBefore: 'operator', roleAfter: 'operator', outcome: 'success', approvalId: revoke, ...newSession() });
    const s2 = newSession();
    for (let k = rng.int(1, 3); k > 0; k--) {
      r += rng.int(10000, 60000);
      add({ trueMs: r, actor: subject, src: 'portal', dst: rng.pick(REPORT_SCOPE), action: 'read', roleBefore: 'viewer', roleAfter: 'viewer', outcome: 'deny', approvalId: revoke, ...s2 });
    }
    return grant;
  };

  // ---- benign scenarios ----
  for (let i = 0; i < mix.routineSessions; i++) { const u = rng.pick(users); routineSession(u.actor, /** @type {any} */ (u.role), startAt()); }
  for (let i = 0; i < mix.serviceRuns; i++) {
    const svc = rng.pick(SERVICES);
    const s = newSession();
    let t = startAt();
    for (let k = rng.int(2, 5); k > 0; k--) {
      const [src, dst] = rng.pick(svc.edges);
      add({ trueMs: t, actor: svc.actor, src, dst, action: 'read', roleBefore: svc.role, roleAfter: svc.role, outcome: 'allow', approvalId: '', ...s });
      t += rng.int(1000, 20000);
    }
  }
  const grantIds = [];
  for (let i = 0; i < mix.approvedAdmin; i++) {
    // the first one is off-hours (02:00–05:00), a hard benign case
    grantIds.push(approvedAdmin(i === 0 ? day0 + 2 * HOUR + rng.int(0, 3 * HOUR) : startAt()));
  }
  for (let i = 0; i < mix.approvedDecrease; i++) {
    const subject = freshUser();
    const at = startAt();
    routineSession(subject, 'report-reader', at - rng.int(5, 30) * 60000, rng.int(1, 3));
    const revoke = newApprovalId();
    changes.push({ approval_id: revoke, approved_by: rng.pick(admins), subject, operation: 'revoke_role', role: 'report-reader', effective_at_utc: iso(at - rng.int(10, 120) * 1000) });
    add({ trueMs: at, actor: subject, src: 'admin-console', dst: 'identity', action: 'role_change', roleBefore: 'report-reader', roleAfter: 'viewer', outcome: 'success', approvalId: revoke, ...newSession() });
  }
  for (let i = 0; i < mix.newHires; i++) routineSession(`user-new-${seed}-${i + 1}`, 'viewer', startAt(), rng.int(1, 4));
  for (let i = 0; i < mix.isolatedDenials; i++) {
    const u = rng.pick(users);
    const s = newSession();
    const at = startAt();
    add({ trueMs: at, actor: u.actor, src: 'portal', dst: 'identity', action: 'sign_in', roleBefore: u.role, roleAfter: u.role, outcome: 'success', approvalId: '', ...s });
    add({ trueMs: at + rng.int(2000, 20000), actor: u.actor, src: 'portal', dst: rng.pick(['billing', 'archive']), action: 'read', roleBefore: u.role, roleAfter: u.role, outcome: 'deny', approvalId: '', ...s });
  }

  // ---- labelled attack scenarios ----
  let incidentNo = 0;
  /** @param {string} kind @param {string} variant @param {boolean} evasive @param {string} actor */
  const incident = (kind, variant, evasive, actor) => {
    const tag = `inc-${seed}-${++incidentNo}`;
    groundTruth.push({ incident_id: tag, kind, variant, evasive, actor, tag });
    return tag;
  };

  for (let i = 0; i < mix.privUnapproved; i++) {
    const actor = attacker();
    const v = i % 3 === 0 ? 'no_approval' : i % 3 === 1 ? 'other_subject_approval' : 'wrong_role_approval';
    const tag = incident('privilege', `unapproved_escalation:${v}`, false, actor);
    let approvalId = '';
    if (v === 'other_subject_approval' && grantIds.length) approvalId = rng.pick(grantIds);
    const s = newSession();
    let t = startAt();
    if (v === 'wrong_role_approval') {
      approvalId = newApprovalId();
      changes.push({ approval_id: approvalId, approved_by: rng.pick(admins), subject: actor, operation: 'grant_role', role: 'report-reader', scope: REPORT_SCOPE, valid_from_utc: iso(t - HOUR), valid_until_utc: iso(t + HOUR) });
    }
    add({ trueMs: t, actor, src: 'portal', dst: 'identity', action: 'sign_in', roleBefore: 'viewer', roleAfter: 'viewer', outcome: 'success', approvalId: '', ...s });
    t += rng.int(2000, 15000);
    add({ trueMs: t, actor, src: 'admin-console', dst: 'identity', action: 'role_change', roleBefore: 'viewer', roleAfter: 'operator', outcome: 'success', approvalId, ...s, tag });
    for (let k = rng.int(1, 3); k > 0; k--) {
      t += rng.int(1000, 30000);
      const [src, dst] = rng.pick([['portal', 'reports'], ['admin-console', 'identity'], ['portal', 'catalog']]);
      add({ trueMs: t, actor, src, dst, action: 'read', roleBefore: 'operator', roleAfter: 'operator', outcome: 'allow', approvalId: '', ...s, tag });
    }
  }
  for (let i = 0; i < mix.privExpired; i++) {
    const actor = attacker();
    const tag = incident('privilege', 'expired_approval', false, actor);
    const s = newSession();
    let t = startAt();
    const grant = newApprovalId();
    const validUntil = t - rng.int(5, 60) * 60000;
    const admin = rng.pick(admins);
    changes.push({ approval_id: grant, approved_by: admin, subject: actor, operation: 'grant_role', role: 'report-reader', scope: REPORT_SCOPE, valid_from_utc: iso(validUntil - 2 * HOUR), valid_until_utc: iso(validUntil) });
    add({ trueMs: validUntil - 2 * HOUR + 10000, actor: admin, src: 'admin-console', dst: 'identity', action: 'approve_role_change', roleBefore: 'operator', roleAfter: 'operator', outcome: 'success', approvalId: grant, ...newSession() });
    add({ trueMs: t, actor, src: 'admin-console', dst: 'identity', action: 'role_change', roleBefore: 'viewer', roleAfter: 'report-reader', outcome: 'success', approvalId: grant, ...s, tag });
    t += rng.int(2000, 30000);
    add({ trueMs: t, actor, src: 'portal', dst: rng.pick(REPORT_SCOPE), action: 'read', roleBefore: 'report-reader', roleAfter: 'report-reader', outcome: 'allow', approvalId: grant, ...s, tag });
  }

  /** A probe sequence over the given edges with the given gaps (ms) and outcomes. */
  const probe = (/** @type {string} */ actor, /** @type {string} */ role, /** @type {number[][]} */ edgesAndGaps, /** @type {string} */ tag) => {
    const s = newSession();
    let t = startAt();
    for (const [src, dst, gap, outcome] of /** @type {any[]} */ (edgesAndGaps)) {
      t += gap;
      add({ trueMs: t, actor, src, dst, action: 'read', roleBefore: role, roleAfter: role, outcome, approvalId: '', ...s, tag });
    }
  };
  const pickActor = () => (rng.chance(0.5) ? { actor: 'svc-report-worker', role: 'service-reader' } : { actor: attacker(), role: 'viewer' });

  for (let i = 0; i < mix.lmChain3; i++) {
    const a = pickActor();
    const tag = incident('lateral', 'chain_3_edges_denied', false, a.actor);
    probe(a.actor, a.role, rng.sample(PROBE_EDGES, 3).map(([s, d], k) => [s, d, k === 0 ? 0 : rng.int(1000, 10000), 'deny']), tag);
  }
  for (let i = 0; i < mix.lmAllowed; i++) {
    const a = pickActor();
    if (i % 2 === 0) {
      const tag = incident('lateral', 'one_edge_allowed_sensitive', false, a.actor);
      const [s, d] = rng.pick(SENSITIVE_PROBES);
      probe(a.actor, a.role, [[s, d, 0, 'allow']], tag);
    } else {
      const tag = incident('lateral', 'two_edge_allowed', false, a.actor);
      const [e1, e2] = rng.sample(SENSITIVE_PROBES, 2);
      probe(a.actor, a.role, [[e1[0], e1[1], 0, 'allow'], [e2[0], e2[1], rng.int(1000, 15000), 'allow']], tag);
    }
  }
  for (let i = 0; i < mix.lmDenyBurst; i++) {
    const a = pickActor();
    const tag = incident('lateral', 'deny_burst_2_targets', false, a.actor);
    const e1 = rng.pick(PROBE_EDGES);
    const e2 = rng.pick(PROBE_EDGES.filter(([, d]) => d !== e1[1]));
    probe(a.actor, a.role, [[e1[0], e1[1], 0, 'deny'], [e2[0], e2[1], rng.int(2000, 15000), 'deny'], [e1[0], e1[1], rng.int(2000, 15000), 'deny']], tag);
  }
  for (let i = 0; i < mix.evasiveLowSlow; i++) {
    const a = pickActor();
    const tag = incident('lateral', 'low_and_slow_3_edges', true, a.actor);
    probe(a.actor, a.role, rng.sample(PROBE_EDGES, 3).map(([s, d], k) => [s, d, k === 0 ? 0 : rng.int(75000, 120000), 'deny']), tag);
  }
  for (let i = 0; i < mix.evasiveTwoEdge; i++) {
    const a = pickActor();
    const tag = incident('lateral', 'two_edge_denied', true, a.actor);
    const e1 = rng.pick(PROBE_EDGES);
    const e2 = rng.pick(PROBE_EDGES.filter(([, d]) => d !== e1[1]));
    probe(a.actor, a.role, [[e1[0], e1[1], 0, 'deny'], [e2[0], e2[1], rng.int(1000, 10000), 'deny']], tag);
  }

  // ---- clocks and delivery ----
  /** @type {Map<string, number>} */
  const skew = new Map();
  const skewOf = (/** @type {string} */ actor) => {
    if (!skew.has(actor)) {
      const u = rng.next();
      const sign = rng.chance(0.5) ? 1 : -1;
      skew.set(actor, u < 0.70 ? 0 : u < 0.95 ? sign * rng.int(100, 4500) : sign * rng.int(5001, 6500));
    }
    return /** @type {number} */ (skew.get(actor));
  };
  recs.sort((a, b) => a.trueMs - b.trueMs || a.seq - b.seq);
  const rows = recs.map((r, i) => {
    const off = skewOf(r.actor);
    const u = rng.next();
    const delay = u < 0.85 ? rng.int(30, 400) : u < 0.98 ? rng.int(1000, 4000) : rng.int(5200, 8000);
    return {
      id: `g${seed}-${String(i + 1).padStart(5, '0')}`, r, off, delay,
      receivedMs: r.trueMs + delay,
    };
  });
  const receiptOrder = [...rows].sort((a, b) => a.receivedMs - b.receivedMs || (a.id < b.id ? -1 : 1));
  const lines = [COLUMNS.join(',')];
  for (const x of receiptOrder) {
    const r = x.r;
    const rec = {
      event_id: x.id, event_time_utc: iso(r.trueMs + x.off), received_time_utc: iso(x.receivedMs), source_clock_offset_ms: String(x.off),
      actor: r.actor, source_service: r.src, target_service: r.dst, action: r.action, role_before: r.roleBefore, role_after: r.roleAfter,
      outcome: r.outcome, approval_id: r.approvalId, session_id: r.session, correlation_id: r.correlation,
    };
    lines.push(COLUMNS.map((c) => q(/** @type {any} */ (rec)[c])).join(','));
  }
  const csv = lines.join('\n') + '\n';
  const { events, rejects } = parseCsv(csv);
  if (rejects.length) throw new Error(`generator produced ${rejects.length} invalid rows`);

  // ---- ground truth (read only by the benchmark scorer) ----
  /** @type {Map<string, string>} */
  const eventLabels = new Map();
  for (const x of rows) eventLabels.set(x.id, x.r.tag);
  const incidents = groundTruth.map((g) => {
    const mine = rows.filter((x) => x.r.tag === g.tag);
    return {
      incident_id: g.incident_id, kind: g.kind, variant: g.variant, evasive: g.evasive, actor: g.actor,
      event_ids: mine.map((x) => x.id),
      last_event_received_ms: Math.max(...mine.map((x) => x.receivedMs)),
    };
  });
  const benign = rows.filter((x) => x.r.tag === 'benign').length;
  /** @type {Record<string, number>} */
  const byVariant = {};
  for (const i of incidents) byVariant[i.variant] = (byVariant[i.variant] || 0) + 1;
  const summary = {
    seed,
    events: rows.length,
    benign_events: benign,
    malicious_events: rows.length - benign,
    incidents: incidents.length,
    evasive_incidents: incidents.filter((i) => i.evasive).length,
    incidents_by_variant: byVariant,
    approvals: changes.length,
    clock: {
      skewed_within_range: rows.filter((x) => x.off !== 0 && Math.abs(x.off) <= 5000).length,
      skew_out_of_range: rows.filter((x) => Math.abs(x.off) > 5000).length,
      delayed_1_to_4_s: rows.filter((x) => x.delay >= 1000 && x.delay <= 4000).length,
      delayed_over_5_s: rows.filter((x) => x.delay > 5000).length,
    },
  };
  return { seed, csv, events, approvals: { synthetic: true, changes }, incidents, eventLabels, summary };
}

/**
 * Benign warm-up corpus: routine traffic only, every routine edge at least once.
 * Generated from its own seed, kept apart from evaluation seeds.
 * @param {number} seed
 * @param {{ count?: number }} [opts]
 */
function generateWarmupCorpus(seed, { count = 500 } = {}) {
  const rng = new Rng(seed);
  const t0 = Date.UTC(2026, 0, 1, 8) + (seed % 200) * 24 * HOUR;
  const all = [];
  for (const [role, edges] of Object.entries(ROUTINE)) for (const e of edges) all.push({ role, e });
  for (const svc of SERVICES) for (const e of svc.edges) all.push({ role: svc.role, e, actor: svc.actor });
  all.push({ role: 'viewer', e: ['portal', 'identity'] }, { role: 'operator', e: ['admin-console', 'identity'], actor: 'user-admin-1' });
  const lines = [COLUMNS.join(',')];
  for (let i = 0; i < Math.max(count, all.length); i++) {
    const x = i < all.length ? all[i] : rng.pick(all);
    const t = iso(t0 + i * rng.int(1000, 20000));
    const rec = {
      event_id: `w${seed}-${i + 1}`, event_time_utc: t, received_time_utc: t, source_clock_offset_ms: '0',
      actor: x.actor || `user-${String(rng.int(1, 50)).padStart(3, '0')}`, source_service: x.e[0], target_service: x.e[1], action: 'read',
      role_before: x.role, role_after: x.role, outcome: 'allow', approval_id: '', session_id: `wsess-${seed}-${i}`, correlation_id: `wflow-${seed}-${i}`,
    };
    lines.push(COLUMNS.map((c) => q(/** @type {any} */ (rec)[c])).join(','));
  }
  return parseCsv(lines.join('\n') + '\n').events;
}

module.exports = { mulberry32, Rng, generateDataset, generateWarmupCorpus, DEFAULT_MIX, PROBE_EDGES, ROUTINE };
