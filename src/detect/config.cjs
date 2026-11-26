'use strict';
// @ts-check
// Detector configuration (docs/plans/phase-5.md §2.4). Every threshold is
// configurable and reported verbatim with each benchmark run.

/** Documented expected service edges from the practice context (features P1-10 [v0.3]). */
const DOCUMENTED_PRACTICE_EDGES = Object.freeze([
  Object.freeze(['portal', 'identity']),
  Object.freeze(['admin-console', 'identity']),
  Object.freeze(['portal', 'catalog']),
  Object.freeze(['portal', 'reports']),
  Object.freeze(['portal', 'reports-node-a']),
  Object.freeze(['portal', 'reports-node-b']),
  Object.freeze(['reports', 'catalog']),
]);

/** Role privilege order (higher = more privilege). */
const DEFAULT_ROLE_RANKS = new Map([
  ['viewer', 1],
  ['service-reader', 2],
  ['report-reader', 3],
  ['operator', 4],
  ['admin', 5],
]);

const NUMERIC_KEYS = Object.freeze({
  maxOffsetMs: 'nonneg',
  latenessMs: 'nonneg',
  uncertaintyMs: 'nonneg',
  lmWindowMs: 'positive',
  lm1EdgeThreshold: 'positive',
  lm3DenyThreshold: 'positive',
  lm3TargetThreshold: 'positive',
  revocationContextWindowMs: 'nonneg',
  privLinkWindowMs: 'nonneg',
});

const DEFAULT_CONFIG = Object.freeze({
  maxOffsetMs: 5000,
  latenessMs: 5000,
  uncertaintyMs: 250,
  lmWindowMs: 60000,
  lm1EdgeThreshold: 3,
  lm3DenyThreshold: 3,
  lm3TargetThreshold: 2,
  sensitiveServices: Object.freeze(['identity', 'billing', 'archive']),
  revocationContextWindowMs: 300000,
  /** How long after a PRIV-1 a later allowed access in the same session/flow is linked (PRIV-2). */
  privLinkWindowMs: 1800000,
  roleRanks: DEFAULT_ROLE_RANKS,
});

/**
 * @typedef {{ maxOffsetMs: number, latenessMs: number, uncertaintyMs: number, lmWindowMs: number,
 *   lm1EdgeThreshold: number, lm3DenyThreshold: number, lm3TargetThreshold: number,
 *   sensitiveServices: readonly string[], sensitiveSet: ReadonlySet<string>,
 *   revocationContextWindowMs: number, privLinkWindowMs: number,
 *   roleRanks: ReadonlyMap<string, number> }} DetectConfig
 */

/** @param {unknown} v @returns {Map<string, number>} */
function toRoleRanks(v) {
  /** @type {Iterable<[unknown, unknown]>} */
  let entries;
  if (v instanceof Map) entries = v;
  else if (Array.isArray(v)) entries = v;
  else if (v && typeof v === 'object') entries = Object.entries(v);
  else throw new TypeError('roleRanks must be a Map, an array of [role, rank] pairs, or an object');
  const m = new Map();
  for (const pair of entries) {
    if (!Array.isArray(pair) || pair.length !== 2) throw new TypeError('roleRanks entries must be [role, rank] pairs');
    const [role, rank] = pair;
    if (typeof role !== 'string' || role === '') throw new TypeError('roleRanks role must be a non-empty string');
    if (typeof rank !== 'number' || !Number.isFinite(rank)) throw new TypeError(`roleRanks rank for a role must be a finite number`);
    m.set(role, rank);
  }
  return m;
}

/**
 * Defaults plus validated overrides. Unknown keys are rejected so a typo can't
 * silently leave a default in place.
 * @param {Record<string, unknown>} [overrides]
 * @returns {Readonly<DetectConfig>}
 */
function mergeConfig(overrides = {}) {
  if (overrides === null || typeof overrides !== 'object') throw new TypeError('config overrides must be an object');
  /** @type {any} */
  const c = { ...DEFAULT_CONFIG };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) continue;
    if (Object.prototype.hasOwnProperty.call(NUMERIC_KEYS, k)) {
      const kind = /** @type {any} */ (NUMERIC_KEYS)[k];
      if (!Number.isSafeInteger(v) || /** @type {number} */ (v) < (kind === 'positive' ? 1 : 0)) {
        throw new RangeError(`config ${k} must be a ${kind === 'positive' ? 'positive' : 'non-negative'} integer`);
      }
      c[k] = v;
    } else if (k === 'sensitiveServices') {
      if (!Array.isArray(v) || !v.every((s) => typeof s === 'string' && s !== '')) {
        throw new TypeError('config sensitiveServices must be an array of non-empty strings');
      }
      c.sensitiveServices = Object.freeze([...v]);
    } else if (k === 'roleRanks') {
      c.roleRanks = toRoleRanks(v);
    } else {
      throw new RangeError(`unknown config key: ${k}`);
    }
  }
  c.roleRanks = new Map(c.roleRanks);
  c.sensitiveSet = new Set(c.sensitiveServices);
  return Object.freeze(c);
}

/** Plain-JSON view of a config, for reports. @param {DetectConfig} c */
function configSummary(c) {
  return {
    maxOffsetMs: c.maxOffsetMs,
    latenessMs: c.latenessMs,
    uncertaintyMs: c.uncertaintyMs,
    lmWindowMs: c.lmWindowMs,
    lm1EdgeThreshold: c.lm1EdgeThreshold,
    lm3DenyThreshold: c.lm3DenyThreshold,
    lm3TargetThreshold: c.lm3TargetThreshold,
    sensitiveServices: [...c.sensitiveServices],
    revocationContextWindowMs: c.revocationContextWindowMs,
    privLinkWindowMs: c.privLinkWindowMs,
    roleRanks: [...c.roleRanks],
  };
}

module.exports = { DEFAULT_CONFIG, DOCUMENTED_PRACTICE_EDGES, DEFAULT_ROLE_RANKS, mergeConfig, configSummary };
