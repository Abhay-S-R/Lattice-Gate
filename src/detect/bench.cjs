'use strict';
// @ts-check
// Detection benchmark (P1-18, architecture §15.3). The only module that reads
// the generator's ground truth; the detector never imports it.
//
// Units are kept apart:
//  - incident level (primary): an alert matches a labelled incident when their
//    event IDs intersect; one-to-one greedy matching by largest overlap. An
//    alert matched to nothing is a false alert; an incident matched by nothing
//    is a miss (reported as detectable or evasive).
//  - event level (secondary): event IDs covered by alerts vs event IDs that
//    belong to incidents.
// Time-to-alert: from receipt of the last evidence event an alert needed to its
// emission, on the simulated collector clock (includes the reorder-buffer wait,
// up to the lateness), plus the measured detector processing time per event.

const os = require('node:os');
const { detect } = require('./index.cjs');
const { Baseline } = require('./baseline.cjs');
const { generateDataset, generateWarmupCorpus, DEFAULT_MIX } = require('./generator.cjs');
const { configSummary, mergeConfig } = require('./config.cjs');

const DEFINITIONS = Object.freeze({
  incident_match: 'An alert matches a labelled incident when their event IDs intersect; one-to-one greedy matching by largest overlap.',
  precision: 'matched alerts / all alerts (incident level).',
  recall: 'matched incidents / all incidents, evasive ones included (incident level).',
  recall_detectable: 'matched non-evasive incidents / non-evasive incidents.',
  f1: 'harmonic mean of incident-level precision and recall.',
  false_alerts_per_1000_benign: 'unmatched alerts / benign events x 1000.',
  tta_ms: 'emission time minus receipt of the last evidence event the alert needed, on the simulated collector clock '
    + '(includes the reorder-buffer wait, up to the lateness), plus measured processing time per event.',
  event_level: 'event IDs covered by alerts vs event IDs belonging to incidents; reported separately, never mixed with incident metrics.',
  evasive: 'attacks generated to stay under the rule thresholds (low-and-slow, two denied edges); misses are reported, not tuned away.',
});

const ratio = (/** @type {number} */ a, /** @type {number} */ b) => (b === 0 ? null : a / b);
const f1Of = (/** @type {number|null} */ p, /** @type {number|null} */ r) => (p === null || r === null || p + r === 0 ? null : (2 * p * r) / (p + r));
/** @param {number[]} xs */
function median(xs) {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/**
 * Score one run against one labelled dataset.
 * @param {any[]} alerts detector output
 * @param {{ incidents: any[], eventLabels: Map<string, string> }} dataset
 * @param {{ processingMsPerEvent?: number }} [opts]
 */
function score(alerts, dataset, { processingMsPerEvent = 0 } = {}) {
  const incidents = dataset.incidents;
  const pairs = [];
  for (const a of alerts) {
    const ids = new Set(a.event_ids);
    for (const inc of incidents) {
      const overlap = inc.event_ids.filter((/** @type {string} */ id) => ids.has(id)).length;
      if (overlap > 0) pairs.push({ a, inc, overlap });
    }
  }
  pairs.sort((x, y) => y.overlap - x.overlap || (x.a.alert_id < y.a.alert_id ? -1 : x.a.alert_id > y.a.alert_id ? 1 : 0)
    || (x.inc.incident_id < y.inc.incident_id ? -1 : 1));
  const usedA = new Set();
  const usedI = new Set();
  const matches = [];
  for (const p of pairs) {
    if (usedA.has(p.a.alert_id) || usedI.has(p.inc.incident_id)) continue;
    usedA.add(p.a.alert_id);
    usedI.add(p.inc.incident_id);
    matches.push(p);
  }
  const tp = matches.length;
  const fp = alerts.length - tp;
  const fn = incidents.length - tp;
  const benignEvents = [...dataset.eventLabels.values()].filter((v) => v === 'benign').length;
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const detectable = incidents.filter((i) => !i.evasive);
  const matchedDetectable = detectable.filter((i) => usedI.has(i.incident_id)).length;
  const missed = incidents.filter((i) => !usedI.has(i.incident_id)).map((i) => ({ incident_id: i.incident_id, variant: i.variant, evasive: i.evasive }));
  const tta = matches.map((m) => m.a.tta_ms + processingMsPerEvent);

  const predicted = new Set(alerts.flatMap((a) => a.event_ids));
  const actual = new Set(incidents.flatMap((i) => i.event_ids));
  const etp = [...predicted].filter((id) => actual.has(id)).length;
  const efp = predicted.size - etp;
  const efn = actual.size - etp;
  const ep = ratio(etp, etp + efp);
  const er = ratio(etp, etp + efn);

  return {
    incident: {
      tp, fp, fn, precision, recall, f1: f1Of(precision, recall),
      recall_detectable: ratio(matchedDetectable, detectable.length),
      detectable_incidents: detectable.length,
      evasive_incidents: incidents.length - detectable.length,
    },
    event: { tp: etp, fp: efp, fn: efn, precision: ep, recall: er, f1: f1Of(ep, er) },
    benign_events: benignEvents,
    false_alerts_per_1000_benign: benignEvents ? (fp / benignEvents) * 1000 : null,
    tta_ms: tta,
    median_tta_ms: median(tta),
    missed_detectable: missed.filter((m) => !m.evasive),
    missed_evasive: missed.filter((m) => m.evasive),
    false_alerts: alerts.filter((a) => !usedA.has(a.alert_id)).map((a) => ({ alert_id: a.alert_id, rule_id: a.rule_id, event_ids: a.event_ids })),
    matched: matches.map((m) => ({ alert_id: m.a.alert_id, rule_id: m.a.rule_id, incident_id: m.inc.incident_id, variant: m.inc.variant })),
  };
}

/** @param {number[]} seeds @param {string} name */
function checkSeeds(seeds, name) {
  if (!Array.isArray(seeds) || seeds.length === 0 || !seeds.every((s) => Number.isSafeInteger(s) && s >= 0)) {
    throw new RangeError(`${name} must be a non-empty list of non-negative integer seeds`);
  }
  if (new Set(seeds).size !== seeds.length) throw new RangeError(`${name} has duplicate seeds`);
}

/** Totals over several scored seeds. @param {any[]} runs */
function aggregate(runs) {
  const sum = (/** @type {(r: any) => number} */ f) => runs.reduce((n, r) => n + f(r), 0);
  const tp = sum((r) => r.score.incident.tp);
  const fp = sum((r) => r.score.incident.fp);
  const fn = sum((r) => r.score.incident.fn);
  const det = sum((r) => r.score.incident.detectable_incidents);
  const detHit = det - sum((r) => r.score.missed_detectable.length);
  const benign = sum((r) => r.score.benign_events);
  const etp = sum((r) => r.score.event.tp);
  const efp = sum((r) => r.score.event.fp);
  const efn = sum((r) => r.score.event.fn);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  const ep = ratio(etp, etp + efp);
  const er = ratio(etp, etp + efn);
  const tta = runs.flatMap((r) => r.score.tta_ms);
  /** @type {Record<string, { incidents: number, detected: number }>} */
  const byVariant = {};
  for (const r of runs) {
    for (const [v, n] of Object.entries(r.dataset.incidents_by_variant)) {
      byVariant[v] = byVariant[v] || { incidents: 0, detected: 0 };
      byVariant[v].incidents += /** @type {number} */ (n);
    }
    for (const m of r.score.matched) byVariant[m.variant].detected += 1;
  }
  return {
    seeds: runs.map((r) => r.seed),
    events: sum((r) => r.dataset.events),
    benign_events: benign,
    malicious_events: sum((r) => r.dataset.malicious_events),
    incidents: tp + fn,
    alerts: tp + fp,
    incident: { tp, fp, fn, precision, recall, f1: f1Of(precision, recall), recall_detectable: ratio(detHit, det), detectable_incidents: det, evasive_incidents: tp + fn - det },
    event: { tp: etp, fp: efp, fn: efn, precision: ep, recall: er, f1: f1Of(ep, er) },
    false_alerts_per_1000_benign: benign ? (fp / benign) * 1000 : null,
    median_tta_ms: median(tta),
    max_tta_ms: tta.length ? Math.max(...tta) : null,
    detection_by_variant: byVariant,
    missed_detectable: runs.flatMap((r) => r.score.missed_detectable),
    missed_evasive: runs.flatMap((r) => r.score.missed_evasive),
    false_alerts: runs.flatMap((r) => r.score.false_alerts),
    clock: {
      skewed_within_range: sum((r) => r.dataset.clock.skewed_within_range),
      skew_out_of_range: sum((r) => r.dataset.clock.skew_out_of_range),
      delayed_1_to_4_s: sum((r) => r.dataset.clock.delayed_1_to_4_s),
      delayed_over_5_s: sum((r) => r.dataset.clock.delayed_over_5_s),
      late_events: sum((r) => r.detector.late),
      reordered_events: sum((r) => r.detector.reordered),
    },
  };
}

/**
 * @param {{ tuningSeeds?: number[], holdoutSeeds?: number[], warmupSeed?: number, cfg?: Record<string, unknown> }} [opts]
 */
function runBenchmark({ tuningSeeds = [101, 102, 103], holdoutSeeds = [201, 202, 203, 204, 205], warmupSeed = 1, cfg = {} } = {}) {
  checkSeeds(tuningSeeds, 'tuning seeds');
  checkSeeds(holdoutSeeds, 'held-out seeds');
  if (!Number.isSafeInteger(warmupSeed) || warmupSeed < 0) throw new RangeError('warm-up seed must be a non-negative integer');
  const overlap = tuningSeeds.filter((s) => holdoutSeeds.includes(s));
  if (overlap.length) throw new RangeError(`tuning and held-out seeds must be disjoint (shared: ${overlap.join(', ')})`);
  if (tuningSeeds.includes(warmupSeed) || holdoutSeeds.includes(warmupSeed)) throw new RangeError('warm-up seed must differ from tuning and held-out seeds');
  const config = mergeConfig(cfg);

  const baseline = Baseline.fromDocumented();
  baseline.addCorpus(generateWarmupCorpus(warmupSeed), { seed: warmupSeed });

  const runSeed = (/** @type {number} */ seed) => {
    const ds = generateDataset(seed);
    const r = detect(ds.events, ds.approvals, baseline, cfg);
    const processingMsPerEvent = r.stats.events ? r.stats.processing_ns / r.stats.events / 1e6 : 0;
    return {
      seed,
      dataset: ds.summary,
      detector: { alerts_by_rule: r.stats.alerts_by_rule, late: r.stats.late, reordered: r.stats.reordered, clock_unsupported: r.stats.clock_unsupported, processing_ms_per_event: processingMsPerEvent },
      score: score(r.alerts, ds, { processingMsPerEvent }),
    };
  };
  const tuningRuns = tuningSeeds.map(runSeed);
  const holdoutRuns = holdoutSeeds.map(runSeed);
  const strip = (/** @type {any} */ run) => ({ ...run, score: { ...run.score, tta_ms: undefined } });

  return {
    benchmark: 'kig detect, synthetic labelled benchmark (P1-18)',
    data_origin: 'synthetic: seeded generator (src/detect/generator.cjs), not production traffic',
    runtime: { node: process.version, platform: process.platform, arch: process.arch, cpus: os.cpus().length },
    seeds: { tuning: tuningSeeds, holdout: holdoutSeeds, warmup: warmupSeed },
    baseline: baseline.summary(),
    config: configSummary(config),
    scenario_mix_per_seed: DEFAULT_MIX,
    definitions: DEFINITIONS,
    tuning: aggregate(tuningRuns),
    holdout: aggregate(holdoutRuns),
    per_seed: { tuning: tuningRuns.map(strip), holdout: holdoutRuns.map(strip) },
  };
}

module.exports = { score, runBenchmark, median, DEFINITIONS };
