'use strict';
// @ts-check
// `kig bench detect --seeds <tuning> --holdout <seeds> [--warmup-seed <n>] [--out <file>] [--json]`
// Runs the seeded synthetic benchmark (P1-18) and prints the held-out metrics:
// precision, recall, F1 (incident and event level, separately), median
// time-to-alert, false alerts per 1,000 benign events, and the misses.
// Seeds: comma-separated integers and ranges, e.g. 101,102,103 or 201-205.
// The JSON report goes to --out, or evidence/detect-<timestamp>.json; on a
// read-only filesystem the write is skipped with a notice.
// Exit: 0 success, 2 bad arguments.

const fs = require('node:fs');
const path = require('node:path');
const { runBenchmark } = require('../detect/bench.cjs');

const name = 'bench detect';
const describe = 'seeded synthetic detection benchmark (tuning and held-out seeds)';
const options = /** @type {const} */ ({
  seeds: { type: 'string' },
  holdout: { type: 'string' },
  'warmup-seed': { type: 'string' },
  out: { type: 'string' },
  json: { type: 'boolean', default: false },
});
const USAGE = 'usage: node kig.cjs bench detect --seeds <tuning, e.g. 101,102,103> --holdout <held-out, e.g. 201-205> '
  + '[--warmup-seed <n>] [--out <report.json>] [--json]\n';
const REPO = path.resolve(__dirname, '..', '..');

class UsageError extends Error {}

/** "101,102,201-205" → [101, 102, 201, 202, 203, 204, 205] @param {string|undefined} s @param {string} flag */
function parseSeeds(s, flag) {
  if (!s) throw new UsageError(`--${flag} is required`);
  const out = [];
  for (const part of s.split(',')) {
    const m = /^\s*(\d{1,9})(?:\s*-\s*(\d{1,9}))?\s*$/.exec(part);
    if (!m) throw new UsageError(`--${flag}: "${part.slice(0, 20)}" is not a seed or a range`);
    const a = Number(m[1]);
    const b = m[2] === undefined ? a : Number(m[2]);
    if (b < a || b - a > 10000) throw new UsageError(`--${flag}: bad range ${a}-${b}`);
    for (let x = a; x <= b; x++) out.push(x);
  }
  return out;
}

const pct = (/** @type {number|null} */ x) => (x === null ? 'n/a' : x.toFixed(3));
const ms = (/** @type {number|null} */ x) => (x === null ? 'n/a' : `${Math.round(x)} ms`);

/** @param {string} label @param {any} s */
function summarize(label, s) {
  const L = [];
  L.push(`${label} seeds ${s.seeds.join(',')}: ${s.events} events (${s.benign_events} benign, ${s.malicious_events} attack), ${s.incidents} incidents, ${s.alerts} alerts`);
  L.push(`  incident level : precision ${pct(s.incident.precision)}  recall ${pct(s.incident.recall)}  F1 ${pct(s.incident.f1)}  `
    + `(recall on detectable ${pct(s.incident.recall_detectable)}; ${s.incident.evasive_incidents} evasive incidents included)`);
  L.push(`  event level    : precision ${pct(s.event.precision)}  recall ${pct(s.event.recall)}  F1 ${pct(s.event.f1)}`);
  L.push(`  median time-to-alert ${ms(s.median_tta_ms)} (max ${ms(s.max_tta_ms)}; includes the reorder-buffer wait)`);
  L.push(`  false alerts per 1,000 benign events: ${s.false_alerts_per_1000_benign === null ? 'n/a' : s.false_alerts_per_1000_benign.toFixed(2)}`);
  L.push(`  missed: ${s.missed_detectable.length} detectable, ${s.missed_evasive.length} evasive`);
  for (const [v, d] of Object.entries(s.detection_by_variant)) L.push(`    ${v.padEnd(48)} ${d.detected}/${d.incidents}`);
  L.push(`  clock: ${s.clock.skewed_within_range} skewed in range, ${s.clock.skew_out_of_range} out of range, `
    + `${s.clock.delayed_1_to_4_s} delayed 1-4 s, ${s.clock.delayed_over_5_s} delayed > 5 s, ${s.clock.late_events} late, ${s.clock.reordered_events} reordered`);
  return L.join('\n');
}

/** @param {any} values @returns {Promise<number>} */
async function run(values) {
  let report;
  try {
    const tuningSeeds = parseSeeds(values.seeds, 'seeds');
    const holdoutSeeds = parseSeeds(values.holdout, 'holdout');
    const warmupSeed = values['warmup-seed'] === undefined ? 1 : parseSeeds(values['warmup-seed'], 'warmup-seed')[0];
    try {
      report = runBenchmark({ tuningSeeds, holdoutSeeds, warmupSeed });
    } catch (e) {
      if (e instanceof RangeError) throw new UsageError(e.message);
      throw e;
    }
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`kig bench detect: ${e.message}\n${USAGE}`);
    return 2;
  }
  const generatedAt = new Date().toISOString();
  const full = { generated_at: generatedAt, ...report };
  const file = values.out ? path.resolve(values.out) : path.join(REPO, 'evidence', `detect-${generatedAt.replace(/[:.]/g, '-')}.json`);
  const note = (/** @type {string} */ s) => (values.json ? process.stderr : process.stdout).write(s + '\n');
  if (values.json) process.stdout.write(JSON.stringify(full, null, 2) + '\n');
  else {
    process.stdout.write(`kig bench detect (synthetic data; baseline ${report.baseline.source}, ${report.baseline.edgeCount} edges, warm-up seed ${report.seeds.warmup})\n`);
    process.stdout.write(summarize('HELD-OUT', report.holdout) + '\n');
    process.stdout.write(summarize('tuning  ', report.tuning) + '\n');
  }
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(full, null, 2) + '\n');
    note(`report: ${file}`);
  } catch (e) {
    note(`report not saved (${/** @type {any} */ (e).code || 'error'}): ${file} is not writable here (read-only filesystem?)`);
  }
  return 0;
}

module.exports = { name, describe, options, USAGE, run, parseSeeds };
