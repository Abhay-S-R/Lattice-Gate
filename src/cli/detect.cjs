'use strict';
// @ts-check
// `kig detect --events <csv|jsonl> [--approvals <json>] [--baseline <json>]
//            [--window-ms <n>] [--max-offset-ms <n>] [--json]`
// Runs the detector over an event file and prints alerts with explanations
// plus the timeline (raw, received and corrected times kept side by side).
// Every value from the input is escaped before it reaches the terminal.
// Exit: 0 success, 2 bad arguments or unreadable/invalid input.

const { parseArgs } = require('node:util');
const { detect } = require('../detect/index.cjs');
const { loadEventsFile } = require('../detect/ingest.cjs');
const { loadApprovalsFile } = require('../detect/approvals.cjs');
const { Baseline } = require('../detect/baseline.cjs');

const name = 'detect';
const describe = 'explainable privilege-change and lateral-movement detection over an event file';
const options = /** @type {const} */ ({
  events: { type: 'string' },
  approvals: { type: 'string' },
  baseline: { type: 'string' },
  'window-ms': { type: 'string' },
  'max-offset-ms': { type: 'string' },
  json: { type: 'boolean', default: false },
  help: { type: 'boolean', short: 'h', default: false },
});

const USAGE = 'usage: node kig.cjs detect --events <file.csv|file.jsonl> [--approvals <approvals.json>] '
  + '[--baseline <baseline.json>] [--window-ms <ms>] [--max-offset-ms <ms>] [--json]\n';

/** Characters that could steer a terminal: C0/C1 controls, DEL, line/paragraph separators, bidi overrides, lone surrogates. */
/** `\uXXXX` escape text for a code point (built at runtime so the source holds no raw separators). */
const cp = (/** @type {number} */ n) => '\\u' + n.toString(16).padStart(4, '0');
const range = (/** @type {number} */ a, /** @type {number} */ b) => `${cp(a)}-${cp(b)}`;
/** C1 controls and DEL, line/paragraph separators, bidi embeddings/overrides/isolates. */
const EXTRA = [range(0x7f, 0x9f), range(0x2028, 0x2029), range(0x202a, 0x202e), range(0x2066, 0x2069)].join('');
const HIGH = range(0xd800, 0xdbff);
const LOW = range(0xdc00, 0xdfff);
const UNSAFE = new RegExp(`[${range(0, 0x1f)}${EXTRA}]|[${HIGH}](?![${LOW}])|(?<![${HIGH}])[${LOW}]`, 'g');
const JSON_UNSAFE = new RegExp(`[${EXTRA}]`, 'g');
const hex4 = (/** @type {string} */ c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
/** Escape untrusted text for terminal display. @param {unknown} s */
const safe = (s) => String(s).replace(UNSAFE, hex4);
/** JSON text with the characters JSON.stringify leaves raw (C1, bidi, separators) escaped too. @param {unknown} v */
const safeJson = (/** @type {unknown} */ v) => JSON.stringify(v, null, 2).replace(JSON_UNSAFE, hex4);

class UsageError extends Error {}

/** @param {string|undefined} v @param {string} flag */
function intOpt(v, flag) {
  if (v === undefined) return undefined;
  if (!/^\d{1,12}$/.test(v)) throw new UsageError(`--${flag} must be a non-negative integer (milliseconds)`);
  return Number(v);
}

/** @param {any} r @param {any[]} rejects */
function render(r, rejects) {
  const L = [];
  L.push(`kig detect: ${r.stats.events} events (${rejects.length} rejected), ${r.alerts.length} alert(s), ${r.notices.length} notice(s); `
    + `baseline ${safe(r.baseline.source)} (${r.baseline.edgeCount} edges); window ${r.config.lmWindowMs / 1000} s; lateness ${r.config.latenessMs / 1000} s`);
  for (const x of rejects) L.push(`REJECTED line ${x.line}: ${safe(x.reason)}`);
  for (const a of r.alerts) {
    L.push('');
    L.push(`${a.alert_id}  ${a.rule_id}  ${a.severity}  ${a.classification}`);
    L.push(`  identity : ${safe(a.identity)}   session: ${safe(a.session || '-')}   flow: ${safe(a.correlation || '-')}`);
    L.push(`  window   : ${a.window.start_utc} .. ${a.window.end_utc}${a.order_uncertain ? '   ORDER UNCERTAIN' : ''}`);
    L.push(`  path     : ${a.path.map(safe).join(', ')}`);
    L.push(`  events   : ${a.outcomes.map((/** @type {any} */ o) => `${safe(o.event_id)} (${safe(o.outcome)})`).join(', ')}`);
    if (a.also_matched && a.also_matched.length) L.push(`  also     : ${a.also_matched.join(', ')}`);
    L.push(`  reason   : ${safe(a.reason)}`);
    L.push(`  tta      : ${a.tta_ms} ms (simulated collector clock, includes the reorder wait)`);
  }
  for (const n of r.notices) {
    L.push('');
    L.push(`${n.notice_id}  ${n.rule_id}  ${n.severity}  ${n.classification}`);
    L.push(`  ${safe(n.reason)}`);
  }
  L.push('');
  L.push('timeline (event-time order; ingest index, raw and received times kept)');
  L.push('  ingest  event_id      corrected (UTC)           received (UTC)            offset   delay  flags  classification');
  for (const e of r.timeline) {
    const flags = [e.late ? 'L' : '', e.clock_unsupported ? 'C' : '', e.order_uncertain ? 'U' : ''].join('') || '-';
    L.push(`  ${String(e.ingest_idx).padStart(6)}  ${safe(e.event_id).padEnd(12)}  ${e.corrected_time_utc}  ${safe(e.received_time_utc).padEnd(24)}  `
      + `${String(e.source_clock_offset_ms).padStart(6)}  ${String(e.delivery_delay_ms).padStart(5)}  ${flags.padEnd(5)}  ${safe(e.classification)}`);
  }
  L.push('  flags: L late (arrived below the watermark), C clock offset unsupported (ordered by receipt), U order uncertain');
  return L.join('\n') + '\n';
}

/** @param {any} values parsed options @returns {Promise<number>} */
async function run(values) {
  if (values.help) { process.stdout.write(USAGE); return 0; }
  try {
    if (!values.events) throw new UsageError('--events is required');
    const cfg = { lmWindowMs: intOpt(values['window-ms'], 'window-ms'), maxOffsetMs: intOpt(values['max-offset-ms'], 'max-offset-ms') };
    let loaded, approvals, baseline;
    try { loaded = loadEventsFile(values.events); } catch (e) { throw new UsageError(`cannot read events: ${/** @type {Error} */ (e).message}`); }
    try { approvals = values.approvals ? loadApprovalsFile(values.approvals) : undefined; } catch (e) { throw new UsageError(`cannot read approvals: ${/** @type {Error} */ (e).message}`); }
    try { baseline = values.baseline ? Baseline.fromFile(values.baseline) : undefined; } catch (e) { throw new UsageError(`cannot read baseline: ${/** @type {Error} */ (e).message}`); }
    let r;
    try { r = detect(loaded.events, approvals, baseline, cfg); } catch (e) { throw new UsageError(/** @type {Error} */ (e).message); }
    process.stdout.write(values.json ? safeJson({ ...r, rejects: loaded.rejects }) + '\n' : render(r, loaded.rejects));
    return 0;
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    process.stderr.write(`kig detect: ${safe(e.message)}\n${USAGE}`);
    return 2;
  }
}

/** @param {string[]} argv @returns {Promise<number>} */
async function main(argv) {
  let values;
  try {
    ({ values } = parseArgs({ args: argv, options, strict: true, allowPositionals: false }));
  } catch (e) {
    process.stderr.write(`kig detect: ${safe(/** @type {Error} */ (e).message)}\n${USAGE}`);
    return 2;
  }
  return run(values);
}

module.exports = { name, describe, options, run, main, safe, safeJson };
