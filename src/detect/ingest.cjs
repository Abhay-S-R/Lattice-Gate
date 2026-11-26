'use strict';
// @ts-check
// Event ingest (architecture §15.2, P1-11). Parses the toolkit practice format
// (CSV, RFC 4180 subset; or JSONL with the same keys) into normalized events.
// Raw source strings are kept untouched; malformed rows go to `rejects` with a
// reason instead of being guessed at or coerced.

const fs = require('node:fs');

const COLUMNS = Object.freeze([
  'event_id', 'event_time_utc', 'received_time_utc', 'source_clock_offset_ms', 'actor',
  'source_service', 'target_service', 'action', 'role_before', 'role_after', 'outcome',
  'approval_id', 'session_id', 'correlation_id',
]);
const REQUIRED_NON_EMPTY = Object.freeze(['event_id', 'actor', 'source_service', 'target_service', 'action', 'outcome']);

const ISO_UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
const INTEGER = /^[+-]?\d{1,15}$/;

/**
 * Strict ISO-8601 UTC ('Z' suffix, optional 1–3 fractional digits). Calendar
 * fields must round-trip, so 2026-02-30 is rejected rather than rolled over.
 * @param {string} s @returns {number} ms since epoch, or NaN
 */
function parseUtc(s) {
  const m = ISO_UTC.exec(s);
  if (!m) return NaN;
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return NaN;
  const d = new Date(ms);
  const ok = d.getUTCFullYear() === Number(m[1]) && d.getUTCMonth() + 1 === Number(m[2]) && d.getUTCDate() === Number(m[3])
    && d.getUTCHours() === Number(m[4]) && d.getUTCMinutes() === Number(m[5]) && d.getUTCSeconds() === Number(m[6]);
  return ok ? ms : NaN;
}

/**
 * @typedef {object} DetectEvent
 * @property {string} id
 * @property {string} rawEventTimeUtc
 * @property {string} rawReceivedTimeUtc
 * @property {number} eventTimeMs
 * @property {number} receivedMs
 * @property {number} offsetMs
 * @property {number|null} correctedMs
 * @property {number|null} deliveryDelayMs
 * @property {boolean} clockUnsupported
 * @property {number} uncertaintyMs
 * @property {number} ingestIdx
 * @property {boolean} late
 * @property {boolean} orderUncertain
 * @property {string} actor
 * @property {string} src
 * @property {string} dst
 * @property {string} action
 * @property {string} roleBefore
 * @property {string} roleAfter
 * @property {string} outcome
 * @property {string|null} approvalId
 * @property {string} session
 * @property {string} correlation
 */

/**
 * Validate one record (column name → string) into an event.
 * @param {Map<string, string>} rec
 * @param {number} ingestIdx
 * @returns {{ event: DetectEvent } | { reason: string }}
 */
function normalize(rec, ingestIdx) {
  for (const c of REQUIRED_NON_EMPTY) {
    if (rec.get(c) === '') return { reason: `empty_${c}` };
  }
  const rawEventTimeUtc = /** @type {string} */ (rec.get('event_time_utc'));
  const rawReceivedTimeUtc = /** @type {string} */ (rec.get('received_time_utc'));
  const eventTimeMs = parseUtc(rawEventTimeUtc);
  if (Number.isNaN(eventTimeMs)) return { reason: 'invalid_event_time_utc' };
  const receivedMs = parseUtc(rawReceivedTimeUtc);
  if (Number.isNaN(receivedMs)) return { reason: 'invalid_received_time_utc' };
  const rawOffset = /** @type {string} */ (rec.get('source_clock_offset_ms'));
  const offsetMs = INTEGER.test(rawOffset) ? Number(rawOffset) : NaN;
  if (!Number.isSafeInteger(offsetMs)) return { reason: 'invalid_source_clock_offset_ms' };
  const approval = /** @type {string} */ (rec.get('approval_id'));
  return {
    event: {
      id: /** @type {string} */ (rec.get('event_id')),
      rawEventTimeUtc,
      rawReceivedTimeUtc,
      eventTimeMs,
      receivedMs,
      offsetMs,
      correctedMs: null,
      deliveryDelayMs: null,
      clockUnsupported: false,
      uncertaintyMs: 0,
      ingestIdx,
      late: false,
      orderUncertain: false,
      actor: /** @type {string} */ (rec.get('actor')),
      src: /** @type {string} */ (rec.get('source_service')),
      dst: /** @type {string} */ (rec.get('target_service')),
      action: /** @type {string} */ (rec.get('action')),
      roleBefore: /** @type {string} */ (rec.get('role_before')),
      roleAfter: /** @type {string} */ (rec.get('role_after')),
      outcome: /** @type {string} */ (rec.get('outcome')),
      approvalId: approval === '' ? null : approval,
      session: /** @type {string} */ (rec.get('session_id')),
      correlation: /** @type {string} */ (rec.get('correlation_id')),
    },
  };
}

/**
 * Split CSV text into rows (RFC 4180 subset): quoted fields with "" escapes,
 * commas and newlines inside quotes, CRLF or LF row ends. A quote error marks
 * only its own row.
 * @param {string} text
 * @returns {Array<{ fields: string[], line: number, raw: string, error: string|null }>}
 */
function splitCsv(text) {
  const rows = [];
  let i = 0;
  let line = 1;
  const n = text.length;
  while (i < n) {
    const start = i;
    const startLine = line;
    const fields = [];
    let field = '';
    let error = null;
    let quoted = false; // current field opened with a quote
    let inQuotes = false;
    let fieldStart = true;
    let ended = false;
    while (i < n && !ended) {
      const ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i++;
          const next = text[i];
          if (i < n && next !== ',' && next !== '\n' && next !== '\r') error = error || 'stray_quote';
          continue;
        }
        if (ch === '\n') line++;
        field += ch; i++;
        continue;
      }
      if (ch === ',') { fields.push(field); field = ''; quoted = false; fieldStart = true; i++; continue; }
      if (ch === '\n' || ch === '\r') {
        i += (ch === '\r' && text[i + 1] === '\n') ? 2 : 1;
        line++;
        ended = true;
        continue;
      }
      if (ch === '"') {
        if (fieldStart && !quoted) { quoted = true; inQuotes = true; fieldStart = false; i++; continue; }
        error = error || 'bare_quote';
      }
      fieldStart = false;
      field += ch; i++;
    }
    if (inQuotes) error = error || 'unterminated_quote';
    fields.push(field);
    let end = i;
    while (end > start && (text[end - 1] === '\n' || text[end - 1] === '\r')) end--;
    rows.push({ fields, line: startLine, raw: text.slice(start, end), error });
  }
  return rows;
}

/** @param {string} text */
const stripBom = (text) => (text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);

/**
 * @param {string} text
 * @returns {{ events: DetectEvent[], rejects: Array<{ line: number, reason: string, raw: string }> }}
 */
function parseCsv(text) {
  const rows = splitCsv(stripBom(text)).filter((r) => !(r.fields.length === 1 && r.fields[0] === '' && !r.error));
  if (rows.length === 0 || rows[0].error) throw new Error('events CSV has no valid header row');
  const header = rows[0].fields;
  if (new Set(header).size !== header.length) throw new Error('events CSV header has duplicate column names');
  const missing = COLUMNS.filter((c) => !header.includes(c));
  if (missing.length) throw new Error(`events CSV header is missing column(s): ${missing.join(', ')}`);

  const events = [];
  const rejects = [];
  const seen = new Set();
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const ingestIdx = r - 1;
    const reject = (/** @type {string} */ reason) => rejects.push({ line: row.line, reason, raw: row.raw });
    if (row.error) { reject(row.error); continue; }
    if (row.fields.length !== header.length) { reject('column_count'); continue; }
    const rec = new Map(header.map((h, k) => [h, row.fields[k]]));
    const res = normalize(rec, ingestIdx);
    if ('reason' in res) { reject(res.reason); continue; }
    if (seen.has(res.event.id)) { reject('duplicate_event_id'); continue; }
    seen.add(res.event.id);
    events.push(res.event);
  }
  return { events, rejects };
}

/**
 * JSON Lines with the same keys as the CSV columns. Values must be strings
 * (source_clock_offset_ms may also be an integer number).
 * @param {string} text
 */
function parseJsonl(text) {
  const events = [];
  const rejects = [];
  const seen = new Set();
  const lines = stripBom(text).split(/\r?\n/);
  let ingestIdx = 0;
  for (let k = 0; k < lines.length; k++) {
    const raw = lines[k];
    if (raw.trim() === '') continue;
    const idx = ingestIdx++;
    const reject = (/** @type {string} */ reason) => rejects.push({ line: k + 1, reason, raw });
    let obj;
    try { obj = JSON.parse(raw); } catch { reject('invalid_json'); continue; }
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) { reject('not_an_object'); continue; }
    /** @type {Map<string, string>} */
    const rec = new Map();
    let bad = null;
    for (const c of COLUMNS) {
      if (!Object.prototype.hasOwnProperty.call(obj, c)) { bad = `missing_field_${c}`; break; }
      const v = obj[c];
      if (typeof v === 'string') rec.set(c, v);
      else if (c === 'source_clock_offset_ms' && Number.isSafeInteger(v)) rec.set(c, String(v));
      else { bad = `invalid_field_${c}`; break; }
    }
    if (bad) { reject(bad); continue; }
    const res = normalize(rec, idx);
    if ('reason' in res) { reject(res.reason); continue; }
    if (seen.has(res.event.id)) { reject('duplicate_event_id'); continue; }
    seen.add(res.event.id);
    events.push(res.event);
  }
  return { events, rejects };
}

/**
 * Read an events file; `.jsonl` / `.ndjson` → JSONL, anything else → CSV.
 * Invalid UTF-8 is an error, never replaced silently.
 * @param {string} filePath
 */
function loadEventsFile(filePath) {
  const buf = fs.readFileSync(filePath);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    throw new Error('events file is not valid UTF-8');
  }
  return /\.(jsonl|ndjson)$/i.test(filePath) ? parseJsonl(text) : parseCsv(text);
}

module.exports = { COLUMNS, parseUtc, parseCsv, parseJsonl, loadEventsFile };
