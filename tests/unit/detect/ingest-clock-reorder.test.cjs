'use strict';
// Task 5.1: ingest, clock correction, reorder buffer (P1-11, architecture §15.2).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseCsv, parseJsonl, loadEventsFile, COLUMNS } = require('../../../src/detect/ingest.cjs');
const { correct } = require('../../../src/detect/clock.cjs');
const { ReorderBuffer } = require('../../../src/detect/reorder.cjs');
const { DEFAULT_CONFIG, mergeConfig, DOCUMENTED_PRACTICE_EDGES, DEFAULT_ROLE_RANKS } = require('../../../src/detect/config.cjs');

const HEADER = COLUMNS.join(',');
/** One CSV row from a partial record; times default to a fixed instant. */
function row(o = {}) {
  const r = {
    event_id: 'e1', event_time_utc: '2026-01-15T09:00:00.000Z', received_time_utc: '2026-01-15T09:00:00.100Z',
    source_clock_offset_ms: '0', actor: 'a', source_service: 's', target_service: 't', action: 'read',
    role_before: 'viewer', role_after: 'viewer', outcome: 'allow', approval_id: '', session_id: 'sess', correlation_id: 'flow',
    ...o,
  };
  return COLUMNS.map((c) => r[c]).join(',');
}
const csv = (...rows) => [HEADER, ...rows].join('\n') + '\n';
const one = (o) => correct(parseCsv(csv(row(o))).events[0]);

// ---- config ----

test('config defaults match the plan (2.4)', () => {
  assert.equal(DEFAULT_CONFIG.maxOffsetMs, 5000);
  assert.equal(DEFAULT_CONFIG.latenessMs, 5000);
  assert.equal(DEFAULT_CONFIG.uncertaintyMs, 250);
  assert.equal(DEFAULT_CONFIG.lmWindowMs, 60000);
  assert.equal(DEFAULT_CONFIG.lm1EdgeThreshold, 3);
  assert.equal(DEFAULT_CONFIG.lm3DenyThreshold, 3);
  assert.equal(DEFAULT_CONFIG.lm3TargetThreshold, 2);
  assert.deepEqual([...DEFAULT_CONFIG.sensitiveServices], ['identity', 'billing', 'archive']);
  assert.equal(DEFAULT_CONFIG.revocationContextWindowMs, 300000);
  assert.ok(DEFAULT_ROLE_RANKS instanceof Map);
  assert.deepEqual([...DEFAULT_ROLE_RANKS], [['viewer', 1], ['service-reader', 2], ['report-reader', 3], ['operator', 4], ['admin', 5]]);
  assert.equal(DOCUMENTED_PRACTICE_EDGES.length, 7);
});

test('mergeConfig overrides, validates and keeps defaults', () => {
  const c = mergeConfig({ lmWindowMs: 30000, sensitiveServices: ['vault'] });
  assert.equal(c.lmWindowMs, 30000);
  assert.equal(c.latenessMs, 5000);
  assert.ok(c.sensitiveSet.has('vault') && !c.sensitiveSet.has('billing'));
  assert.ok(c.roleRanks instanceof Map);
  assert.throws(() => mergeConfig({ lmWindowMs: -1 }), /lmWindowMs/);
  assert.throws(() => mergeConfig({ lm1EdgeThreshold: 1.5 }), /lm1EdgeThreshold/);
  assert.throws(() => mergeConfig({ noSuchKey: 1 }), /noSuchKey/);
  const r = mergeConfig({ roleRanks: [['guest', 0], ['viewer', 1]] });
  assert.equal(r.roleRanks.get('guest'), 0);
});

// ---- ingest ----

test('parseCsv parses quoted fields, embedded commas, escaped quotes, and CRLF', () => {
  const text = [HEADER, row({ event_id: 'e1', actor: '"x, ""y"""', session_id: '"multi\r\nline"' }), row({ event_id: 'e2' })].join('\r\n') + '\r\n';
  const { events, rejects } = parseCsv(text);
  assert.deepEqual(rejects, []);
  assert.equal(events.length, 2);
  assert.equal(events[0].actor, 'x, "y"');
  assert.equal(events[0].session, 'multi\r\nline');
  assert.equal(events[1].id, 'e2');
  assert.equal(events[1].ingestIdx, 1);
});

test('parseCsv normalizes every field and keeps raw strings', () => {
  const { events } = parseCsv(csv(row({ approval_id: 'change-1', source_clock_offset_ms: '-250' })));
  const e = events[0];
  assert.equal(e.id, 'e1');
  assert.equal(e.rawEventTimeUtc, '2026-01-15T09:00:00.000Z');
  assert.equal(e.rawReceivedTimeUtc, '2026-01-15T09:00:00.100Z');
  assert.equal(e.eventTimeMs, Date.parse('2026-01-15T09:00:00.000Z'));
  assert.equal(e.receivedMs, Date.parse('2026-01-15T09:00:00.100Z'));
  assert.equal(e.offsetMs, -250);
  assert.equal(e.correctedMs, null);
  assert.equal(e.ingestIdx, 0);
  assert.equal(e.late, false);
  assert.equal(e.orderUncertain, false);
  assert.deepEqual([e.actor, e.src, e.dst, e.action, e.roleBefore, e.roleAfter, e.outcome, e.approvalId, e.session, e.correlation],
    ['a', 's', 't', 'read', 'viewer', 'viewer', 'allow', 'change-1', 'sess', 'flow']);
  assert.equal(parseCsv(csv(row())).events[0].approvalId, null, 'empty approval_id → null');
});

test('parseCsv quarantines malformed rows into rejects without throwing', () => {
  const text = csv(
    row({ event_id: 'ok1' }),
    row({ event_id: 'bad-time', event_time_utc: '2026-01-15 09:00:00' }),
    row({ event_id: 'bad-day', received_time_utc: '2026-02-30T09:00:00.000Z' }),
    row({ event_id: 'bad-offset', source_clock_offset_ms: '1.5' }),
    row({ event_id: 'bad-offset2', source_clock_offset_ms: 'abc' }),
    row({ event_id: 'no-actor', actor: '' }),
    'too,few,columns',
    row({ event_id: 'ok1' }),
    row({ event_id: 'ok2' }),
  );
  const { events, rejects } = parseCsv(text);
  assert.deepEqual(events.map((e) => e.id), ['ok1', 'ok2']);
  assert.deepEqual(rejects.map((r) => r.reason), [
    'invalid_event_time_utc', 'invalid_received_time_utc', 'invalid_source_clock_offset_ms', 'invalid_source_clock_offset_ms',
    'empty_actor', 'column_count', 'duplicate_event_id']);
  assert.deepEqual(rejects.map((r) => r.line), [3, 4, 5, 6, 7, 8, 9]);
  for (const r of rejects) assert.equal(typeof r.raw, 'string');
  assert.equal(events[1].ingestIdx, 8, 'ingestIdx is the arrival position among data rows');
});

test('parseCsv rejects quote errors per row and keeps going', () => {
  const text = csv(row({ event_id: 'x', actor: 'a"b' }), row({ event_id: 'y' }), row({ event_id: 'z', actor: '"open' }));
  const { events, rejects } = parseCsv(text);
  assert.deepEqual(events.map((e) => e.id), ['y']);
  assert.deepEqual(rejects.map((r) => r.reason), ['bare_quote', 'unterminated_quote']);
});

test('parseCsv throws on a missing header column', () => {
  assert.throws(() => parseCsv('event_id,actor\nx,y\n'), /missing column/);
  assert.throws(() => parseCsv(''), /header/);
});

test('parseCsv tolerates BOM, extra columns and blank trailing lines', () => {
  const text = '﻿' + HEADER + ',extra\n' + row() + ',z\n\n\n';
  const { events, rejects } = parseCsv(text);
  assert.equal(events.length, 1);
  assert.deepEqual(rejects, []);
});

test('parseJsonl produces identical normalized events to parseCsv', () => {
  const recs = [{ event_id: 'e1' }, { event_id: 'e2', approval_id: 'c-1', source_clock_offset_ms: '2000' }];
  const full = (o) => Object.fromEntries(COLUMNS.map((c, i) => [c, row(o).split(',')[i]]));
  const fromCsv = parseCsv(csv(...recs.map(row))).events;
  const jsonl = recs.map((o) => JSON.stringify({ ...full(o), source_clock_offset_ms: Number(full(o).source_clock_offset_ms) })).join('\n') + '\n';
  const fromJsonl = parseJsonl(jsonl).events;
  assert.deepEqual(fromJsonl, fromCsv);
});

test('parseJsonl rejects non-objects, bad JSON and missing fields', () => {
  const good = Object.fromEntries(COLUMNS.map((c, i) => [c, row().split(',')[i]]));
  const missing = { ...good, event_id: 'm' };
  delete missing.actor;
  const text = ['[1]', '{bad', JSON.stringify(missing), JSON.stringify(good)].join('\n');
  const { events, rejects } = parseJsonl(text);
  assert.equal(events.length, 1);
  assert.deepEqual(rejects.map((r) => r.reason), ['not_an_object', 'invalid_json', 'missing_field_actor']);
});

test('loadEventsFile dispatches on extension', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-ingest-'));
  fs.writeFileSync(path.join(dir, 'e.csv'), csv(row()));
  const rec = Object.fromEntries(COLUMNS.map((c, i) => [c, row().split(',')[i]]));
  fs.writeFileSync(path.join(dir, 'e.jsonl'), JSON.stringify(rec) + '\n');
  assert.equal(loadEventsFile(path.join(dir, 'e.csv')).events.length, 1);
  assert.equal(loadEventsFile(path.join(dir, 'e.jsonl')).events.length, 1);
  fs.writeFileSync(path.join(dir, 'bad.csv'), Buffer.from([0xff, 0xfe, 0x00]));
  assert.throws(() => loadEventsFile(path.join(dir, 'bad.csv')), /UTF-8/);
});

// ---- clock ----

test('clock evt-015', () => {
  const e = one({ event_id: 'evt-015', event_time_utc: '2026-01-15T09:06:03.000Z', received_time_utc: '2026-01-15T09:06:01.200Z', source_clock_offset_ms: '2000' });
  assert.equal(e.correctedMs, Date.parse('2026-01-15T09:06:01.000Z'));
  assert.equal(e.deliveryDelayMs, 200);
  assert.equal(e.clockUnsupported, false);
  assert.equal(e.orderUncertain, false);
  assert.equal(e.uncertaintyMs, 250);
  assert.equal(e.rawEventTimeUtc, '2026-01-15T09:06:03.000Z');
  assert.equal(e.rawReceivedTimeUtc, '2026-01-15T09:06:01.200Z');
  assert.equal(e.offsetMs, 2000);
});

test('clock does not mutate its input', () => {
  const raw = parseCsv(csv(row({ source_clock_offset_ms: '2000' }))).events[0];
  const before = JSON.stringify(raw);
  correct(raw);
  assert.equal(JSON.stringify(raw), before);
});

test('clock offset +6000 and -5001 flagged clockUnsupported and NOT clamped', () => {
  for (const off of [6000, -5001]) {
    const e = one({ source_clock_offset_ms: String(off) });
    assert.equal(e.clockUnsupported, true);
    assert.equal(e.offsetMs, off);
    assert.equal(e.correctedMs, e.eventTimeMs - off, 'computed for diagnostics, never clamped');
    assert.equal(e.orderUncertain, true);
    assert.equal(e.orderMs, e.receivedMs, 'ordered by receipt');
  }
  for (const off of [5000, -5000]) assert.equal(one({ source_clock_offset_ms: String(off) }).clockUnsupported, false, 'boundary is supported');
});

// ---- reorder ----

/** Build corrected events at the given event-time offsets (ms after t0), arriving in array order. */
function evs(specs) {
  const t0 = Date.parse('2026-01-15T09:00:00.000Z');
  const iso = (ms) => new Date(t0 + ms).toISOString();
  const text = csv(...specs.map((s, i) => row({
    event_id: s.id ?? `e${i}`, event_time_utc: iso(s.at), received_time_utc: iso(s.rx ?? s.at + 100),
    actor: s.actor ?? 'a', session_id: s.session ?? 'sess',
  })));
  return parseCsv(text).events.map((e) => correct(e));
}

test('reorder evt-014 then evt-013', () => {
  // practice: evt-014 at 09:05:02 received first; evt-013 at 09:05:01 received 09:05:04.2
  const [e14, e13, later] = evs([
    { id: 'evt-014', at: 5 * 60000 + 2000, rx: 5 * 60000 + 2200 },
    { id: 'evt-013', at: 5 * 60000 + 1000, rx: 5 * 60000 + 4200 },
    { id: 'evt-015', at: 6 * 60000 + 1000, rx: 6 * 60000 + 1200 },
  ]);
  const buf = new ReorderBuffer();
  const out = [...buf.push(e14), ...buf.push(e13), ...buf.push(later), ...buf.flush()];
  assert.deepEqual(out.map((e) => e.id), ['evt-013', 'evt-014', 'evt-015']);
  assert.ok(e14.ingestIdx < e13.ingestIdx, 'ingest order kept');
  assert.equal(e13.late, false);
  assert.equal(e14.late, false);
});

test('reorder releases only once the watermark passes', () => {
  const [a, b, c] = evs([{ at: 0 }, { at: 3000 }, { at: 5000 }]);
  const buf = new ReorderBuffer({ latenessMs: 5000 });
  assert.deepEqual(buf.push(a), []);
  assert.deepEqual(buf.push(b), []);
  assert.deepEqual(buf.push(c).map((e) => e.id), ['e0'], 'watermark = 5000 - 5000 = 0');
  assert.deepEqual(buf.flush().map((e) => e.id), ['e1', 'e2']);
});

test('reorder late event past 5 s watermark marked late=true and still emitted', () => {
  const [a, b, old] = evs([{ at: 10000 }, { at: 20000 }, { at: 1000, rx: 21000 }]);
  const buf = new ReorderBuffer();
  const out = [...buf.push(a), ...buf.push(b)];
  const lateOut = buf.push(old);
  assert.ok(lateOut.includes(old), 'late event emitted immediately');
  assert.equal(old.late, true);
  assert.equal(a.late, false);
  out.push(...lateOut, ...buf.flush());
  assert.deepEqual(out.map((e) => e.id).sort(), ['e0', 'e1', 'e2']);
});

test('reorder overlapping uncertainty intervals', () => {
  const [a, b] = evs([{ at: 0 }, { at: 300 }]);
  const buf = new ReorderBuffer({ uncertaintyMs: 250 });
  buf.push(a); buf.push(b); buf.flush();
  assert.equal(a.orderUncertain, true);
  assert.equal(b.orderUncertain, true);

  const [c, d] = evs([{ at: 0 }, { at: 600 }]);
  const buf2 = new ReorderBuffer({ uncertaintyMs: 250 });
  buf2.push(c); buf2.push(d); buf2.flush();
  assert.equal(c.orderUncertain, false);
  assert.equal(d.orderUncertain, false);
});

test('overlap is only checked within the same actor and session', () => {
  const [a, b, c] = evs([{ at: 0, actor: 'x' }, { at: 100, actor: 'y' }, { at: 200, actor: 'x', session: 'other' }]);
  const buf = new ReorderBuffer();
  buf.push(a); buf.push(b); buf.push(c); buf.flush();
  assert.deepEqual([a, b, c].map((e) => e.orderUncertain), [false, false, false]);
});

test('overlap detected across separate release batches', () => {
  const [a, b, far] = evs([{ at: 0 }, { at: 6000 }, { at: 6200, rx: 30000 }]);
  const buf = new ReorderBuffer();
  buf.push(a); buf.push(b);
  buf.push(far);
  buf.flush();
  assert.equal(b.orderUncertain, true);
  assert.equal(far.orderUncertain, true);
  assert.equal(a.orderUncertain, false);
});

test('clock-unsupported events are ordered by receipt and never advance the watermark', () => {
  const t0 = Date.parse('2026-01-15T09:00:00.000Z');
  const iso = (ms) => new Date(t0 + ms).toISOString();
  const text = csv(
    row({ event_id: 'skewed', event_time_utc: iso(60000), received_time_utc: iso(1000), source_clock_offset_ms: '-9000' }),
    row({ event_id: 'n1', event_time_utc: iso(2000), received_time_utc: iso(2100) }),
  );
  const [s, n] = parseCsv(text).events.map((e) => correct(e));
  const buf = new ReorderBuffer();
  assert.deepEqual(buf.push(s), []);
  assert.equal(buf.maxCorrectedMs, -Infinity, 'unsupported clock does not move the watermark');
  buf.push(n);
  assert.deepEqual(buf.flush().map((e) => e.id), ['skewed', 'n1']);
});

test('released events carry a simulated collector release time (watermark wait)', () => {
  const [a, b] = evs([{ at: 0, rx: 100 }, { at: 7000, rx: 7100 }]);
  const buf = new ReorderBuffer();
  buf.push(a);
  const out = buf.push(b);
  assert.deepEqual(out, [a]);
  assert.equal(a.releasedAtMs, b.receivedMs, 'released when the watermark passed, at that arrival');
  buf.flush();
  assert.equal(b.releasedAtMs, b.correctedMs + 5000, 'flushed at its lateness deadline');
});
