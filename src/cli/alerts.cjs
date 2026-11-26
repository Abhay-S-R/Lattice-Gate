'use strict';
// @ts-check
// `kig alerts (--adapter <stateDir> | --db <file>) [--json] [--limit N]`
// Operator view of self-monitoring alerts (features P0-10, architecture §5.7):
// kind='alert' audit events, newest first. Every stored value is treated as
// untrusted and rendered through text.safe (no terminal injection).
const ids = require('../core/ids.cjs');
const { STORE_OPTIONS, storePath, withStore } = require('./store-arg.cjs');
const { UsageError } = require('./main.cjs');
const { safe, safeJson } = require('./text.cjs');

const SEVERITIES = new Set(['info', 'low', 'medium', 'high']);

/** Decode a D-04 stored identifier; anything undecodable is shown as raw text. */
function decId(t) {
  if (t == null) return null;
  try { const v = ids.dec(t); return typeof v === 'string' ? v : String(t); } catch { return String(t); }
}

function parseDetail(text) {
  let d = null;
  try { d = JSON.parse(text); } catch { /* tampered or absent */ }
  const severity = d && typeof d.severity === 'string' && SEVERITIES.has(d.severity) ? d.severity : 'unknown';
  const reason = d && typeof d.reason === 'string' ? d.reason : '(unreadable detail)';
  return { severity, reason };
}

function toRecord(row) {
  const { severity, reason } = parseDetail(row.detail);
  return {
    seq: Number(row.seq),
    time: Number.isSafeInteger(Number(row.ts_ms)) ? new Date(Number(row.ts_ms)).toISOString() : 'invalid-time',
    rule: typeof row.rule === 'string' ? row.rule : null,
    severity,
    op: typeof row.op === 'string' ? row.op : null,
    actor: decId(row.actor),
    asset: decId(row.asset),
    request_id: decId(row.request_id),
    reason,
  };
}

function line(a) {
  const ids_ = [['actor', a.actor], ['asset', a.asset], ['request', a.request_id]]
    .filter(([, v]) => v !== null).map(([k, v]) => `${k}=${safe(v)}`).join(' ');
  const rule = /^[A-Z0-9-]+$/.test(String(a.rule)) ? a.rule : safe(a.rule);
  return `#${a.seq} ${a.time} ${a.severity.padEnd(7)} ${rule}${ids_ ? ` ${ids_}` : ''} : ${safe(a.reason)}`;
}

module.exports = {
  name: 'alerts',
  describe: 'list self-monitoring alerts from an audit store, newest first',
  usage: 'usage: node kig.cjs alerts (--adapter <stateDir> | --db <file>) [--json] [--limit N]',
  options: { ...STORE_OPTIONS, json: { type: 'boolean' }, limit: { type: 'string' } },
  async run({ values, io }) {
    const file = storePath(values);
    let limit = -1;
    if (values.limit !== undefined) {
      if (!/^[1-9]\d{0,8}$/.test(values.limit)) throw new UsageError('--limit must be a positive integer');
      limit = Number(values.limit);
    }
    const rows = withStore(file, (db) => db.prepare(
      "SELECT seq, ts_ms, op, request_id, actor, asset, rule, detail FROM audit_events WHERE kind = 'alert' ORDER BY seq DESC LIMIT ?",
    ).all(limit));
    const records = rows.map(toRecord);
    if (values.json) { io.out(`${safeJson(records, 2)}\n`); return 0; }
    if (records.length === 0) { io.out('no alerts\n'); return 0; }
    io.out(`${records.map(line).join('\n')}\n`);
    return 0;
  },
};
