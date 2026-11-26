'use strict';
const { tx } = require('../store/db.cjs');
const audit = require('../core/audit.cjs');
const { BURST_N, BURST_WINDOW_MS } = require('../core/limits.cjs');

// Alerts are best-effort, fixed-vocabulary audit events. They never change
// the allow/deny response and never put request contents in detail.
function record(db, { id, body, decision }) {
  if (!body || typeof body !== 'object') return;
  const requestId = typeof body.request_id === 'string' ? body.request_id : undefined;
  const device = typeof body.device_id === 'string' ? body.device_id : undefined;
  const rule = decision?.rule;
  const alerts = [];
  if (rule === 'device_revoked') alerts.push(['N-REVOKED-RETRY', 'medium', 'revoked device retried access']);
  if (rule === 'old_key_version') alerts.push(['N-OLD-KEY', 'medium', 'device attempted access with an obsolete file key version']);
  if (rule === 'lease_expired') alerts.push(['N-STALE-NODE', 'high', 'node denied access after its policy lease expired']);
  if (decision?.decision === 'deny' && device) {
    const from = Date.now() - BURST_WINDOW_MS;
    const count = Number(db.prepare("SELECT count(*) AS n FROM audit_events WHERE kind='access' AND decision='deny' AND actor=? AND ts_ms>=?").get(require('../core/ids.cjs').enc(device), from)?.n || 0);
    if (count >= BURST_N) alerts.push(['N-AUTH-BURST', 'high', 'repeated authentication failures within the alert window']);
  }
  if (!alerts.length) return;
  try {
    tx(db, () => {
      for (const [alertRule, severity, reason] of alerts) audit.append(db, {
        gen: 0, kind: 'alert', op: typeof body.op === 'string' ? body.op : 'policy.probe',
        request_id: requestId, actor: device, asset: id, decision: 'deny', rule: alertRule,
        detail: { severity, reason },
      });
    });
  } catch { /* monitoring failure must not alter the access decision */ }
}

function wrap(db, id, handler) {
  return async (body, req) => {
    const result = await handler(body, req);
    try { record(db, { id, body, decision: result?.json }); } catch { /* alerting is best-effort */ }
    return result;
  };
}
module.exports = { record, wrap };
