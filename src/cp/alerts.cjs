'use strict';
const { tx } = require('../store/db.cjs');
const audit = require('../core/audit.cjs');

function append(db, rule, severity, reason, asset) {
  try {
    tx(db, () => audit.append(db, { gen: 0, kind: 'alert', op: 'control.monitor', actor: 'control-plane', asset,
      decision: 'deny', rule, detail: { severity, reason } }));
  } catch { /* monitoring must not change control-plane behavior */ }
}
function recordRevocationRefusal(db, deviceId, refusal) {
  const known = new Set(['device_already_revoked', 'device_not_active', 'device_not_found']);
  if (!known.has(refusal)) return;
  append(db, 'CP-REVOKE-REFUSED', 'medium', 'control plane refused a device revocation request', typeof deviceId === 'string' ? deviceId : undefined);
}
function recordMissingAck(db, epoch, nodeId) {
  append(db, 'CP-MISSING-ACK', 'high', 'node did not acknowledge a published policy before the benchmark deadline', `${nodeId}-${epoch}`);
}
function recordUnreadableVersion(db, fileId) {
  append(db, 'CP-RECOVERY-UNREADABLE', 'high', 'a committed file version could not be decrypted through its custodian wrap after recovery', typeof fileId === 'string' ? fileId : undefined);
}
module.exports = { recordRevocationRefusal, recordMissingAck, recordUnreadableVersion };
