'use strict';
const { tx } = require('../store/db.cjs');
const audit = require('../core/audit.cjs');
const ids = require('../core/ids.cjs');
const { publish } = require('./snapshot.cjs');

function revoke(db, deviceId, { env = process.env } = {}) {
  if (!ids.isId(deviceId)) throw new Error('invalid_device_id');
  tx(db, () => {
    const row = db.prepare('SELECT status FROM devices WHERE device_id=?').get(ids.enc(deviceId));
    if (!row) throw new Error('device_not_found');
    if (row.status === 'revoked') throw new Error('device_already_revoked');
    if (row.status !== 'active') throw new Error('device_not_active');
    const changed = db.prepare("UPDATE devices SET status='revoked' WHERE device_id=? AND status='active'").run(ids.enc(deviceId));
    if (Number(changed.changes) !== 1) throw new Error('device_not_active');
    audit.append(db, {
      gen: 0, kind: 'device_revoked', op: 'device.revoke', actor: 'operator', asset: deviceId,
      decision: 'allow', rule: 'device_revoked',
    });
  });
  const epoch = publish(db, { env });
  return { device_id: deviceId, epoch };
}

module.exports = { revoke };
