'use strict';
const { SNAPSHOT } = require('../core/contracts.cjs');
const provider = require('../crypto/provider.cjs');
const lease = require('./lease.cjs');

function routes(db, { env = process.env } = {}) {
  const control = (partitioned) => async (_body, req) => {
    const permitted = env.NODE_ENV === 'test' || (typeof env.KIG_NODE_CONTROL_TOKEN === 'string' &&
      typeof req?.headers?.['x-kig-control-token'] === 'string' &&
      provider.hmacEqual(Buffer.from(env.KIG_NODE_CONTROL_TOKEN), Buffer.from(req.headers['x-kig-control-token'])));
    if (!permitted) return { status: 403, json: { error: 'forbidden' } };
    lease.setPartitioned(db, partitioned);
    let remaining = 0;
    try { remaining = Math.max(0, Number((BigInt(lease.get(db, 'lease_until_mono_ns') || '0') - process.hrtime.bigint()) / 1_000_000n)); } catch { /* corrupt lease remains fail-closed */ }
    return { status: 200, json: { partitioned, lease_ms: SNAPSHOT.leaseMs, expires_in_ms: partitioned ? remaining : 0 } };
  };
  return [['POST /v1/control/partition', control(true)], ['POST /v1/control/heal', control(false)]];
}
module.exports = { routes };
