'use strict';
// Phase 4 node routes: CP-signed staging and drop, device transfers with cutoff and grace.
const { ROUTES } = require('../core/contracts.cjs');
const transfers = require('./transfers.cjs');
const lease = require('./lease.cjs');
const { validRequest } = require('./routes-auth.cjs');

const bad = { status: 400, json: { error: 'bad_request' } };

/** CP → node. Never wrapped in device alerts: the caller is the control plane, not a device. */
function controlRoutes(db, { id, privateKey, cpPub }) {
  const ctx = () => ({ nodeId: id, nodeKey: privateKey, cpPub, partitioned: lease.isPartitioned(db) });
  return [
    [ROUTES.node.stage, async (body) => transfers.stage(db, body, ctx())],
    [ROUTES.node.stageDrop, async (body) => transfers.drop(db, body, ctx())],
  ];
}

/** Device → node. */
function deviceRoutes(db) {
  return [
    [ROUTES.node.transferStart, async (body) => {
      if (!validRequest(body) || body.op !== 'file.transfer') return bad;
      return { status: 200, json: transfers.start(db, body) };
    }],
    [ROUTES.node.transferChunk, async (body) => {
      const result = transfers.chunk(db, body);
      return result ? { status: 200, json: result } : bad;
    }],
  ];
}

module.exports = { controlRoutes, deviceRoutes };
