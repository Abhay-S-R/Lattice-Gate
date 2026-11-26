'use strict';
const { serve } = require('../core/http.cjs');
const { ports, ROUTES, NODE_IDS } = require('../core/contracts.cjs');

function start({ env = process.env } = {}) {
  const id = env.KIG_NODE_ID;
  if (!NODE_IDS.includes(id)) throw new TypeError('invalid KIG_NODE_ID');
  const route = new Map([[ROUTES.node.health, async () => ({ status: 200, json: { status: 'ok', service: 'node', node_id: id, instance: env.KIG_INSTANCE_TOKEN || null } })]]);
  const server = serve(ports(env)[id], route);
  const stop = () => server.close();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  return server;
}

if (require.main === module) start();
module.exports = { start };
