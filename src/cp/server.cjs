'use strict';
const { serve } = require('../core/http.cjs');
const { ports, ROUTES } = require('../core/contracts.cjs');

function start({ env = process.env } = {}) {
  const route = new Map([[ROUTES.cp.health, async () => ({ status: 200, json: { status: 'ok', service: 'cp', instance: env.KIG_INSTANCE_TOKEN || null } })]]);
  const server = serve(ports(env).cp, route);
  const stop = () => server.close();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  return server;
}

if (require.main === module) start();
module.exports = { start };
