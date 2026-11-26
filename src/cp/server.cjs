'use strict';
const { serve } = require('../core/http.cjs');
const { ports, ROUTES, kigHome, layout } = require('../core/contracts.cjs');
const schema = require('../store/schema-cp.cjs');
const { openDb } = require('../store/db.cjs');
const snapshots = require('./snapshot.cjs');
const policyRoutes = require('./routes-policy.cjs');

function start({ env = process.env } = {}) {
  const L = layout(kigHome(env));
  const db = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
  if (!snapshots.latest(db)) snapshots.publish(db);
  const route = new Map([
    [ROUTES.cp.health, async () => ({ status: 200, json: { status: 'ok', service: 'cp', instance: env.KIG_INSTANCE_TOKEN || null } })],
    ...policyRoutes.routes(db, env),
  ]);
  const server = serve(ports(env).cp, route);
  const stop = () => server.close();
  server.once('close', () => db.close());
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  return server;
}

if (require.main === module) start();
module.exports = { start };
