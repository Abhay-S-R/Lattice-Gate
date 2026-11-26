'use strict';
const { serve } = require('../core/http.cjs');
const fs = require('node:fs');
const { ports, ROUTES, NODE_IDS, kigHome, layout } = require('../core/contracts.cjs');
const schema = require('../store/schema-node.cjs');
const { openDb } = require('../store/db.cjs');
const policyRoutes = require('./routes-policy.cjs');
const authRoutes = require('./routes-auth.cjs');
const fileRoutes = require('./routes-files.cjs');
const controlRoutes = require('./routes-control.cjs');
const transferRoutes = require('./routes-transfer.cjs');
const transfers = require('./transfers.cjs');
const alerts = require('./alerts.cjs');

function start({ env = process.env } = {}) {
  const id = env.KIG_NODE_ID;
  if (!NODE_IDS.includes(id)) throw new TypeError('invalid KIG_NODE_ID');
  const L = layout(kigHome(env));
  const db = openDb(L.node(id).db, { create: false, version: schema.VERSION, init: schema.init });
  const privateKey = policyRoutes.ensureNodeKey(L.root, id);
  const cpPub = fs.readFileSync(L.anchor.cpPolicyPub);
  const route = new Map([
    [ROUTES.node.health, async () => ({ status: 200, json: { status: 'ok', service: 'node', node_id: id, instance: env.KIG_INSTANCE_TOKEN || null } })],
    ...policyRoutes.routes(db, { id, privateKey, cpPub, env }),
    ...authRoutes.routes(db).map(([name, handler]) => [name, alerts.wrap(db, id, handler)]),
    ...fileRoutes.routes(db).map(([name, handler]) => [name, alerts.wrap(db, id, handler)]),
    ...controlRoutes.routes(db, { env }),
    ...transferRoutes.controlRoutes(db, { id, privateKey, cpPub }),
    ...transferRoutes.deviceRoutes(db).map(([name, handler]) => [name, alerts.wrap(db, id, handler)]),
  ]);
  const server = serve(ports(env)[id], route);
  const stopPull = policyRoutes.startPullLoop(db, { id, env, cpPub });
  // Retired versions leave this node once their node-local grace has ended (§12.1).
  const purge = setInterval(() => { try { transfers.purgeRetired(db); } catch { /* retried next tick */ } }, 1000);
  purge.unref();
  server.once('close', () => { stopPull(); clearInterval(purge); db.close(); });
  const stop = () => server.close();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  return server;
}

if (require.main === module) start();
module.exports = { start };
