'use strict';
const { serve } = require('../core/http.cjs');
const { ports, ROUTES, kigHome, layout } = require('../core/contracts.cjs');
const schema = require('../store/schema-cp.cjs');
const { openDb } = require('../store/db.cjs');
const snapshots = require('./snapshot.cjs');
const policyRoutes = require('./routes-policy.cjs');
const revokeRoutes = require('./routes-revoke.cjs');
const rotateRoutes = require('./routes-rotate.cjs');
const rotation = require('./rotate.cjs');
const { recover } = require('./recover.cjs');

function start({ env = process.env } = {}) {
  const L = layout(kigHome(env));
  const db = openDb(L.cp.db, { create: false, version: schema.VERSION, init: schema.init });
  schema.ensurePhase4(db);
  if (!snapshots.latest(db)) snapshots.publish(db);
  // §12.3: rotations left unfinished by a previous CP process (a crash). Captured before serving, so a
  // rotation started through this process is never mistaken for a crashed one.
  const crashed = new Set(rotation.pending(db).map((r) => r.rotation_id));
  const route = new Map([
    [ROUTES.cp.health, async () => ({ status: 200, json: { status: 'ok', service: 'cp', instance: env.KIG_INSTANCE_TOKEN || null } })],
    ...policyRoutes.routes(db, env),
    ...revokeRoutes.routes(db, env),
    ...rotateRoutes.routes(db, env),
  ]);
  const server = serve(ports(env).cp, route);
  let closed = false;
  const stop = () => server.close();
  server.once('close', () => { closed = true; db.close(); });
  // Recovery needs the ack route, so it runs once the server listens; a roll-forward whose nodes are
  // unreachable is retried every second until every node has acknowledged.
  server.once('listening', async () => {
    while (!closed) {
      try {
        const r = await recover(db, { env, rotationIds: crashed });
        if (!r.rotations.some((x) => x.status === 'committed')) return;
      } catch { if (closed) return; }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  });
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  return server;
}

if (require.main === module) start();
module.exports = { start };
