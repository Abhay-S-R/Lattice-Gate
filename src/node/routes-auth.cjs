'use strict';
const auth = require('./auth.cjs');
const { ROUTES } = require('../core/contracts.cjs');
function routeChallenge(db) { return async () => ({ status: 200, json: auth.challenge(db) }); }
function routeAuthenticate(db) { return async (body) => { const result = auth.authenticate(db, body); return { status: 200, json: { decision: result.ok ? 'allow' : 'deny', rule: result.rule, ...(result.ok ? { device_id: result.device.device_id } : {}) } }; }; }
function routes(db) { return [[ROUTES.node.challenge, routeChallenge(db)], [ROUTES.node.authenticate, routeAuthenticate(db)]]; }
module.exports = { routes, routeChallenge, routeAuthenticate };
