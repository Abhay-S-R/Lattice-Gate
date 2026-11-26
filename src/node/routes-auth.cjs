'use strict';
const auth = require('./auth.cjs');
const { ROUTES, REQUEST } = require('../core/contracts.cjs');
function routeChallenge(db) { return async () => ({ status: 200, json: auth.challenge(db) }); }
function isBase64(value) {
  return typeof value === 'string' && value.length > 0 &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) &&
    Buffer.from(value, 'base64').toString('base64') === value;
}
function validRequest(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  if (!Number.isSafeInteger(body.version) || !Number.isSafeInteger(body.key_version) || body.key_version < 0) return false;
  for (const key of ['op', 'account', 'device_id', 'resource']) if (typeof body[key] !== 'string') return false;
  if (body.request_id !== null && typeof body.request_id !== 'string') return false;
  if (!isBase64(body.nonce) || Buffer.from(body.nonce, 'base64').length !== REQUEST.nonceBytes) return false;
  return isBase64(body.sign_pk) && isBase64(body.sig);
}
function routeAuthenticate(db) { return async (body) => {
  if (!validRequest(body)) return { status: 400, json: { error: 'bad_request' } };
  const result = auth.authenticate(db, body);
  return { status: 200, json: { decision: result.ok ? 'allow' : 'deny', rule: result.rule, ...(result.ok ? { device_id: result.device.device_id } : {}) } };
}; }
function routes(db) { return [[ROUTES.node.challenge, routeChallenge(db)], [ROUTES.node.authenticate, routeAuthenticate(db)]]; }
module.exports = { routes, routeChallenge, routeAuthenticate, validRequest };
