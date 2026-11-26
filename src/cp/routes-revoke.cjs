'use strict';
const { ROUTES } = require('../core/contracts.cjs');
const revokeDevice = require('./revoke.cjs');

function routes(db, env = process.env) {
  const revoke = async (body) => {
    if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.device_id !== 'string') {
      return { status: 400, json: { error: 'bad_request' } };
    }
    try {
      const result = revokeDevice.revoke(db, body.device_id, { env });
      return { status: 200, json: { revoked: true, device_id: result.device_id, epoch: result.epoch } };
    } catch (e) {
      const code = ['invalid_device_id', 'device_not_found', 'device_already_revoked', 'device_not_active'].includes(e.message)
        ? e.message : 'revocation_failed';
      return { status: code === 'device_not_found' ? 404 : 409, json: { error: code } };
    }
  };
  return [[ROUTES.cp.revoke, revoke]];
}

module.exports = { routes };
