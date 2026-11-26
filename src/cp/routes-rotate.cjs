'use strict';
// CP routes for Phase 4 rotation (P4-D1: rotation runs inside the CP process).
const { ROUTES } = require('../core/contracts.cjs');
const rotation = require('./rotate.cjs');
const lostDevice = require('./lostdevice.cjs');

const STATUS = { file_unknown: 404, rotation_in_progress: 409, invalid_grace: 400 };
const LOST_STATUS = { invalid_device_id: 400, device_not_found: 404, device_not_active: 409 };

function routes(db, env = process.env) {
  const rotate = async (body) => {
    if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.file_id !== 'string') {
      return { status: 400, json: { error: 'bad_request' } };
    }
    try {
      return { status: 200, json: await rotation.rotate(db, body.file_id, { env }) };
    } catch (e) {
      if (e instanceof rotation.RotationError && STATUS[e.code]) return { status: STATUS[e.code], json: { error: e.code } };
      return { status: 500, json: { error: 'rotation_failed' } };
    }
  };
  const lost = async (body) => {
    if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.device_id !== 'string') {
      return { status: 400, json: { error: 'bad_request' } };
    }
    try {
      return { status: 200, json: await lostDevice.lost(db, body.device_id, { env }) };
    } catch (e) {
      if (e instanceof lostDevice.LostError && LOST_STATUS[e.code]) return { status: LOST_STATUS[e.code], json: { error: e.code } };
      return { status: 500, json: { error: 'lost_device_failed' } };
    }
  };
  return [[ROUTES.cp.rotate, rotate], [ROUTES.cp.lost, lost]];
}

module.exports = { routes };
