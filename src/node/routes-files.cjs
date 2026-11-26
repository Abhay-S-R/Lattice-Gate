'use strict';
const { ROUTES } = require('../core/contracts.cjs');
const files = require('./files.cjs');
const { validRequest } = require('./routes-auth.cjs');
function routes(db) { return [[ROUTES.node.fileRead, async body => {
  if (!validRequest(body) || body.op !== 'file.read') return { status: 400, json: { error: 'bad_request' } };
  return { status: 200, json: files.read(db, body) };
}]]; }
module.exports = { routes };
