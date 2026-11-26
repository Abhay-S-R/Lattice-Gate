'use strict';
const { ROUTES } = require('../core/contracts.cjs');
const files = require('./files.cjs');
function routes(db) { return [[ROUTES.node.fileRead, async body => ({ status: 200, json: files.read(db, body) })]]; }
module.exports = { routes };
