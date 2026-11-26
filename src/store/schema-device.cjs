'use strict';
const { initBase } = require('./schema-base.cjs');
const { STORE_VERSIONS } = require('../core/contracts.cjs');
const DDL = `CREATE TABLE keys(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE pinned(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;`;
function init(db) { initBase(db); db.exec(DDL); }
module.exports = { VERSION: STORE_VERSIONS.device, init, DDL };
