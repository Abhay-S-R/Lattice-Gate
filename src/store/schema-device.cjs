'use strict';
const { initBase } = require('./schema-base.cjs');
const { SCHEMA_VERSION_ADAPTER } = require('../core/limits.cjs');
const DDL = `CREATE TABLE keys(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE pinned(name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;`;
function init(db) { initBase(db); db.exec(DDL); }
module.exports = { VERSION: SCHEMA_VERSION_ADAPTER, init, DDL };
