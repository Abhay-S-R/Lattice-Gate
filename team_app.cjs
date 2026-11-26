'use strict';
// Team application boundary for the Round 1 transport (track4_service.cjs).
// All behaviour lives in src/adapter/index.cjs; nothing here writes to stdout or stderr.
exports.handleRaw = (buf) => require('./src/adapter/index.cjs').handleRaw(buf, process.env);
