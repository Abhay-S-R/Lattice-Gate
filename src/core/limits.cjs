'use strict';
// All size, timing and threshold constants (implementation plan, Global constraints).

module.exports = Object.freeze({
  MAX_STDIN_BYTES: 4 * 1024 * 1024,
  MAX_ID_LEN: 8192, // UTF-16 code units
  MAX_CHALLENGE_LEN: 4096,
  KEM_PK_BYTES: 1184,
  BUSY_TIMEOUT_MS: 5000,
  BUSY_RETRIES: 3,
  JITTER_MIN_MS: 20,
  JITTER_MAX_MS: 80,
  BURST_N: 5,
  BURST_WINDOW_MS: 60000,
  SCHEMA_VERSION_ADAPTER: 1,
  PROTO_KEYS: new Set(['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', 'valueOf']),
});
