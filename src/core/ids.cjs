'use strict';
// Opaque identifiers (D-04, architecture §4.1).
// Every client-supplied string is stored as JSON.stringify(value): injective for
// every JS string (lone surrogates and NUL included) and always well-formed text.
// Never use a client string as a file name, SQL text or plain-object key.
const { MAX_ID_LEN, PROTO_KEYS } = require('./limits.cjs');

/** @param {string} s @returns {string} */
const enc = (s) => {
  if (typeof s !== 'string') throw new TypeError('ids.enc expects a string');
  return JSON.stringify(s);
};

/** @param {string} t @returns {string} */
const dec = (t) => {
  const s = JSON.parse(t);
  if (typeof s !== 'string') throw new TypeError('ids.dec: not an encoded string');
  return s;
};

/** @param {unknown} x @returns {x is string} */
const isId = (x) => typeof x === 'string' && x.length <= MAX_ID_LEN;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * True for identifiers worth an A-HOSTILE-ID alert. They are still accepted
 * and handled exactly like any other identifier; this is only a signal.
 * @param {string} s
 */
const isHostile = (s) =>
  CONTROL.test(s) || !s.isWellFormed() || s.includes('../') || s.includes('..\\') || PROTO_KEYS.has(s);

module.exports = { enc, dec, isId, isHostile };
