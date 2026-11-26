'use strict';
// @ts-check
// Terminal-safe rendering of untrusted strings (identifiers come from clients).
// JSON.stringify already escapes C0 controls and lone surrogates; we additionally
// escape DEL, C1 controls (e.g. U+009B CSI), line/paragraph separators and bidi
// controls, which some terminals interpret. Output is still valid JSON that decodes
// to the original value.
const DANGEROUS = /[\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const esc = (/** @type {string} */ c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;

/** Quoted, escaped form of any value, safe to print to a terminal. */
const safe = (/** @type {unknown} */ v) => JSON.stringify(v === undefined ? null : v).replace(DANGEROUS, esc);

/** JSON for machine output, with the same extra escapes. */
const safeJson = (/** @type {unknown} */ v, /** @type {number} */ indent = 0) =>
  JSON.stringify(v, null, indent).replace(DANGEROUS, esc);

module.exports = { safe, safeJson };
