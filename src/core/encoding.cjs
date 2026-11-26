'use strict';
// Length-prefixed encoding (D-08, architecture §4.2). Used for every byte string
// that is hashed, signed or used as AEAD associated data.
//
//   u32be(len(label)) ‖ label
//   per field:  Buffer        → u32be(len) ‖ bytes
//               string        → u32be(len) ‖ UTF-8(ids.enc(s))
//               number|bigint → u32be(8)   ‖ i64be
//               null          → u32be(0xFFFFFFFF)
const { enc } = require('./ids.cjs');

const NULL_LEN = 0xffffffff;
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

function u32(n) {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n, 0);
  return b;
}

function lenPrefixed(bytes) {
  if (bytes.length >= NULL_LEN) throw new RangeError('field too long');
  return [u32(bytes.length), bytes];
}

function i64(v) {
  let n;
  if (typeof v === 'bigint') n = v;
  else if (Number.isSafeInteger(v)) n = BigInt(v);
  else throw new TypeError('integer field must be a safe integer or bigint');
  if (n < I64_MIN || n > I64_MAX) throw new TypeError('integer field out of i64 range');
  const b = Buffer.allocUnsafe(8);
  b.writeBigInt64BE(n, 0);
  return b;
}

/**
 * @param {string} label constant domain-separation label (not client data)
 * @param {Array<Buffer|string|number|bigint|null>} fields
 * @returns {Buffer}
 */
function encode(label, fields) {
  if (typeof label !== 'string') throw new TypeError('label must be a string');
  if (!Array.isArray(fields)) throw new TypeError('fields must be an array');
  const parts = lenPrefixed(Buffer.from(label, 'utf8'));
  for (const f of fields) {
    if (f === null) parts.push(u32(NULL_LEN));
    else if (Buffer.isBuffer(f)) parts.push(...lenPrefixed(f));
    else if (typeof f === 'string') parts.push(...lenPrefixed(Buffer.from(enc(f), 'utf8')));
    else if (typeof f === 'number' || typeof f === 'bigint') parts.push(u32(8), i64(f));
    else throw new TypeError(`unsupported field type: ${typeof f}`);
  }
  return Buffer.concat(parts);
}

module.exports = { encode };
