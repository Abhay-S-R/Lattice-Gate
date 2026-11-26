'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { encode } = require('../../src/core/encoding.cjs');

/** Test-only decoder: returns { label, fields: Array<Buffer|null> }. */
function decode(buf) {
  let off = 0;
  const take = () => {
    const len = buf.readUInt32BE(off); off += 4;
    if (len === 0xffffffff) return null;
    const out = buf.subarray(off, off + len); off += len;
    assert.equal(out.length, len, 'truncated field');
    return out;
  };
  const label = take().toString('utf8');
  const fields = [];
  while (off < buf.length) fields.push(take());
  assert.equal(off, buf.length);
  return { label, fields };
}

test('layout', () => {
  const b = encode('L', [Buffer.from([1, 2]), 'a', 7, null]);
  const d = decode(b);
  assert.equal(d.label, 'L');
  assert.deepEqual(d.fields[0], Buffer.from([1, 2]));
  assert.equal(d.fields[1].toString('utf8'), '"a"');
  assert.equal(d.fields[2].readBigInt64BE(0), 7n);
  assert.equal(d.fields[3], null);
});

test('null differs from empty string', () => {
  assert.notDeepEqual(encode('L', [null]), encode('L', ['']));
});

test('boundary safety', () => {
  const a = encode('L', ['a', 'b']), b = encode('L', ['ab']), c = encode('L', ['a\u0000b']);
  assert.notDeepEqual(a, b);
  assert.notDeepEqual(b, c);
  assert.notDeepEqual(a, c);
});

test('label is domain-separated', () => {
  assert.notDeepEqual(encode('L', ['x']), encode('M', ['x']));
  assert.notDeepEqual(encode('La', []), encode('L', ['a']));
});

test('injection', () => {
  const s = 'x\n{"actor":"admin"}';
  const d = decode(encode('L', [s]));
  assert.equal(d.fields.length, 1);
  assert.equal(JSON.parse(d.fields[0].toString('utf8')), s);
});

test('lone surrogate is distinct from U+FFFD', () => {
  assert.notDeepEqual(encode('L', ['\ud800']), encode('L', ['�']));
});

test('integers: number and bigint agree, negatives ok', () => {
  assert.deepEqual(encode('L', [5]), encode('L', [5n]));
  assert.equal(decode(encode('L', [-1])).fields[0].readBigInt64BE(0), -1n);
  assert.equal(decode(encode('L', [Number.MAX_SAFE_INTEGER])).fields[0].readBigInt64BE(0), BigInt(Number.MAX_SAFE_INTEGER));
});

test('rejects 1.5', () => {
  assert.throws(() => encode('L', [1.5]), TypeError);
});

test('rejects unsafe and out-of-range integers and other types', () => {
  assert.throws(() => encode('L', [2 ** 53]), TypeError);
  assert.throws(() => encode('L', [NaN]), TypeError);
  assert.throws(() => encode('L', [2n ** 63n]), TypeError);
  assert.throws(() => encode('L', [undefined]), TypeError);
  assert.throws(() => encode('L', [{}]), TypeError);
  assert.throws(() => encode('L', [true]), TypeError);
  assert.throws(() => encode(5, []), TypeError);
});

test('deterministic', () => {
  const f = [Buffer.from('z'), 'é🙂', 42, null, -3n];
  assert.deepEqual(encode('kig/v1/event', f), encode('kig/v1/event', f));
});
