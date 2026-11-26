'use strict';
// @ts-check
// Adapter core: decode → parse → route → validate → op → error policy
// (architecture §5.2 steps 3–9, §5.3, §5.6 / D-13, Task 1.14).
//
// Error policy, per op:
//   invalid input   setup/revoke → {"error":"invalid_request"}; read/protected_read → deny;
//                   audit → {"request_id": <given string or null>, "decision":"deny"}. All exit 0.
//   any failure     read/protected_read/audit fail closed with their deny shape, exit 0;
//   inside the op   setup/revoke → no response, exit 1 (an unpersisted change is never acknowledged).
// Nothing here prints; track4_service.cjs owns stdout/stderr.

const os = require('node:os');
const { MAX_STDIN_BYTES } = require('../core/limits.cjs');
const ids = require('../core/ids.cjs');
const { OPS, validate } = require('./validate.cjs');
const ops = require('./ops.cjs');

/** op name → ops.cjs export */
const OP_FN = new Map([
  ['setup', 'setup'],
  ['read', 'read'],
  ['revoke', 'revoke'],
  ['audit', 'audit'],
  ['protected_read', 'protectedRead'],
]);

/** @typedef {{ response: object|null, exitCode: 0|1 }} Outcome */

/** @returns {Outcome} */
const done = (/** @type {object|null} */ response, /** @type {0|1} */ exitCode = 0) => ({ response, exitCode });
const invalidRequest = () => done({ error: 'invalid_request' });

/** @param {unknown} x @returns {x is Record<string, unknown>} */
const isPlainObject = (x) => {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return false;
  const proto = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
};
const own = (/** @type {object} */ o, /** @type {string} */ k) =>
  Object.prototype.hasOwnProperty.call(o, k) ? /** @type {any} */ (o)[k] : undefined;

/** Response for a request that failed validation (§5.3). */
function invalidResponse(/** @type {string} */ op, /** @type {Record<string, unknown>} */ obj) {
  switch (op) {
    case 'read':
    case 'protected_read':
      return done({ decision: 'deny' });
    case 'audit': {
      const rid = own(obj, 'request_id');
      return done({ request_id: typeof rid === 'string' ? rid : null, decision: 'deny' });
    }
    default: // setup, revoke
      return invalidRequest();
  }
}

/** Response when a valid request's op threw (§5.6). */
function failureResponse(/** @type {string} */ op, /** @type {any} */ req) {
  switch (op) {
    case 'read':
    case 'protected_read':
      return done({ decision: 'deny' });
    case 'audit':
      return done({ request_id: req.request_id, decision: 'deny' });
    default: // setup, revoke: exit 1, no stdout
      return done(null, 1);
  }
}

/** The identifier fields of an invalid request that are themselves valid IDs. */
function validIdFields(/** @type {Record<string, unknown>} */ obj) {
  /** @type {Record<string, string>} */
  const f = {};
  for (const k of ['request_id', 'actor', 'asset']) {
    const v = own(obj, k);
    if (ids.isId(v)) f[k] = v;
  }
  return f;
}

/**
 * @param {Uint8Array} buf raw stdin bytes
 * @param {Record<string, string|undefined>} [env]
 * @returns {Promise<Outcome>}
 */
async function handleRaw(buf, env = process.env) {
  const stateDir = (typeof env.TRACK4_STATE_DIR === 'string' && env.TRACK4_STATE_DIR) || os.tmpdir();
  const ctx = { stateDir };

  if (!(buf instanceof Uint8Array) || buf.length > MAX_STDIN_BYTES) return invalidRequest();
  let obj;
  try {
    obj = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buf));
  } catch {
    return invalidRequest();
  }
  if (!isPlainObject(obj)) return invalidRequest();

  const op = own(obj, 'op');
  if (typeof op !== 'string') return invalidRequest();
  if (!OPS.has(op)) return done({ error: 'unsupported_operation' });

  const v = validate(op, obj);
  if (!v.ok) {
    try { await ops.recordInvalid(ctx, op, validIdFields(obj)); } catch { /* best effort */ }
    return invalidResponse(op, obj);
  }

  try {
    const fn = /** @type {any} */ (ops)[/** @type {string} */ (OP_FN.get(op))];
    return done(await fn(ctx, v.req));
  } catch {
    return failureResponse(op, v.req);
  }
}

module.exports = { handleRaw };
