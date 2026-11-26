'use strict';
// @ts-check
// Per-op request validation for the Round 1 adapter (architecture §5.3, Task 1.6).
//
// Identifiers are opaque (D-04): any JS string up to MAX_ID_LEN code units is
// accepted, including '', NUL, lone surrogates and '__proto__'. Hostile-looking
// IDs are still valid; hostileIds() only reports them for the A-HOSTILE-ID alert.
//
// Client maps become Map/Set built from Object.entries (own keys only), never
// plain objects, so prototype keys are ordinary keys. key_material is never
// read into req (P0-04). Failure reasons are fixed codes: they never contain
// client data, so they are safe to put in audit detail.

const { MAX_ID_LEN, MAX_CHALLENGE_LEN, KEM_PK_BYTES } = require('../core/limits.cjs');
const ids = require('../core/ids.cjs');

const OPS = new Set(['setup', 'read', 'revoke', 'audit', 'protected_read']);

/** Exact Base64 length of KEM_PK_BYTES bytes (1184 → 1580). */
const KEM_PK_B64_LEN = Math.ceil(KEM_PK_BYTES / 3) * 4;
const B64_CHARS = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Strict standard Base64 (§5.3): length % 4 === 0, standard alphabet with at
 * most two trailing '=', and canonical (re-encoding the decoded bytes gives
 * back the same string, which rejects non-zero padding bits).
 * @param {unknown} s
 */
function isStrictBase64(s) {
  if (typeof s !== 'string') return false;
  if (s.length % 4 !== 0) return false;
  if (!B64_CHARS.test(s)) return false;
  return Buffer.from(s, 'base64').toString('base64') === s;
}

/** @param {unknown} x @returns {x is Record<string, unknown>} */
const isPlainObject = (x) => {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return false;
  const proto = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
};

/** Own-property read, so nothing is ever picked up from a prototype. */
const own = (/** @type {object} */ obj, /** @type {string} */ k) =>
  Object.prototype.hasOwnProperty.call(obj, k) ? /** @type {any} */ (obj)[k] : undefined;

const fail = (/** @type {string} */ reason) => ({ ok: /** @type {const} */ (false), reason });
const pass = (/** @type {object} */ req) => ({ ok: /** @type {const} */ (true), req });

/** @param {Record<string, unknown>} obj */
function setup(obj) {
  const rawOwners = own(obj, 'owners');
  const rawContents = own(obj, 'contents');
  const rawDisabled = own(obj, 'disabled');
  if (!isPlainObject(rawOwners)) return fail('invalid_owners');
  if (!isPlainObject(rawContents)) return fail('invalid_contents');
  if (!Array.isArray(rawDisabled)) return fail('invalid_disabled');

  /** @type {Map<string, string>} */
  const owners = new Map();
  for (const [asset, owner] of Object.entries(rawOwners)) {
    if (!ids.isId(asset) || !ids.isId(owner)) return fail('invalid_owners');
    owners.set(asset, /** @type {string} */ (owner));
  }
  /** @type {Map<string, string>} */
  const contents = new Map();
  for (const [asset, body] of Object.entries(rawContents)) {
    if (!ids.isId(asset) || typeof body !== 'string') return fail('invalid_contents');
    contents.set(asset, body);
  }
  /** @type {Set<string>} */
  const disabled = new Set();
  for (const actor of rawDisabled) {
    if (!ids.isId(actor)) return fail('invalid_disabled');
    disabled.add(actor);
  }
  // key_material is deliberately not read.
  return pass({ owners, contents, disabled });
}

/** @param {Record<string, unknown>} obj */
function read(obj) {
  const actor = own(obj, 'actor'), asset = own(obj, 'asset'), request_id = own(obj, 'request_id');
  if (!ids.isId(actor)) return fail('invalid_actor');
  if (!ids.isId(asset)) return fail('invalid_asset');
  if (!ids.isId(request_id)) return fail('invalid_request_id');
  return pass({ actor, asset, request_id });
}

/** @param {Record<string, unknown>} obj */
function revoke(obj) {
  const actor = own(obj, 'actor');
  if (!ids.isId(actor)) return fail('invalid_actor');
  return pass({ actor });
}

/** @param {Record<string, unknown>} obj */
function audit(obj) {
  const request_id = own(obj, 'request_id');
  if (!ids.isId(request_id)) return fail('invalid_request_id');
  return pass({ request_id });
}

/** @param {Record<string, unknown>} obj */
function protectedRead(obj) {
  const actor = own(obj, 'actor'), asset = own(obj, 'asset');
  const challenge = own(obj, 'challenge'), publicKey = own(obj, 'public_key');
  let request_id = own(obj, 'request_id');
  if (!ids.isId(actor)) return fail('invalid_actor');
  if (!ids.isId(asset)) return fail('invalid_asset');
  if (typeof challenge !== 'string' || challenge.length > MAX_CHALLENGE_LEN) return fail('invalid_challenge');
  // Length first: cheap, and it bounds the decode below.
  if (typeof publicKey !== 'string' || publicKey.length !== KEM_PK_B64_LEN || !isStrictBase64(publicKey)) {
    return fail('invalid_public_key');
  }
  const key = Buffer.from(publicKey, 'base64');
  if (key.length !== KEM_PK_BYTES) return fail('invalid_public_key');
  // Optional (the contract does not send one); absent or null both mean "none".
  if (request_id === undefined || request_id === null) request_id = null;
  else if (!ids.isId(request_id)) return fail('invalid_request_id');
  return pass({ actor, asset, challenge, publicKey: key, request_id });
}

/** @type {Map<string, (obj: Record<string, unknown>) => {ok: boolean, req?: any, reason?: string}>} */
const VALIDATORS = new Map([
  ['setup', setup],
  ['read', read],
  ['revoke', revoke],
  ['audit', audit],
  ['protected_read', protectedRead],
]);

/**
 * @param {string} op
 * @param {unknown} obj parsed request object
 * @returns {{ ok: true, req: any } | { ok: false, reason: string }}
 */
function validate(op, obj) {
  const fn = typeof op === 'string' ? VALIDATORS.get(op) : undefined;
  if (!fn) return fail('unsupported_operation');
  if (!isPlainObject(obj)) return fail('not_an_object');
  return /** @type {any} */ (fn(obj));
}

/**
 * Identifiers in a validated req for which ids.isHostile is true, each once,
 * in first-seen order. Bodies and challenges are not identifiers.
 * @param {any} req
 * @returns {string[]}
 */
function hostileIds(req) {
  /** @type {string[]} */
  const all = [];
  if (req.owners instanceof Map) {
    for (const [asset, owner] of req.owners) all.push(asset, owner);
    for (const asset of req.contents.keys()) all.push(asset);
    for (const actor of req.disabled) all.push(actor);
  } else {
    for (const k of ['actor', 'asset', 'request_id']) {
      if (typeof req[k] === 'string') all.push(req[k]);
    }
  }
  return [...new Set(all.filter((s) => ids.isHostile(s)))];
}

module.exports = { OPS, isStrictBase64, validate, hostileIds };
