'use strict';
// @ts-check
// Owner-read access policy (architecture §5.5 `read`, Task 1.7).
//
// Check order is fixed: revoked → unknown asset (missing row, or owner/body
// NULL) → not owner → allow. Revocation comes first so a revoked owner never
// reaches the body. IDs are stored D-04 encoded (ids.enc), and enc is
// injective, so comparing encodings is exact string equality, including for
// lone surrogates and NUL that SQLite TEXT would otherwise mangle.
//
// Read-only: the caller runs this inside its transaction and records the
// decision itself. A deny result has no `body` key at all.

const ids = require('./ids.cjs');

/**
 * @typedef {'actor_revoked'|'unknown_asset'|'not_owner'|'owner_allowed'} Rule
 * @typedef {{ decision: 'deny', rule: Exclude<Rule, 'owner_allowed'> }
 *         | { decision: 'allow', rule: 'owner_allowed', body: string }} Authorization
 */

/**
 * @param {import('node:sqlite').DatabaseSync} db adapter DB (schema §5.4)
 * @param {string} actor decoded actor ID
 * @param {string} asset decoded asset ID
 * @returns {Authorization}
 */
function authorizeOwnerRead(db, actor, asset) {
  const encActor = ids.enc(actor);

  const revoked = db.prepare('SELECT 1 FROM revoked_actors WHERE actor = ?').get(encActor);
  if (revoked !== undefined) return { decision: 'deny', rule: 'actor_revoked' };

  const row = /** @type {{ owner: string|null, body: string|null } | undefined} */ (
    db.prepare('SELECT owner, body FROM assets WHERE asset = ?').get(ids.enc(asset)));
  if (row === undefined || row.owner === null || row.body === null) {
    return { decision: 'deny', rule: 'unknown_asset' };
  }

  if (row.owner !== encActor) return { decision: 'deny', rule: 'not_owner' };

  return { decision: 'allow', rule: 'owner_allowed', body: ids.dec(row.body) };
}

module.exports = { authorizeOwnerRead };
