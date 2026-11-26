'use strict';
// Byte strings signed for Phase 4 staging (docs/plans/phase-4.md P4-D2). Shared by the CP (signs
// stage/drop, verifies node acks) and nodes (verify stage/drop, sign acks). Length-prefixed (D-08).
const { encode } = require('./encoding.cjs');
const provider = require('../crypto/provider.cjs');
const { ROTATION } = require('./contracts.cjs');

/** Digest of exactly what a stage message carries: [{device_id, envelope}] in device-id order. */
const digest = (fileId, version, nonce, ciphertext, envelopes) =>
  provider.sha256(encode(ROTATION.stageContentLabel, [fileId, version, nonce, ciphertext, JSON.stringify(envelopes)]));
/** Signed by the CP policy key. op is 'stage' or 'drop' (drop signs an empty digest). */
const signedBytes = (op, rotationId, fileId, version, contentDigest) =>
  encode(ROTATION.stageLabel, [op, rotationId, fileId, version, contentDigest]);
/** Signed by the node key in its answer. */
const ackBytes = (nodeId, op, rotationId, fileId, version, contentDigest) =>
  encode(ROTATION.stageAckLabel, [nodeId, op, rotationId, fileId, version, contentDigest]);
/** Plain code-unit order, identical on every platform (not locale-dependent). */
const byDevice = (a, b) => (a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0);

module.exports = { digest, signedBytes, ackBytes, byDevice };
