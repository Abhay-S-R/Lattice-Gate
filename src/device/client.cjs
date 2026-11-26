'use strict';
const path = require('node:path');
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { REQUEST } = require('../core/contracts.cjs');
const keystore = require('./keystore.cjs');
function transcript(fields) { return encode(REQUEST.label, REQUEST.fields.map(k => fields[k])); }
async function request(nodeUrl, deviceDir, op, fields) {
  const { call } = require('../core/http.cjs');
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new TypeError('invalid request fields');
  const { home: homeOverride, ...requestFields } = fields;
  const home = homeOverride || (deviceDir ? path.resolve(deviceDir, '..', '..') : require('../core/contracts.cjs').kigHome());
  const deviceId = requestFields.device_id;
  const keys = keystore.load(home, deviceId);
  const challenge = await call(`${nodeUrl}/v1/challenge`, 'GET', null, { timeoutMs: 5000 });
  if (challenge.status !== 200 || !challenge.json || typeof challenge.json.nonce !== 'string') throw new Error('challenge_unavailable');
  const ch = challenge.json || challenge;
  const nonce = Buffer.from(ch.nonce, 'base64');
  if (nonce.length !== REQUEST.nonceBytes || nonce.toString('base64') !== ch.nonce) throw new Error('challenge_invalid');
  const signedFields = Object.fromEntries(REQUEST.fields.map((key) => [key,
    key === 'version' ? REQUEST.version : key === 'op' ? op : key === 'nonce' ? nonce : requestFields[key]]));
  const body = { ...signedFields, nonce: nonce.toString('base64') };
  body.sig = provider.sign(keys.signPrivate, REQUEST.context, transcript(signedFields)).toString('base64');
  body.sign_pk = provider.exportPublic(keys.signPublic).toString('base64');
  const route = op === 'file.read' ? '/v1/files/read' : op === 'file.transfer' ? '/v1/transfer/start' : '/v1/auth';
  const response = await call(`${nodeUrl}${route}`, 'POST', body, { timeoutMs: 5000 });
  if (response.status !== 200 || !response.json || typeof response.json !== 'object' || Array.isArray(response.json)) {
    throw new Error('node_request_failed');
  }
  return response.json;
}
/** Fetch one chunk of an open transfer (Phase 4). The transfer ID is the bearer credential. */
async function transferChunk(nodeUrl, transferId, index) {
  const { call } = require('../core/http.cjs');
  const response = await call(`${nodeUrl}/v1/transfer/chunk`, 'POST', { transfer_id: transferId, index }, { timeoutMs: 5000 });
  if (response.status !== 200 || !response.json || typeof response.json !== 'object' || Array.isArray(response.json)) throw new Error('node_request_failed');
  return response.json;
}
module.exports = { request, transcript, transferChunk };
