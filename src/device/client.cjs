'use strict';
const path = require('node:path');
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { REQUEST } = require('../core/contracts.cjs');
const keystore = require('./keystore.cjs');
function transcript(fields) { return encode(REQUEST.label, REQUEST.fields.map(k => fields[k])); }
async function request(nodeUrl, deviceDir, op, fields) {
  const { call } = require('../core/http.cjs');
  const { home: homeOverride, ...requestFields } = fields;
  const home = homeOverride || (deviceDir ? path.resolve(deviceDir, '..', '..') : require('../core/contracts.cjs').kigHome());
  const deviceId = requestFields.device_id;
  const keys = keystore.load(home, deviceId);
  const challenge = await call(`${nodeUrl}/v1/challenge`, 'GET', null, { timeoutMs: 5000 });
  const ch = challenge.json || challenge;
  const nonce = Buffer.from(ch.nonce, 'base64');
  const body = { version: REQUEST.version, op, ...requestFields, nonce: nonce.toString('base64') };
  body.sig = provider.sign(keys.signPrivate, REQUEST.context, transcript({ ...body, nonce })).toString('base64');
  body.sign_pk = provider.exportPublic(keys.signPublic).toString('base64');
  const route = op === 'file.read' ? '/v1/files/read' : '/v1/auth';
  return call(`${nodeUrl}${route}`, 'POST', body, { timeoutMs: 5000 });
}
module.exports = { request, transcript };
