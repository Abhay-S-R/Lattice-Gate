'use strict';
const fs = require('node:fs');
const { layout, kigHome, SNAPSHOT, ROUTES } = require('../core/contracts.cjs');
const { getMeta } = require('../store/schema-base.cjs');
const { encode } = require('../core/encoding.cjs');
const provider = require('../crypto/provider.cjs');
const snapshots = require('./snapshot.cjs');

function routes(db, env = process.env) {
  const L = layout(kigHome(env));
  const privateKey = provider.importPrivate(fs.readFileSync(L.cp.keys.policy.key));
  const head = async (_body, req) => {
    const raw = new URL(req.url || '/', 'http://127.0.0.1').searchParams.get('nonce') || '';
    if (!/^[0-9a-f]{32}$/.test(raw)) return { status: 400, json: { error: 'bad_request' } };
    const nonce = Buffer.from(raw, 'hex');
    const epoch = Number(getMeta(db, 'epoch'));
    const sig = provider.sign(privateKey, SNAPSHOT.context, encode(SNAPSHOT.headLabel, [epoch, nonce]));
    return { status: 200, json: { epoch, nonce: raw, sig: sig.toString('base64') } };
  };
  const pull = async () => {
    const signed = snapshots.latest(db);
    if (!signed) return { status: 503, json: { error: 'policy_unavailable' } };
    return { status: 200, json: { snapshot: signed.snapshot, sig: signed.sig.toString('base64') } };
  };
  const ack = async (body) => {
    if (!snapshots.recordAck(db, body, env)) return { status: 400, json: { error: 'bad_ack' } };
    return { status: 200, json: { accepted: true } };
  };
  return [[ROUTES.cp.policyHead, head], [ROUTES.cp.policyPull, pull], [ROUTES.cp.policyAck, ack]];
}

module.exports = { routes };
