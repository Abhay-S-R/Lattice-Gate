'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { layout, kigHome, ports, url, ROUTES, SNAPSHOT } = require('../core/contracts.cjs');
const { encode } = require('../core/encoding.cjs');
const provider = require('../crypto/provider.cjs');
const policy = require('./policy.cjs');
const { call } = require('../core/http.cjs');
const POLICY_PUSH_ROUTE = 'POST /v1/policy';

function signedAck(id, epoch, privateKey) {
  return { node_id: id, epoch, sig: provider.sign(privateKey, SNAPSHOT.context, encode(SNAPSHOT.ackLabel, [id, epoch])).toString('base64') };
}
function routes(db, { id, privateKey, cpPub, env = process.env }) {
  const push = async (body) => {
    if (!body || typeof body !== 'object' || Array.isArray(body)) return { status: 400, json: { error: 'bad_request' } };
    const result = policy.applySnapshot(db, body, cpPub);
    if (result.reason === 'bad_signature' || result.reason === 'invalid_snapshot') {
      return { status: 400, json: { error: 'bad_policy' } };
    }
    const epoch = result.applied ? body.snapshot.epoch : policy.appliedEpoch(db);
    const ack = signedAck(id, epoch, privateKey);
    if (ack) {
      const cp = url(ports(env).cp);
      call(`${cp}${ROUTES.cp.policyAck.split(' ')[1]}`, 'POST', ack).catch(() => {});
    }
    return { status: 200, json: { applied: result.applied, reason: result.reason, ...(ack ? { ack } : {}) } };
  };
  const head = async () => {
    const state = policy.current(db);
    return { status: 200, json: { epoch: state.applied_epoch, lease_valid: state.lease_valid } };
  };
  return [[POLICY_PUSH_ROUTE, push], [ROUTES.node.policyHead, head]];
}

function ensureNodeKey(home, id) {
  const file = layout(home).node(id).key;
  if (!fs.existsSync(file.private) || !fs.existsSync(file.pub)) {
    const pair = provider.sigGenerate();
    fs.mkdirSync(path.dirname(file.private), { recursive: true, mode: 0o700 });
    const privateTmp = `${file.private}.tmp-${process.pid}`;
    const publicTmp = `${file.pub}.tmp-${process.pid}`;
    fs.writeFileSync(privateTmp, provider.exportPrivate(pair.privateKey), { mode: 0o600 });
    fs.chmodSync(privateTmp, 0o600);
    fs.writeFileSync(publicTmp, provider.exportPublic(pair.publicKey), { mode: 0o644 });
    fs.renameSync(privateTmp, file.private);
    fs.renameSync(publicTmp, file.pub);
  }
  return provider.importPrivate(fs.readFileSync(file.private));
}

async function syncOnce(db, { id, env = process.env, cpPub }) {
  const cp = url(ports(env).cp);
  const nonce = provider.random(SNAPSHOT.headNonceBytes);
  const headResponse = await call(`${cp}${ROUTES.cp.policyHead.split(' ')[1]}?nonce=${nonce.toString('hex')}`, 'GET', null);
  if (headResponse.status !== 200) return { synced: false, reason: 'head_unavailable' };
  const accepted = policy.acceptHead(db, headResponse.json, nonce, cpPub);
  if (!accepted.accepted) return { synced: false, reason: accepted.reason };
  if (accepted.epoch <= policy.appliedEpoch(db)) return { synced: true, reason: 'current' };
  const pullResponse = await call(`${cp}${ROUTES.cp.policyPull.split(' ')[1]}`, 'POST', { epoch: accepted.epoch });
  if (pullResponse.status !== 200) return { synced: false, reason: 'snapshot_unavailable' };
  const result = policy.applySnapshot(db, pullResponse.json, cpPub);
  if (!result.applied) return { synced: false, reason: result.reason };
  const nodePrivate = ensureNodeKey(require('../core/contracts.cjs').kigHome(env), id);
  const ack = signedAck(id, result.epoch || policy.appliedEpoch(db), nodePrivate);
  await call(`${cp}${ROUTES.cp.policyAck.split(' ')[1]}`, 'POST', ack).catch(() => null);
  return { synced: true, reason: 'applied' };
}

function startPullLoop(db, options) {
  let busy = false;
  const run = async () => {
    if (busy) return;
    busy = true;
    try { await syncOnce(db, options); } catch { /* loss of contact leaves the monotonic lease to expire */ }
    finally { busy = false; }
  };
  const timer = setInterval(run, SNAPSHOT.pullIntervalMs);
  timer.unref();
  run();
  return () => clearInterval(timer);
}

module.exports = { routes, syncOnce, startPullLoop, ensureNodeKey, signedAck };
