'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const ops = require('../../src/adapter/ops.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const p = require('../../src/crypto/provider.cjs');
const { freshCtx, setupReq, withState, stateContains } = require('../helpers/state.cjs');

const SCEN = { owners: { brief: 'maya', other: 'peer' }, contents: { brief: 'demo note', other: 'peer note' }, disabled: [] };

async function keypair() {
  const { publicKey, privateKey } = p.kemGenerate();
  return { raw: await p.kemExportRawPublic(publicKey), privateKey };
}
const pr = (actor, asset, challenge, publicKey, request_id = null) => ({ actor, asset, challenge, publicKey, request_id });

/** What the worker does: decapsulate, recompute the HMAC, compare. */
function verify(res, privateKey, challenge, body) {
  const ct = Buffer.from(res.ciphertext, 'base64');
  assert.equal(ct.length, 1088);
  assert.equal(ct.toString('base64'), res.ciphertext, 'standard Base64');
  const ss = p.kemDecapsulate(privateKey, ct);
  assert.match(res.proof, /^[0-9a-f]{64}$/);
  assert.equal(res.proof, p.hmacHex(ss, Buffer.from(challenge + body, 'utf8')));
  return ss;
}

const accessEvents = (db) => db.prepare(`SELECT op, request_id, actor, decision, rule FROM audit_events
  WHERE kind = 'access' ORDER BY seq`).all()
  .map((r) => ({ ...r, request_id: r.request_id === null ? null : ids.dec(r.request_id), actor: ids.dec(r.actor) }));

test('owner gets verifiable proof', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  const res = await ops.protectedRead(ctx, pr('maya', 'brief', 'chal-1', k.raw));
  assert.deepEqual(Object.keys(res).sort(), ['ciphertext', 'proof']);
  verify(res, k.privateKey, 'chal-1', 'demo note');
  withState(ctx, (db) => {
    assert.deepEqual(accessEvents(db), [
      { op: 'protected_read', request_id: null, actor: 'maya', decision: 'allow', rule: 'owner_allowed' },
    ]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('two calls give different ciphertexts, both verify', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  const a = await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw));
  const b = await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw));
  assert.notEqual(a.ciphertext, b.ciphertext);
  verify(a, k.privateKey, 'c', 'demo note');
  verify(b, k.privateKey, 'c', 'demo note');
});

test('revoked actor gets deny with one key', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.revoke(ctx, { actor: 'maya' });
  const k = await keypair();
  const res = await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw, 'p1'));
  assert.deepEqual(res, { decision: 'deny' });
  withState(ctx, (db) => assert.deepEqual(accessEvents(db).at(-1),
    { op: 'protected_read', request_id: 'p1', actor: 'maya', decision: 'deny', rule: 'actor_revoked' }));
});

test('not owner and unknown asset deny', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  assert.deepEqual(await ops.protectedRead(ctx, pr('maya', 'other', 'c', k.raw)), { decision: 'deny' });
  assert.deepEqual(await ops.protectedRead(ctx, pr('maya', 'nope', 'c', k.raw)), { decision: 'deny' });
});

test('invalid 0xFF key → deny + audit rule invalid_public_key', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const res = await ops.protectedRead(ctx, pr('maya', 'brief', 'c', Buffer.alloc(1184, 0xff), 'p9'));
  assert.deepEqual(res, { decision: 'deny' });
  withState(ctx, (db) => {
    assert.deepEqual(accessEvents(db), [
      { op: 'protected_read', request_id: 'p9', actor: 'maya', decision: 'deny', rule: 'invalid_public_key' },
    ]);
    assert.equal(audit.verifyChain(db).ok, true);
  });
});

test('unauthorized request with a bad key is denied by policy first', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  await ops.protectedRead(ctx, pr('maya', 'other', 'c', Buffer.alloc(1184, 0xff)));
  withState(ctx, (db) => assert.equal(accessEvents(db).at(-1).rule, 'not_owner'));
});

test('unicode challenge and body', async () => {
  const ctx = freshCtx();
  const body = 'ünïcode ✓ <i> 🙂';
  await ops.setup(ctx, setupReq({ owners: { u: 'maya' }, contents: { u: body } }));
  const k = await keypair();
  const challenge = 'défi ✓ 🙂';
  verify(await ops.protectedRead(ctx, pr('maya', 'u', challenge, k.raw)), k.privateKey, challenge, body);
});

test('lone surrogate body is hashed as Node UTF-8 (U+FFFD)', async () => {
  const ctx = freshCtx();
  const body = 'a\ud800b';
  await ops.setup(ctx, setupReq({ owners: { s: 'maya' }, contents: { s: body } }));
  const k = await keypair();
  const res = await ops.protectedRead(ctx, pr('maya', 's', 'c', k.raw));
  const ss = p.kemDecapsulate(k.privateKey, Buffer.from(res.ciphertext, 'base64'));
  assert.equal(res.proof, p.hmacHex(ss, Buffer.from('ca�b', 'utf8')));
});

test('empty challenge and empty body', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq({ owners: { e: 'maya' }, contents: { e: '' } }));
  const k = await keypair();
  verify(await ops.protectedRead(ctx, pr('maya', 'e', '', k.raw)), k.privateKey, '', '');
});

test('shared secret not in response or db', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  const res = await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw, 'p1'));
  const ss = verify(res, k.privateKey, 'c', 'demo note');
  const json = JSON.stringify(res);
  for (const enc of ['hex', 'base64']) assert.ok(!json.includes(ss.toString(enc)));
  assert.equal(stateContains(ctx.stateDir, ss), false);
  assert.equal(stateContains(ctx.stateDir, ss.toString('hex')), false);
  assert.equal(stateContains(ctx.stateDir, ss.toString('base64')), false);
});

test('optional request_id is recorded so audit can find it', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw, 'pr-7'));
  assert.deepEqual(await ops.audit(ctx, { request_id: 'pr-7' }), { request_id: 'pr-7', decision: 'allow' });
});

test('no store → deny, nothing created', async () => {
  const fs = require('node:fs');
  const ctx = freshCtx();
  const k = await keypair();
  assert.deepEqual(await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw)), { decision: 'deny' });
  assert.deepEqual(fs.readdirSync(ctx.stateDir), []);
});

test('revocation between authorize and record → deny is recorded, no ciphertext', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  const real = p.kemEncapsulateRaw;
  p.kemEncapsulateRaw = async (raw) => {
    await ops.revoke(ctx, { actor: 'maya' }); // races in while the key is being encapsulated
    return real(raw);
  };
  try {
    assert.deepEqual(await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw, 'race')), { decision: 'deny' });
  } finally {
    p.kemEncapsulateRaw = real;
  }
  withState(ctx, (db) => {
    assert.deepEqual(accessEvents(db).at(-1),
      { op: 'protected_read', request_id: 'race', actor: 'maya', decision: 'deny', rule: 'actor_revoked' });
    assert.equal(db.prepare(`SELECT count(*) AS n FROM audit_events WHERE kind='access' AND decision='allow'`).get().n, 0);
  });
});

test('failure recording the allow → deny', async () => {
  const ctx = freshCtx();
  await ops.setup(ctx, setupReq(SCEN));
  const k = await keypair();
  const real = audit.append;
  audit.append = (db, ev) => {
    if (ev.kind === 'access' && ev.decision === 'allow') throw new Error('disk full');
    return real(db, ev);
  };
  try {
    assert.deepEqual(await ops.protectedRead(ctx, pr('maya', 'brief', 'c', k.raw)), { decision: 'deny' });
  } finally {
    audit.append = real;
  }
});
