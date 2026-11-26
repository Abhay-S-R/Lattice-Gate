'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const provider = require('../crypto/provider.cjs');
const identity = require('../messaging/identity.cjs');
const handshake = require('../messaging/handshake.cjs');
const record = require('../messaging/record.cjs');
const chunk = require('../messaging/chunk.cjs');
const { TransportSim } = require('../messaging/transport-sim.cjs');
const replay = require('../messaging/replay.cjs');
const { encode } = require('../core/encoding.cjs');
const { UsageError } = require('./main.cjs');

const ROOT = path.resolve(__dirname, '..', '..');

function requireOk(ok, message) { if (!ok) throw new Error(message); }
function requireThrows(fn, message) {
  try { fn(); } catch { return; }
  throw new Error(message);
}
function cli(env, args) {
  const result = spawnSync(process.execPath, [path.join(ROOT, 'kig.cjs'), ...args], {
    cwd: ROOT, env, encoding: 'utf8', timeout: 30000,
  });
  if (result.status !== 0) throw new Error(`${args[0]} command failed (${result.stderr || result.stdout || 'timeout'})`);
}
function pass(io, name) { io.out(`PASS ${name}\n`); }
function corruptBase64(value) {
  const bytes = Buffer.from(value, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
}
function transcriptCandidateCannotOpen(m1, m2, packet) {
  const th1 = Buffer.from(m2.th1, 'hex');
  const kemCiphertext = Buffer.from(m2.ct, 'base64');
  const nonceR = Buffer.from(m2.nonce_r, 'base64');
  const th2 = provider.sha256(encode('kig/v1/handshake/m2', [th1, kemCiphertext, nonceR, m2.responder, m2.epoch]));
  const candidate = provider.kemEncapsulate(provider.importPublic(Buffer.from(m1.ephemeral_pk, 'base64')));
  const key = provider.hkdf(candidate.sharedKey, th2,
    encode('kig/v1/traffic-key', [handshake.VERSION, handshake.SUITE, 'initiator-to-responder', m1.initiator, m1.responder]), 32);
  const fields = {
    sender_account: packet.sender_account, sender_device: packet.sender_device,
    recipient_account: packet.recipient_account, recipient_device: packet.recipient_device,
    epoch: packet.epoch, msg_id: packet.msg_id, seq: packet.seq,
    chunk_idx: packet.chunk_idx, chunk_total: packet.chunk_total,
  };
  const aad = record.header({ sessionId: packet.session_id }, fields);
  const iv = record.nonce('i2r', BigInt(packet.seq));
  try {
    requireOk(!candidate.ciphertext.equals(kemCiphertext), 'public encapsulation recreated the captured KEM ciphertext');
    try {
      const plaintext = provider.aeadOpen(key, iv, aad, Buffer.from(packet.ciphertext, 'base64'));
      plaintext.fill(0);
      return false;
    } catch (error) {
      if (error instanceof provider.AeadError) return true;
      throw error;
    }
  } finally {
    candidate.sharedKey.fill(0);
    key.fill(0);
    th1.fill(0);
    kemCiphertext.fill(0);
    nonceR.fill(0);
    th2.fill(0);
    aad.fill(0);
    iv.fill(0);
  }
}

async function demo(seed, io) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-msg-demo-'));
  const env = { ...process.env, KIG_HOME: home, KIG_PORT_BASE: '19000' };
  const openSessions = [];
  try {
    cli(env, ['init']);
    for (const account of ['alice', 'bob', 'retired']) cli(env, ['account', 'add', account]);
    for (const [device, account, approval] of [
      ['alice-phone', 'alice', 'alice-first'], ['bob-phone', 'bob', 'bob-first'], ['retired-phone', 'retired', 'retired-first'],
    ]) {
      cli(env, ['device', 'enrol', device, '--account', account]);
      cli(env, ['device', 'approve', device, '--operator', '--approval-id', approval]);
    }
    const alice = identity.load(home, 'alice-phone');
    const bob = identity.load(home, 'bob-phone');
    const retired = identity.load(home, 'retired-phone');
    pass(io, 'temporary Alice/Bob identities are enrolled and pinned to the signed policy');

    const tamperedInit = handshake.initiate(alice, 'bob-phone');
    const badM1 = { ...tamperedInit.m1, nonce_i: corruptBase64(tamperedInit.m1.nonce_i) };
    requireThrows(() => handshake.respond(bob, badM1), 'tampered M1 unexpectedly verified');
    handshake.abort(tamperedInit.state);
    requireThrows(() => handshake.initiate(alice, 'unknown-phone'), 'unregistered peer unexpectedly accepted');
    pass(io, 'tampered M1 and unregistered peer are rejected');

    const tamperedInit2 = handshake.initiate(alice, 'bob-phone');
    const pending2 = handshake.respond(bob, tamperedInit2.m1);
    openSessions.push(pending2.session);
    const badM2 = { ...pending2.m2, nonce_r: corruptBase64(pending2.m2.nonce_r) };
    requireThrows(() => handshake.finish(tamperedInit2.state, badM2), 'tampered M2 unexpectedly verified');
    handshake.close(pending2.session);

    const tamperedInit3 = handshake.initiate(alice, 'bob-phone');
    const pending3 = handshake.respond(bob, tamperedInit3.m1);
    openSessions.push(pending3.session);
    const wrongMac = { ...pending3.m2, mac_r: corruptBase64(pending3.m2.mac_r) };
    requireThrows(() => handshake.finish(tamperedInit3.state, wrongMac), 'wrong responder confirmation MAC unexpectedly verified');
    handshake.close(pending3.session);
    pass(io, 'tampered M2 signature transcript and key-confirmation MAC are rejected');

    const confirmInit = handshake.initiate(alice, 'bob-phone');
    const confirmPending = handshake.respond(bob, confirmInit.m1);
    openSessions.push(confirmPending.session);
    const confirmed = handshake.finish(confirmInit.state, confirmPending.m2);
    openSessions.push(confirmed.session);
    requireThrows(() => handshake.confirm(confirmPending.session, { ...confirmed.m3, mac_i: corruptBase64(confirmed.m3.mac_i) }),
      'wrong initiator confirmation MAC unexpectedly verified');
    handshake.close(confirmed.session);
    pass(io, 'wrong initiator key-confirmation MAC is rejected');

    const initiated = handshake.initiate(alice, 'bob-phone');
    const responder = handshake.respond(bob, initiated.m1);
    openSessions.push(responder.session);
    const finished = handshake.finish(initiated.state, responder.m2);
    openSessions.push(finished.session);
    requireOk(initiated.state.ephemeralPrivate === null, 'initiator ephemeral KEM private key was retained');
    requireOk(handshake.confirm(responder.session, finished.m3), 'responder key confirmation failed');
    requireOk(finished.session.sessionId === responder.session.sessionId, 'peers derived different session IDs');
    pass(io, 'authenticated ephemeral KEM handshake, transcript signatures, and mutual key confirmation');

    const shortRecord = record.seal(finished.session, Buffer.from('recipient-bound message'));
    requireThrows(() => record.open(responder.session, shortRecord, 'alice-phone'), 'wrong recipient was accepted');
    const tamperedRecipient = { ...shortRecord, recipient_device: 'alice-phone' };
    requireThrows(() => record.open(responder.session, tamperedRecipient), 'tampered recipient-device field was accepted');
    pass(io, 'tampered recipient-device field is rejected');
    const changedAad = { ...shortRecord, msg_id: shortRecord.msg_id.replace(/^./, shortRecord.msg_id[0] === '0' ? '1' : '0') };
    requireThrows(() => record.open(responder.session, changedAad), 'altered record AAD was accepted');
    const received = record.open(responder.session, shortRecord);
    requireOk(received.toString('utf8') === 'recipient-bound message', 'recipient did not recover the message');
    received.fill(0);
    requireThrows(() => record.open(responder.session, shortRecord), 'duplicate record was accepted');
    pass(io, 'wrong recipient, altered AAD, and duplicate record are rejected');

    const body = Buffer.from(`seeded messaging payload ${String(seed).padStart(8, '0')}\n`.repeat(1900));
    const pieces = chunk.split(body);
    const sealed = pieces.map((part) => {
      const value = record.seal(finished.session, part.plaintext, { msg_id: part.msg_id, chunk_idx: part.chunk_idx, chunk_total: part.chunk_total });
      part.plaintext.fill(0);
      return value;
    });
    const rewritten = { ...sealed[0], chunk_total: sealed[0].chunk_total + 1 };
    requireThrows(() => record.open(responder.session, rewritten), 'unauthenticated chunk count rewrite was accepted');
    const assembler = new chunk.Reassembler();
    const transport = new TransportSim(seed, { drop: 0.12, dup: 0.2, reorder: 1, delay: 40, retries: 3 });
    const delivery = transport.deliver(sealed, (wire) => {
      const plaintext = record.open(responder.session, wire);
      return assembler.add(wire, plaintext);
    });
    requireOk(delivery.transport.missing === 0, 'bounded retries failed to recover all chunks');
    pass(io, `transport receipt: ${delivery.transport.receipts}/${sealed.length} chunks (${delivery.transport.retries} retries)`);
    const completed = delivery.arrivals.map((row) => row.result).filter((row) => row?.state === 'delivered');
    requireOk(completed.length === 1, 'chunks did not reassemble exactly once');
    pass(io, `reassembly complete: ${completed.length} message`);
    requireOk(completed[0].message.equals(body), 'reassembled message differs from sent plaintext');
    completed[0].message.fill(0);
    body.fill(0);
    pass(io, 'application delivery: exact message delivered once despite loss, duplication, and reordering');

    const expiring = new chunk.Reassembler();
    expiring.add({ session_id: finished.session.sessionId, msg_id: 'a'.repeat(32), chunk_idx: 0, chunk_total: 2 }, Buffer.from('partial'), 1000);
    const expired = expiring.expire(1000 + chunk.REASSEMBLY_TIMEOUT_MS);
    requireOk(expired.length === 1 && expired[0].reason === 'reassembly_timeout', 'incomplete message did not expire');
    const tooLarge = Buffer.alloc(chunk.MAX_MESSAGE_BYTES + 1);
    requireThrows(() => chunk.split(tooLarge), 'oversize message bypassed the reassembly limit');
    tooLarge.fill(0);
    const bounded = new chunk.Reassembler({ maxBufferedBytes: 1 });
    const limited = bounded.add({ session_id: finished.session.sessionId, msg_id: 'b'.repeat(32), chunk_idx: 0, chunk_total: 1 }, Buffer.from('xx'));
    requireOk(limited.state === 'failed' && limited.reason === 'buffer_limit', 'buffer cap was not enforced');
    pass(io, 'incomplete message expires; message-size and buffer limits fail closed');

    const capturedM1 = initiated.m1;
    const capturedM2 = responder.m2;
    const leakedSigningKey = alice.keys.signPrivate;
    const leakedKeyProof = provider.sign(leakedSigningKey, provider.CONTEXTS.handshake, Buffer.from(capturedM2.th1, 'hex'));
    requireOk(provider.verify(alice.keys.signPublic, provider.CONTEXTS.handshake, Buffer.from(capturedM2.th1, 'hex'), leakedKeyProof),
      'compromised long-term signing key could not sign the captured transcript');
    leakedKeyProof.fill(0);
    handshake.close(finished.session);
    handshake.close(responder.session);
    requireThrows(() => record.open(responder.session, shortRecord), 'record from a closed session was accepted');
    requireOk(!replay.isActive(home, 'bob-phone', responder.session.sessionId, 'alice-phone', responder.session.epoch),
      'closed session remains active in persistent replay state');
    requireOk(initiated.state.ephemeralPrivate === null, 'initiator ephemeral KEM private key survived session close');
    const trafficKeysCleared = [finished.session.sendKey, finished.session.receiveKey,
      responder.session.sendKey, responder.session.receiveKey].every((key) => Buffer.isBuffer(key) && key.every((byte) => byte === 0));
    requireOk(trafficKeysCleared, 'traffic keys survived session close');
    requireOk(transcriptCandidateCannotOpen(capturedM1, capturedM2, shortRecord),
      'captured transcript and exposed signing key recovered the closed-session ciphertext');
    requireOk(typeof capturedM1.ephemeral_pk === 'string' && typeof capturedM2.ct === 'string', 'handshake transcript was not captured');
    pass(io, 'forward secrecy: recorded ciphertext remains unreadable after signing-key exposure and session close');

    const retiredSessionInit = handshake.initiate(alice, 'retired-phone');
    const retiredPending = handshake.respond(retired, retiredSessionInit.m1);
    openSessions.push(retiredPending.session);
    const retiredFinished = handshake.finish(retiredSessionInit.state, retiredPending.m2);
    openSessions.push(retiredFinished.session);
    handshake.confirm(retiredPending.session, retiredFinished.m3);
    const liveRetiredRecord = record.seal(retiredFinished.session, Buffer.from('old-session'));
    cli(env, ['revoke', '--device', 'retired-phone']);
    requireThrows(() => handshake.initiate(alice, 'retired-phone'), 'revoked peer established a new session');
    requireThrows(() => record.open(retiredPending.session, liveRetiredRecord), 'revoked peer session record was accepted');
    requireThrows(() => record.seal(retiredFinished.session, Buffer.from('after revocation')), 'revoked peer session sent a record');
    pass(io, 'revoked device cannot establish or continue a session');

    io.out('Session resumption: NOT SUPPORTED (D-05)\n');
    return 0;
  } catch (e) {
    io.err(`kig msg demo: ${String(e?.message || e).split(/\r?\n/)[0]}\n`);
    return 1;
  } finally {
    for (const session of openSessions) {
      try { if (!session.closed) handshake.close(session); } catch { /* best-effort local cleanup */ }
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'msg', describe: 'run the secure messaging handshake, replay, and delivery demo',
  usage: 'usage: node kig.cjs msg demo [--seed <uint32>]',
  options: { seed: { type: 'string' } },
  async run({ values, positionals, io }) {
    if (positionals.length !== 1 || positionals[0] !== 'demo') throw new UsageError('expected demo');
    const seed = values.seed === undefined ? 2026 : Number(values.seed);
    if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new UsageError('--seed must be an integer from 0 to 4294967295');
    return demo(seed, io);
  },
};
