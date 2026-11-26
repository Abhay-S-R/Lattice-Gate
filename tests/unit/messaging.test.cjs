'use strict';
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const assert = require('node:assert/strict');
const { freshHome } = require('../helpers/kig-home.cjs');
const { runKig, ROOT } = require('../helpers/run-kig.cjs');
const identity = require('../../src/messaging/identity.cjs');
const handshake = require('../../src/messaging/handshake.cjs');
const record = require('../../src/messaging/record.cjs');

function preparePair(home) {
  const env = { KIG_HOME: home, KIG_PORT_BASE: '19000' };
  const run = (...args) => {
    const result = runKig(args, { env });
    assert.equal(result.code, 0, `${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  };
  run('init');
  run('account', 'add', 'alice');
  run('account', 'add', 'bob');
  run('device', 'enrol', 'alice-phone', '--account', 'alice');
  run('device', 'approve', 'alice-phone', '--operator', '--approval-id', 'alice-first');
  run('device', 'enrol', 'bob-phone', '--account', 'bob');
  run('device', 'approve', 'bob-phone', '--operator', '--approval-id', 'bob-first');

  const alice = identity.load(home, 'alice-phone');
  const bob = identity.load(home, 'bob-phone');
  const started = handshake.initiate(alice, 'bob-phone');
  const pending = handshake.respond(bob, started.m1);
  const finished = handshake.finish(started.state, pending.m2);
  assert.equal(handshake.confirm(pending.session, finished.m3), true);
  return { alice, bob, started, pending, finished };
}

const receiverSource = `
const fs = require('node:fs');
const record = require('./src/messaging/record.cjs');
const value = JSON.parse(fs.readFileSync(0, 'utf8'));
const session = {
  ...value.session,
  sendKey: Buffer.from(value.session.sendKey, 'base64'),
  receiveKey: Buffer.from(value.session.receiveKey, 'base64'),
  established: true,
  closed: false,
};
try {
  const plaintext = record.open(session, value.record);
  plaintext.fill(0);
  process.stdout.write('accepted\\n');
} catch (error) {
  process.stderr.write(String(error.message || error) + '\\n');
  process.exitCode = 1;
}
`;

function receiverProcess(home, session, packet) {
  const input = JSON.stringify({
    session: {
      home,
      deviceId: session.deviceId,
      account: session.account,
      peerDevice: session.peerDevice,
      peerAccount: session.peerAccount,
      epoch: session.epoch,
      sessionId: session.sessionId,
      role: session.role,
      sendKey: session.sendKey.toString('base64'),
      receiveKey: session.receiveKey.toString('base64'),
    },
    record: packet,
  });
  return spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '-e', receiverSource], {
    cwd: ROOT,
    env: { ...process.env, KIG_HOME: home },
    encoding: 'utf8',
    input,
    timeout: 30000,
  });
}

test('msg demo explicitly exercises recipient tampering and signing-key exposure', () => {
  const result = runKig(['msg', 'demo', '--seed', '2026'], { timeoutMs: 60000 });
  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /PASS tampered recipient-device field is rejected/);
  assert.match(result.stdout, /PASS forward secrecy: recorded ciphertext remains unreadable after signing-key exposure and session close/);
});

test('a replay remains rejected in a fresh receiver process', (t) => {
  const home = freshHome();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const pair = preparePair(home);
  const packet = record.seal(pair.finished.session, Buffer.from('persisted replay marker'));

  const first = receiverProcess(home, pair.pending.session, packet);
  assert.equal(first.status, 0, first.stderr || first.stdout);
  assert.equal(first.stdout.trim(), 'accepted');

  const restarted = receiverProcess(home, pair.pending.session, packet);
  assert.equal(restarted.status, 1, restarted.stdout);
  assert.equal(restarted.stderr.trim(), 'duplicate_message');

  handshake.close(pair.finished.session);
  handshake.close(pair.pending.session);
});
