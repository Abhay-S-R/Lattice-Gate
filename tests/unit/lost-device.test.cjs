'use strict';
// Task 4.2: lost device → revoke on every node, re-key, approved re-enrolment (features P1-03; architecture §11).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { NODE_IDS, layout } = require('../../src/core/contracts.cjs');
const { freshHome, startCluster } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');
const client = require('../../src/device/client.cjs');
const deviceFiles = require('../../src/device/files.cjs');
const keystore = require('../../src/device/keystore.cjs');
const wrap = require('../../src/core/wrap.cjs');
const provider = require('../../src/crypto/provider.cjs');
const { encode } = require('../../src/core/encoding.cjs');
const { WRAP } = require('../../src/core/contracts.cjs');

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
let seq = 0;

test('lost device: denied everywhere, re-keyed, old envelope useless; replacement needs a second factor; peer keeps access', async (t) => {
  const home = freshHome();
  const inputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-lost-input-'));
  const plaintext = Buffer.from(`brief for the lost-device test ${provider.random(8).toString('hex')}\n`);
  const input = path.join(inputDir, 'brief.txt');
  fs.writeFileSync(input, plaintext);
  let cluster;
  t.after(async () => {
    if (cluster) await cluster.stop();
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(inputDir, { recursive: true, force: true });
  });
  cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  const run = (args) => runKig(args, { env, timeoutMs: 120000 });
  const ok = (args) => { const r = run(args); assert.equal(r.code, 0, `${args.join(' ')}: ${r.stderr || r.stdout}`); return r; };
  const request = (node, device, account, op, keyVersion, resource = 'brief') => client.request(cluster.nodeUrls[node], layout(home).device(device).dir, op,
    { home, version: 1, op, account, device_id: device, resource, request_id: `lost-${++seq}`, key_version: keyVersion });
  const readUntil = async (node, device, account, v) => {
    const end = Date.now() + 8000; let last;
    while (Date.now() < end) {
      last = await request(node, device, account, 'file.read', v);
      if (last.decision === 'allow') return deviceFiles.read(home, device, last);
      await pause(25);
    }
    throw new Error(`${device} could not read v${v} via ${node}: ${last && last.rule}`);
  };

  ok(['account', 'add', 'alice']);
  ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'alice-first']);
  ok(['device', 'enrol', 'alice-laptop', '--account', 'alice']);
  ok(['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'alice-laptop-ok']);
  ok(['account', 'add', 'bob']);
  ok(['device', 'enrol', 'bob-laptop', '--account', 'bob']);
  ok(['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'bob-first']);
  ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  ok(['share', 'brief', '--with', 'bob']);

  // What the phone holds before it is lost: its v1 response (ciphertext + its own envelope).
  const phoneV1 = await request('A', 'alice-phone', 'alice', 'file.read', 1);
  assert.equal(phoneV1.decision, 'allow');
  assert.ok(deviceFiles.read(home, 'alice-phone', phoneV1).equals(plaintext));

  const lost = ok(['lost', '--device', 'alice-phone']);
  assert.match(lost.stdout, /^LOST "alice-phone": revoked at epoch \d+; signed node acks after A [\d.]+ ms, B [\d.]+ ms, C [\d.]+ ms/m);
  assert.match(lost.stdout, /ROTATED "brief" 1 -> 2 epoch=\d+ \(complete/);

  for (const id of NODE_IDS) {
    for (const op of ['policy.probe', 'file.read', 'file.transfer']) {
      const denied = await request(id, 'alice-phone', 'alice', op, 2);
      assert.deepEqual([denied.decision, denied.rule], ['deny', 'device_revoked'], `${op} via ${id}`);
    }
    assert.ok((await readUntil(id, 'bob-laptop', 'bob', 2)).equals(plaintext), `peer keeps access via ${id}`);
    assert.ok((await readUntil(id, 'alice-laptop', 'alice', 2)).equals(plaintext), `alice-laptop via ${id}`);
  }

  // The phone's old material cannot open the new version.
  const bobV2 = await request('B', 'bob-laptop', 'bob', 'file.read', 2);
  assert.equal(bobV2.version, 2);
  const phoneKeys = keystore.load(home, 'alice-phone');
  const oldDek = wrap.kemUnwrap(phoneKeys.kemPrivate, phoneV1.envelope, ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope']);
  for (const aadVersion of [1, 2]) {
    assert.throws(() => provider.aeadOpen(oldDek, Buffer.from(bobV2.nonce, 'base64'),
      encode(WRAP.fileAadLabel, ['brief', aadVersion, 'kig/v1/file']), Buffer.from(bobV2.ciphertext, 'base64')), `old DEK, aad v${aadVersion}`);
  }
  assert.throws(() => deviceFiles.read(home, 'alice-phone', { ...bobV2, account: 'alice', envelope: phoneV1.envelope }), 'old envelope against v2');
  assert.notEqual(Buffer.from(bobV2.ciphertext, 'base64').toString('hex'), Buffer.from(phoneV1.ciphertext, 'base64').toString('hex'));

  // Re-enrolment needs a second factor.
  ok(['device', 'enrol', 'alice-phone-2', '--account', 'alice']);
  for (const id of NODE_IDS) assert.equal((await request(id, 'alice-phone-2', 'alice', 'file.read', 2)).rule, 'unknown_device', `pending device via ${id}`);
  const byLost = run(['device', 'approve', 'alice-phone-2', '--by', 'alice-phone', '--approval-id', 'from-lost-phone']);
  assert.equal(byLost.code, 1);
  assert.match(byLost.stderr, /approval denied \(approver_not_active\)/);
  const noFactor = run(['device', 'approve', 'alice-phone-2', '--approval-id', 'nothing']);
  assert.equal(noFactor.code, 2, 'an approval needs --by <device> or --operator');
  const approved = ok(['device', 'approve', 'alice-phone-2', '--by', 'alice-laptop', '--approval-id', 'phone-2-by-laptop']);
  assert.match(approved.stdout, /^DEVICE alice-phone-2 active\nPROVISIONED alice-phone-2: "brief" v2\n$/);
  for (const id of NODE_IDS) assert.ok((await readUntil(id, 'alice-phone-2', 'alice', 2)).equals(plaintext), `replacement via ${id}`);

  // Reporting an already revoked device again only re-keys; an unknown device is refused.
  const again = ok(['lost', '--device', 'alice-phone']);
  assert.match(again.stdout, /^LOST "alice-phone": already revoked; re-keying its files\n {2}ROTATED "brief" 2 -> 3 /);
  for (const id of NODE_IDS) {
    assert.ok((await readUntil(id, 'alice-phone-2', 'alice', 3)).equals(plaintext));
    assert.ok((await readUntil(id, 'bob-laptop', 'bob', 3)).equals(plaintext));
  }
  const unknown = run(['lost', '--device', 'nobody']);
  assert.equal(unknown.code, 1);
  assert.match(unknown.stderr, /lost-device response refused \(device_not_found\)/);
});
