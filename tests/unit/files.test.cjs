'use strict';
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

function storeFiles(home) {
  const l = layout(home);
  const roots = [path.dirname(l.cp.db), ...NODE_IDS.map((id) => l.node(id).dir), path.join(home, 'devices')];
  const files = [];
  const visit = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(file);
      else files.push(file);
    }
  };
  roots.forEach(visit);
  return [...new Set(files)];
}

test('encrypted files can be shared and read through every node without plaintext stored', async (t) => {
  const home = freshHome();
  const inputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-file-input-'));
  const marker = `KIG_M4_PLAINTEXT_${require('node:crypto').randomBytes(18).toString('hex')}`;
  const input = path.join(inputDir, 'brief.txt');
  fs.writeFileSync(input, marker, { mode: 0o600 });
  let cluster;
  t.after(async () => {
    if (cluster) await cluster.stop();
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(inputDir, { recursive: true, force: true });
  });

  cluster = await startCluster(home);
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(new URL(cluster.cpUrl).port) };
  const run = (args) => runKig(args, { env, timeoutMs: 30000 });
  const successful = (args) => {
    const result = run(args);
    assert.equal(result.code, 0, `${args.join(' ')} failed: ${result.stderr || result.stdout}`);
    return result;
  };

  successful(['account', 'add', 'alice']);
  successful(['device', 'enrol', 'alice-phone', '--account', 'alice']);
  successful(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'alice-first']);
  successful(['device', 'enrol', 'alice-laptop', '--account', 'alice']);
  successful(['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'alice-laptop']);
  successful(['account', 'add', 'bob']);
  successful(['device', 'enrol', 'bob-laptop', '--account', 'bob']);
  successful(['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'bob-first']);
  successful(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
  successful(['share', 'brief', '--with', 'bob']);

  for (const deviceId of ['alice-phone', 'alice-laptop', 'bob-laptop']) {
    for (const nodeId of NODE_IDS) {
      const result = successful(['file', 'read', 'brief', '--device', deviceId, '--node', nodeId]);
      assert.equal(result.stdout.trim(), marker, `${deviceId} could not read through ${nodeId}`);
    }
  }

  const request = await client.request(cluster.nodeUrls.A, layout(home).device('alice-phone').dir, 'file.read', {
    home, version: 1, op: 'file.read', account: 'alice', device_id: 'alice-phone', resource: 'brief',
    request_id: `m4-${Date.now()}`, key_version: 1,
  });
  assert.equal(request.decision, 'allow');
  assert.equal(deviceFiles.read(home, 'alice-phone', request).toString('utf8'), marker);
  assert.throws(() => deviceFiles.read(home, 'alice-laptop', request));

  const tampered = (change) => {
    const response = structuredClone(request);
    change(response);
    assert.throws(() => deviceFiles.read(home, 'alice-phone', response));
  };
  tampered((r) => { const bytes = Buffer.from(r.ciphertext, 'base64'); bytes[0] ^= 1; r.ciphertext = bytes.toString('base64'); });
  tampered((r) => { const bytes = Buffer.from(r.ciphertext, 'base64'); bytes[bytes.length - 1] ^= 1; r.ciphertext = bytes.toString('base64'); });
  tampered((r) => { const bytes = Buffer.from(r.nonce, 'base64'); bytes[0] ^= 1; r.nonce = bytes.toString('base64'); });
  tampered((r) => { r.file_id = `${r.file_id}-other`; });
  tampered((r) => { r.account = 'bob'; });

  for (const file of storeFiles(home)) {
    assert.equal(fs.readFileSync(file).includes(Buffer.from(marker)), false, `plaintext found in store file ${file}`);
  }
});
