'use strict';
// Phase 4 P4-D9: a file must fit one signed stage message, so publish enforces the rotation size cap.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { ROTATION } = require('../../src/core/contracts.cjs');
const { freshHome } = require('../helpers/kig-home.cjs');
const { runKig } = require('../helpers/run-kig.cjs');

test('publish accepts a file at the 256 KiB cap and refuses one byte more', (t) => {
  const home = freshHome();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const env = { KIG_HOME: home, KIG_PORT_BASE: String(20000 + Math.floor(Math.random() * 20000)) };
  const run = (args) => runKig(args, { env, timeoutMs: 60000 });
  for (const args of [['init'], ['account', 'add', 'alice'], ['device', 'enrol', 'alice-phone', '--account', 'alice'],
    ['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'a1']]) assert.equal(run(args).code, 0, args.join(' '));
  const atCap = path.join(home, 'at-cap.bin');
  const over = path.join(home, 'over.bin');
  fs.writeFileSync(atCap, Buffer.alloc(ROTATION.maxFileBytes, 0x61));
  fs.writeFileSync(over, Buffer.alloc(ROTATION.maxFileBytes + 1, 0x61));
  const ok = run(['file', 'publish', 'big', '--as', 'alice-phone', '--input', atCap]);
  assert.equal(ok.code, 0, ok.stderr);
  const refused = run(['file', 'publish', 'too-big', '--as', 'alice-phone', '--input', over]);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /publish failed \(file_too_large\)/);
});
