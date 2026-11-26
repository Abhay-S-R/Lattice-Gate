'use strict';
// Task 2.1: CLI router (architecture §17.1).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runKig } = require('../helpers/run-kig.cjs');
const main = require('../../src/cli/main.cjs');

test('every registered command has the module shape', () => {
  assert.ok(main.COMMANDS instanceof Map);
  for (const [name, mod] of main.COMMANDS) {
    assert.equal(mod.name, name);
    assert.equal(typeof mod.describe, 'string');
    assert.equal(typeof mod.usage, 'string');
    assert.equal(typeof mod.options, 'object');
    assert.equal(typeof mod.run, 'function');
  }
  for (const n of ['compat']) assert.ok(main.COMMANDS.has(n), n);
});

test('kig help lists every command on stdout, exit 0', () => {
  const r = runKig(['help']);
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
  for (const n of main.COMMANDS.keys()) assert.match(r.stdout, new RegExp(`\\b${n}\\b`));
});

test('no command prints usage on stderr, exit 2', () => {
  const r = runKig([]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /usage/i);
});

test('unknown command exits 2 with help', () => {
  const r = runKig(['no-such-command']);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /unknown command/i);
  assert.match(r.stderr, /usage/i);
});

test('unknown option exits 2 with that command usage', () => {
  const r = runKig(['compat', '--no-such-flag']);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /usage: node kig\.cjs compat/i);
});

test('<command> --help prints that command usage, exit 0', () => {
  const r = runKig(['compat', '--help']);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /usage: node kig\.cjs compat/i);
});

test('compat still works through the router', () => {
  const r = runKig(['compat']);
  assert.equal(r.code, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /^PASS /m);
});

test('a command that throws a UsageError exits 2, other errors exit 1 with one line', async () => {
  const out = [], err = [];
  const io = { out: (s) => out.push(s), err: (s) => err.push(s) };
  const boom = { name: 'boom', describe: 'x', usage: 'usage: node kig.cjs boom', options: {},
    run: async () => { throw new Error('secret detail\nsecond line'); } };
  const bad = { name: 'bad', describe: 'x', usage: 'usage: node kig.cjs bad', options: {},
    run: async () => { throw new main.UsageError('need --db'); } };
  const cmds = new Map([['boom', boom], ['bad', bad]]);
  assert.equal(await main.main(['boom'], { io, commands: cmds }), 1);
  assert.equal(err.join('').split('\n').filter(Boolean).length, 1);
  assert.equal(await main.main(['bad'], { io, commands: cmds }), 2);
  assert.match(err.join(''), /need --db/);
});
