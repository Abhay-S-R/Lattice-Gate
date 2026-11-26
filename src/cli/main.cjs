'use strict';
// @ts-check
// `kig` command router (architecture §17.1, Task 2.1).
//
// Every command is a module exporting:
//   { name, describe, usage, options, run({ values, positionals, io }) → Promise<exit code> }
// where `options` is a util.parseArgs options config. Register it in COMMANDS below.
// Exit codes: 0 ok; 1 command failed / check failed; 2 usage error.
const { parseArgs } = require('node:util');

/** Throw from a command's run() for bad/missing arguments → exit 2 with that command's usage. */
class UsageError extends Error {
  constructor(message) { super(message); this.name = 'UsageError'; }
}

/** Throw from a command's run() for an expected, user-facing failure → exit 1, message printed. */
class CommandError extends Error {
  constructor(message) { super(message); this.name = 'CommandError'; }
}

const compat = {
  name: 'compat',
  describe: 'check that this runtime supports everything KIG needs',
  usage: 'usage: node kig.cjs compat',
  options: {},
  run: () => require('./compat.cjs').main(),
};

/** @type {Map<string, any>} */
const COMMANDS = new Map();
// Registered after the error classes exist (command modules import them from here).
module.exports = { COMMANDS, UsageError, CommandError };
// Phase 5 detector commands. The wrappers live here so src/cli/detect.cjs stays
// inside the detector's require graph (tests/unit/detect/no-label-leak.test.cjs).
const detectCli = require('./detect.cjs');
const detect = {
  name: 'detect',
  describe: detectCli.describe,
  usage: detectCli.USAGE.trimEnd(),
  options: detectCli.options,
  run: ({ values, positionals }) => {
    if (positionals.length) throw new UsageError(`unexpected argument '${oneLine(positionals[0])}'`);
    return detectCli.run(values);
  },
};
const benchDetectCli = require('./bench-detect.cjs');
const bench = {
  name: 'bench',
  describe: `benchmarks; 'bench detect': ${benchDetectCli.describe}`,
  usage: 'usage: node kig.cjs bench detect --seeds <list> --holdout <list> [options]\n       node kig.cjs bench revocation --n 100 --seed <s> [--out <file>] [--json]',
  options: { ...benchDetectCli.options, n: { type: 'string' }, seed: { type: 'string' } },
  run: ({ values, positionals }) => {
    if (positionals.length !== 1) throw new UsageError("expected 'bench detect' or 'bench revocation'");
    if (positionals[0] === 'detect') return benchDetectCli.run(values);
    if (positionals[0] === 'revocation') return require('./bench-revocation.cjs').run(values);
    throw new UsageError("expected 'bench detect' or 'bench revocation'");
  },
};

const supervisor = require('./supervisor.cjs');
for (const mod of [compat, require('./verify-log.cjs'), require('./keys.cjs'), require('./checkpoint.cjs'), require('./alerts.cjs'),
  require('./init.cjs'), require('./account.cjs'), require('./device.cjs'), require('./file.cjs'), require('./share.cjs'),
  require('./revoke.cjs'), require('./node.cjs'),
  require('./msg.cjs'),
  detect, bench, supervisor.up, supervisor.down, supervisor.statusCommand]) {
  COMMANDS.set(mod.name, mod);
}

const stdio = {
  out: (/** @type {string} */ s) => process.stdout.write(s),
  err: (/** @type {string} */ s) => process.stderr.write(s),
};

function usage(commands) {
  const width = Math.max(...[...commands.keys()].map((k) => k.length));
  const lines = [...commands.values()].map((c) => `  ${c.name.padEnd(width)}  ${c.describe}`);
  return `usage: node kig.cjs <command> [options]\n       node kig.cjs <command> --help\n\ncommands:\n${lines.join('\n')}\n`;
}

/** First line of a message only, so errors never spill multi-line detail. */
const oneLine = (/** @type {unknown} */ m) => String(m).split(/\r?\n/)[0];

/**
 * @param {string[]} argv arguments after `kig.cjs`
 * @param {{ io?: typeof stdio, commands?: Map<string, any> }} [o]
 * @returns {Promise<number>}
 */
async function main(argv, { io = stdio, commands = COMMANDS } = {}) {
  const [name, ...rest] = argv;
  if (name === 'help' || name === '--help' || name === '-h') { io.out(usage(commands)); return 0; }
  if (name === undefined) { io.err(usage(commands)); return 2; }
  const cmd = commands.get(name);
  if (!cmd) { io.err(`kig: unknown command '${oneLine(name)}'\n${usage(commands)}`); return 2; }

  let parsed;
  try {
    parsed = parseArgs({
      args: rest, options: { help: { type: 'boolean', short: 'h' }, ...cmd.options },
      allowPositionals: true, strict: true,
    });
  } catch (e) {
    io.err(`kig ${name}: ${oneLine(/** @type {Error} */ (e).message)}\n${cmd.usage}\n`);
    return 2;
  }
  if (parsed.values.help) { io.out(`${cmd.usage}\n`); return 0; }

  try {
    const code = await cmd.run({ values: parsed.values, positionals: parsed.positionals, io });
    return Number.isInteger(code) ? code : 0;
  } catch (e) {
    if (e instanceof UsageError) { io.err(`kig ${name}: ${oneLine(e.message)}\n${cmd.usage}\n`); return 2; }
    if (e instanceof CommandError) { io.err(`kig ${name}: ${oneLine(e.message)}\n`); return 1; }
    io.err(`kig ${name}: failed (${e && /** @type {Error} */ (e).name || 'Error'})\n`);
    return 1;
  }
}

Object.assign(module.exports, { main, usage });
