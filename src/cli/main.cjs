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
for (const mod of [compat, require('./verify-log.cjs'), require('./keys.cjs'), require('./checkpoint.cjs'), require('./alerts.cjs')]) {
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
