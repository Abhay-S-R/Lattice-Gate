'use strict';
// Round 2 operator CLI: node kig.cjs <command> [options]
process.removeAllListeners('warning');

// `kig bench <kind>`: benchmark subcommands (Phase 7 adds more kinds here).
const BENCH = new Map([
  ['detect', (args) => require('./src/cli/bench-detect.cjs').main(args)],
]);

const COMMANDS = new Map([
  ['compat', (args) => require('./src/cli/compat.cjs').main(args)],
  ['detect', (args) => require('./src/cli/detect.cjs').main(args)],
  ['bench', async (args) => {
    const sub = BENCH.get(args[0]);
    if (!sub) { process.stderr.write(USAGE); return 2; }
    return sub(args.slice(1));
  }],
  ['help', async () => { process.stdout.write(USAGE); return 0; }],
]);

const USAGE = `usage: node kig.cjs <command>

commands:
  compat         check that this runtime supports everything KIG needs
  detect         explainable privilege-change and lateral-movement detection over an event file
  bench detect   seeded synthetic detection benchmark (tuning and held-out seeds)
  help           show this list
`;

async function main(argv) {
  const cmd = COMMANDS.get(argv[0]);
  if (!cmd) { process.stderr.write(USAGE); return 2; }
  return cmd(argv.slice(1));
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  () => { process.stderr.write('kig: command failed\n'); process.exitCode = 1; },
);
