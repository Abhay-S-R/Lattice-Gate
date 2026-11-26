'use strict';
// Round 2 operator CLI: node kig.cjs <command> [options]
process.removeAllListeners('warning');

const COMMANDS = new Map([
  ['compat', (args) => require('./src/cli/compat.cjs').main(args)],
  ['detect', (args) => require('./src/cli/detect.cjs').main(args)],
  ['help', async () => { process.stdout.write(USAGE); return 0; }],
]);

const USAGE = `usage: node kig.cjs <command>

commands:
  compat    check that this runtime supports everything KIG needs
  detect    explainable privilege-change and lateral-movement detection over an event file
  help      show this list
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
