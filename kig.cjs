'use strict';
// Round 2 operator CLI: node kig.cjs <command> [options]
process.removeAllListeners('warning');

const COMMANDS = new Map([
  ['compat', () => require('./src/cli/compat.cjs').main()],
]);

const USAGE = `usage: node kig.cjs <command>\n\ncommands:\n  compat    check that this runtime supports everything KIG needs\n`;

async function main(argv) {
  const cmd = COMMANDS.get(argv[0]);
  if (!cmd) { process.stderr.write(USAGE); return 2; }
  return cmd(argv.slice(1));
}

main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  () => { process.stderr.write('kig: command failed\n'); process.exitCode = 1; },
);
