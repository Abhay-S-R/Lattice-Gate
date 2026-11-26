'use strict';
// Round 2 operator CLI: node kig.cjs <command> [options]   (see src/cli/main.cjs)
process.removeAllListeners('warning');

require('./src/cli/main.cjs').main(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  () => { process.stderr.write('kig: command failed\n'); process.exitCode = 1; },
);
