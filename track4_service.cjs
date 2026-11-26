'use strict';
process.removeAllListeners('warning'); // first: ExperimentalWarning (SQLite, ML-KEM) must never reach stderr
// Round 1 transport (toolkit starter, adapted; architecture §5.2).
// One JSON object in on stdin, one JSON object + '\n' out on stdout, then exit.
// Changes from the starter: warning suppression; bounded stdin read with fatal
// UTF-8 decoding (in index.cjs); invalid input → {"error":"invalid_request"},
// exit 0. stderr only ever gets the fixed line below, only with exit 1.
const fs = require('node:fs');

const FAIL_LINE = 'Request failed; inspect team application locally.\n';
const MAX_STDIN_BYTES = 4 * 1024 * 1024; // = limits.MAX_STDIN_BYTES; inlined so a load failure still exits cleanly
const CHUNK = 64 * 1024;
const NAP = new Int32Array(new SharedArrayBuffer(4));

/**
 * Read fd 0 to EOF. Returns null if it exceeds MAX_STDIN_BYTES; the rest is
 * still drained (and discarded) so the writer never sees EPIPE.
 * @returns {Buffer|null}
 */
function readStdin() {
  const chunks = [];
  const buf = Buffer.allocUnsafe(CHUNK);
  let total = 0;
  let over = false;
  for (;;) {
    let n;
    try {
      n = fs.readSync(0, buf, 0, CHUNK, null);
    } catch (e) {
      if (e && e.code === 'EAGAIN') { Atomics.wait(NAP, 0, 0, 5); continue; }
      if (e && e.code === 'EOF') break;
      throw e;
    }
    if (n === 0) break;
    if (over) continue;
    total += n;
    if (total > MAX_STDIN_BYTES) { over = true; chunks.length = 0; continue; }
    chunks.push(Buffer.from(buf.subarray(0, n)));
  }
  return over ? null : Buffer.concat(chunks);
}

async function main() {
  try {
    const input = readStdin();
    const { response, exitCode } = input === null
      ? { response: { error: 'invalid_request' }, exitCode: 0 }
      : await require('./team_app.cjs').handleRaw(input);
    if (exitCode !== 0 || !response || typeof response !== 'object' || Array.isArray(response)) {
      process.stderr.write(FAIL_LINE);
      process.exitCode = 1;
      return;
    }
    process.stdout.write(JSON.stringify(response) + '\n');
    process.exitCode = 0;
  } catch {
    process.stderr.write(FAIL_LINE);
    process.exitCode = 1;
  }
}
main();
