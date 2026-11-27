'use strict';
// @ts-check
// Process liveness shared by `kig dashboard --stop/--status` and `kig crash-test`.
//
// process.kill(pid, 0) succeeds for a zombie: a process that has exited but whose
// parent has not reaped it yet (e.g. the parent is blocked in spawnSync). Treating that
// as "alive" made `kig dashboard --stop` report "did not exit within 5 s" for a server
// that had already shut down. On Linux we read the state from /proc and count a
// zombie (Z) or dead (X) process as not alive.
// ponytail: macOS/BSD zombies still read as alive (no /proc); add a `ps -o stat=` probe if that ever matters.
const fs = require('node:fs');

/** @param {number} pid @returns {boolean} */
function pidAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (e) {
    return /** @type {NodeJS.ErrnoException} */ (e).code === 'EPERM'; // exists, owned by someone else
  }
  if (process.platform !== 'linux') return true;
  let stat;
  try { stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8'); } catch { return false; } // vanished meanwhile
  // Format: "<pid> (<comm>) <state> ..."; comm may contain spaces or ')', so split after the last ')'.
  const state = stat.slice(stat.lastIndexOf(')') + 2, stat.lastIndexOf(')') + 3);
  return state !== 'Z' && state !== 'X';
}

module.exports = { pidAlive };
