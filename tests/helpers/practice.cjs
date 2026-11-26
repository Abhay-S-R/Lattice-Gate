'use strict';
// Locate the organizer toolkit's practice set (read in place, never copied into
// this repo). Fails loudly if it can't be found, so a missing toolkit is never
// mistaken for a passing run.
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');

function practiceDir() {
  const candidates = [
    process.env.TOOLKIT_DIR && path.resolve(ROOT, process.env.TOOLKIT_DIR, 'practice'),
    '/toolkit/practice', // judge replica
    path.join(ROOT, 'toolkit', 'practice'), // CI checkout
    path.resolve(ROOT, '..', 'Track-4-Toolkit', 'practice'),
    path.resolve(ROOT, '..', 'track4-toolkit', 'practice'),
  ].filter(Boolean);
  const found = candidates.find((d) => fs.existsSync(path.join(d, 'events.csv')) && fs.existsSync(path.join(d, 'approvals.json')));
  if (!found) {
    throw new Error(`toolkit practice set not found (set TOOLKIT_DIR); looked in:\n  ${candidates.join('\n  ')}`);
  }
  return found;
}

const practiceEventsPath = () => path.join(practiceDir(), 'events.csv');
const practiceApprovalsPath = () => path.join(practiceDir(), 'approvals.json');
const practiceApprovals = () => JSON.parse(fs.readFileSync(practiceApprovalsPath(), 'utf8'));

module.exports = { practiceDir, practiceEventsPath, practiceApprovalsPath, practiceApprovals };
