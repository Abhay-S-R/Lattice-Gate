'use strict';
// Task 5.5: the detector never reads ground truth (P1-09, P1-18). Static check
// over the detector's modules and over its whole require graph.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const DETECT = path.join(ROOT, 'src', 'detect');
const SCORING_ONLY = new Set(['generator.cjs', 'bench.cjs']);
const FORBIDDEN = [/labels\.csv/i, /eventLabels/, /incidents/i, /\blabels?\b/i, /bench\.cjs/, /generator\.cjs/, /node:crypto/, /require\(\s*['"]crypto['"]\s*\)/];

const detectorFiles = () => fs.readdirSync(DETECT)
  .filter((f) => f.endsWith('.cjs') && !SCORING_ONLY.has(f))
  .map((f) => path.join(DETECT, f))
  .concat([path.join(ROOT, 'src', 'cli', 'detect.cjs')]);

/** Static require() targets of a file. */
const requiresOf = (file) => [...fs.readFileSync(file, 'utf8').matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]);

test('detector modules never reference ground truth, the scorer, the generator or node:crypto', () => {
  const files = detectorFiles();
  assert.ok(files.length >= 11, `found ${files.length} detector files`);
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    for (const re of FORBIDDEN) assert.doesNotMatch(text, re, `${path.relative(ROOT, f)} matches ${re}`);
  }
});

test('detector modules import only node built-ins and each other (no packages)', () => {
  for (const f of detectorFiles()) {
    for (const r of requiresOf(f)) {
      assert.ok(r.startsWith('node:') || r.startsWith('./') || r.startsWith('../'), `${path.relative(ROOT, f)} requires package ${r}`);
    }
  }
});

test('require graph from the detector entry points never reaches generator.cjs or bench.cjs', () => {
  const seen = new Set();
  const stack = [path.join(DETECT, 'index.cjs'), path.join(ROOT, 'src', 'cli', 'detect.cjs')];
  while (stack.length) {
    const f = stack.pop();
    if (seen.has(f)) continue;
    seen.add(f);
    for (const r of requiresOf(f)) {
      if (r.startsWith('node:')) continue;
      const target = path.resolve(path.dirname(f), r);
      assert.ok(!SCORING_ONLY.has(path.basename(target)) || path.dirname(target) !== DETECT, `${path.relative(ROOT, f)} reaches ${path.relative(ROOT, target)}`);
      stack.push(target);
    }
  }
  const reached = [...seen].map((f) => path.relative(ROOT, f).split(path.sep).join('/')).sort();
  assert.ok(reached.includes('src/detect/rules-lm.cjs') && reached.includes('src/detect/ingest.cjs'));
  for (const f of reached) assert.ok(f.startsWith('src/detect/') || f === 'src/cli/detect.cjs', `unexpected module in the detector graph: ${f}`);
});
