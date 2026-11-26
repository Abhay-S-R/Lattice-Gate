'use strict';
// Global constraint: only src/crypto/provider.cjs may import node:crypto.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '../..');
const ALLOWED = path.join(ROOT, 'src', 'crypto', 'provider.cjs');
const IMPORT = /require\(\s*['"](node:)?crypto['"]\s*\)|from\s+['"](node:)?crypto['"]/;

function walk(dir, out) {
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(c|m)?js$/.test(e.name)) out.push(p);
  }
  return out;
}

test('only provider.cjs imports node:crypto', () => {
  const files = walk(path.join(ROOT, 'src'), [])
    .concat(['track4_service.cjs', 'team_app.cjs', 'kig.cjs'].map((f) => path.join(ROOT, f)).filter(fs.existsSync));
  assert.ok(files.includes(ALLOWED), 'provider.cjs must exist');
  const offenders = files.filter((f) => f !== ALLOWED && IMPORT.test(fs.readFileSync(f, 'utf8')));
  assert.deepEqual(offenders.map((f) => path.relative(ROOT, f)), []);
});
