'use strict';
// Task 2.2: kig verify-log (features P1-08, architecture §14.3).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { runKig } = require('../helpers/run-kig.cjs');
const { makeStore, tamperedCopy, INJECTION } = require('../helpers/audit-fixture.cjs');
const { openReadOnly, StateError } = require('../../src/store/db.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');

const OK = /^OK (\d+) ([0-9a-f]{64})\n$/;

test('openReadOnly: missing file → StateError missing, file not created', () => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kig-ro-')), 'nope.db');
  assert.throws(() => openReadOnly(p), (e) => e instanceof StateError && e.kind === 'missing');
  assert.equal(fs.existsSync(p), false);
});

test('openReadOnly: writes are refused', async () => {
  const { dbPath } = await makeStore();
  const db = openReadOnly(dbPath);
  assert.throws(() => db.exec("INSERT INTO meta (k, v) VALUES ('x', 'y')"));
  db.close();
});

test('untouched store: OK <count> <head>, exit 0', async () => {
  const { dbPath } = await makeStore();
  const r = runKig(['verify-log', '--db', dbPath]);
  assert.equal(r.code, 0, r.stderr);
  const m = OK.exec(r.stdout);
  assert.ok(m, r.stdout);
  const db = openReadOnly(dbPath);
  const v = audit.verifyChain(db);
  db.close();
  assert.equal(Number(m[1]), v.count);
  assert.equal(m[2], v.head.toString('hex'));
});

test('--adapter <stateDir> resolves the adapter store', async () => {
  const { ctx } = await makeStore();
  const r = runKig(['verify-log', '--adapter', ctx.stateDir]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, OK);
});

test('verify-log does not modify the store', async () => {
  const { dbPath } = await makeStore();
  const before = fs.readFileSync(dbPath);
  runKig(['verify-log', '--db', dbPath]);
  assert.ok(fs.readFileSync(dbPath).equals(before));
});

test('edited row → BROKEN seq=N content_edit, exit 1', async () => {
  const { dbPath } = await makeStore();
  const copy = tamperedCopy(dbPath, (db) => db.exec("UPDATE audit_events SET decision = 'allow' WHERE seq = 3"));
  const r = runKig(['verify-log', '--db', copy]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, 'BROKEN seq=3 content_edit\n');
});

test('edited actor (client string) → content_edit', async () => {
  const { dbPath } = await makeStore();
  const copy = tamperedCopy(dbPath, (db) => db.prepare('UPDATE audit_events SET actor = ? WHERE seq = 2').run(ids.enc('bob')));
  assert.equal(runKig(['verify-log', '--db', copy]).stdout, 'BROKEN seq=2 content_edit\n');
});

test('deleted row → missing_or_reordered at the gap', async () => {
  const { dbPath } = await makeStore();
  const copy = tamperedCopy(dbPath, (db) => db.exec('DELETE FROM audit_events WHERE seq = 4'));
  const r = runKig(['verify-log', '--db', copy]);
  assert.equal(r.code, 1);
  assert.equal(r.stdout, 'BROKEN seq=4 missing_or_reordered\n');
});

test('reordered rows → missing_or_reordered', async () => {
  const { dbPath } = await makeStore();
  const copy = tamperedCopy(dbPath, (db) => {
    db.exec('UPDATE audit_events SET seq = -1 WHERE seq = 2');
    db.exec('UPDATE audit_events SET seq = 2 WHERE seq = 3');
    db.exec('UPDATE audit_events SET seq = 3 WHERE seq = -1');
  });
  assert.equal(runKig(['verify-log', '--db', copy]).stdout, 'BROKEN seq=2 missing_or_reordered\n');
});

test('injection actor stays one event with the true actor', async () => {
  const { dbPath } = await makeStore();
  const db = openReadOnly(dbPath);
  const access = db.prepare("SELECT actor FROM audit_events WHERE request_id = ? AND kind = 'access'").all(ids.enc('r3'));
  const alertsRows = db.prepare("SELECT actor, rule FROM audit_events WHERE request_id = ? AND kind = 'alert'").all(ids.enc('r3'));
  const spoofed = db.prepare("SELECT count(*) AS n FROM audit_events WHERE actor = ?").get(ids.enc('admin')).n;
  db.close();
  assert.equal(access.length, 1);
  assert.equal(ids.dec(access[0].actor), INJECTION);
  assert.ok(alertsRows.some((a) => a.rule === 'A-HOSTILE-ID'));
  for (const a of alertsRows) assert.equal(ids.dec(a.actor), INJECTION);
  assert.equal(spoofed, 0);
  assert.match(runKig(['verify-log', '--db', dbPath]).stdout, OK);
});

test('missing --db/--adapter → exit 2; both → exit 2', async () => {
  assert.equal(runKig(['verify-log']).code, 2);
  const { ctx, dbPath } = await makeStore();
  assert.equal(runKig(['verify-log', '--db', dbPath, '--adapter', ctx.stateDir]).code, 2);
});

test('nonexistent store → exit 1, nothing created', () => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kig-vl-')), 'nope.db');
  const r = runKig(['verify-log', '--db', p]);
  assert.equal(r.code, 1);
  assert.match(r.stderr, /no audit store/i);
  assert.equal(fs.existsSync(p), false);
});

test('not a database → exit 1, one line', () => {
  const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'kig-vl-')), 'junk.db');
  fs.writeFileSync(p, 'not sqlite at all, just text '.repeat(200));
  const r = runKig(['verify-log', '--db', p]);
  assert.equal(r.code, 1);
  assert.equal(r.stderr.trim().split('\n').length, 1);
});
