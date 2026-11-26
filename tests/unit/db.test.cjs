'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { openDb, tx, quarantine, isBusy, StateError } = require('../../src/store/db.cjs');

const DB_MODULE = path.resolve(__dirname, '../../src/store/db.cjs');
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kig-db-'));
const initT = (db) => db.exec('CREATE TABLE t (x INTEGER) STRICT');
const opts = (create) => ({ create, version: 1, init: initT });

function kindOf(fn) {
  try { fn(); } catch (e) { assert.ok(e instanceof StateError, `not a StateError: ${e && e.message}`); return e.kind; }
  assert.fail('expected a StateError');
}

test('missing file not created', () => {
  const p = path.join(tmpDir(), 'a.db');
  assert.equal(kindOf(() => openDb(p, opts(false))), 'missing');
  assert.equal(fs.existsSync(p), false);
});

test('create sets wal and version', () => {
  const p = path.join(tmpDir(), 'a.db');
  const db = openDb(p, opts(true));
  assert.equal(db.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
  assert.equal(db.prepare('PRAGMA user_version').get().user_version, 1);
  assert.equal(db.prepare('PRAGMA synchronous').get().synchronous, 2); // FULL
  assert.equal(db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
  db.close();
  const again = openDb(p, opts(false));
  assert.equal(again.prepare('SELECT count(*) AS n FROM t').get().n, 0);
  again.close();
});

test('init runs once', () => {
  const p = path.join(tmpDir(), 'a.db');
  let calls = 0;
  const o = { create: true, version: 1, init: (db) => { calls++; initT(db); } };
  openDb(p, o).close();
  openDb(p, o).close();
  assert.equal(calls, 1);
});

test('schema mismatch', () => {
  const p = path.join(tmpDir(), 'a.db');
  openDb(p, opts(true)).close();
  assert.equal(kindOf(() => openDb(p, { create: false, version: 2, init: initT })), 'schema');
  assert.equal(kindOf(() => openDb(p, { create: true, version: 2, init: initT })), 'schema');
});

test('uninitialised file opened without create is missing', () => {
  const p = path.join(tmpDir(), 'a.db');
  fs.writeFileSync(p, '');
  assert.equal(kindOf(() => openDb(p, opts(false))), 'missing');
});

test('corrupt', () => {
  const p = path.join(tmpDir(), 'a.db');
  openDb(p, opts(true)).close();
  for (const s of ['-wal', '-shm']) fs.rmSync(p + s, { force: true });
  fs.writeFileSync(p, Buffer.concat([Buffer.alloc(4096, 0), Buffer.from('garbage')]));
  assert.equal(kindOf(() => openDb(p, opts(false))), 'corrupt');
  assert.equal(kindOf(() => openDb(p, opts(true))), 'corrupt');
});

test('tx commits and returns value', () => {
  const db = openDb(path.join(tmpDir(), 'a.db'), opts(true));
  const r = tx(db, () => { db.prepare('INSERT INTO t VALUES (1)').run(); return 'ok'; });
  assert.equal(r, 'ok');
  assert.equal(db.prepare('SELECT count(*) AS n FROM t').get().n, 1);
  db.close();
});

test('tx rollback leaves no row', () => {
  const db = openDb(path.join(tmpDir(), 'a.db'), opts(true));
  assert.throws(() => tx(db, () => { db.prepare('INSERT INTO t VALUES (1)').run(); throw new Error('boom'); }), /boom/);
  assert.equal(db.isTransaction, false);
  assert.equal(db.prepare('SELECT count(*) AS n FROM t').get().n, 0);
  db.close();
});

test('tx rejects async fn', () => {
  const db = openDb(path.join(tmpDir(), 'a.db'), opts(true));
  assert.throws(() => tx(db, async () => {}), TypeError);
  assert.equal(db.isTransaction, false);
  db.close();
});

test('isBusy', () => {
  assert.equal(isBusy(Object.assign(new Error('database is locked'), { errcode: 5 })), true);
  assert.equal(isBusy(Object.assign(new Error('x'), { errcode: 5 | (2 << 8) })), true); // extended BUSY_*
  assert.equal(isBusy(Object.assign(new Error('x'), { errcode: 6 })), true);
  assert.equal(isBusy(Object.assign(new Error('no such table'), { errcode: 1 })), false);
  assert.equal(isBusy(null), false);
});

test('busy writer becomes StateError locked after retries', () => {
  const p = path.join(tmpDir(), 'a.db');
  const holder = openDb(p, opts(true));
  holder.exec('BEGIN IMMEDIATE');
  const other = openDb(p, opts(false));
  // Shrink the busy timeout so the test is quick; retries still apply.
  other.exec('PRAGMA busy_timeout = 10');
  assert.equal(kindOf(() => tx(other, () => {})), 'locked');
  holder.exec('ROLLBACK');
  holder.close(); other.close();
});

function runChild(p, i) {
  const code = `
    const { openDb, tx } = require(${JSON.stringify(DB_MODULE)});
    const db = openDb(process.argv[1], { create: true, version: 1,
      init: (d) => d.exec('CREATE TABLE t (x INTEGER) STRICT') });
    tx(db, () => db.prepare('INSERT INTO t VALUES (?)').run(Number(process.argv[2])));
    db.close();`;
  return new Promise((resolve) => {
    const c = spawn(process.execPath, ['-e', code, p, String(i)], { stdio: ['ignore', 'ignore', 'pipe'] });
    let err = '';
    c.stderr.on('data', (d) => { err += d; });
    c.on('close', (code) => resolve({ code, err }));
  });
}

test('parallel create (cold-start race, 8 children x 20 rounds)', { timeout: 180000 }, async () => {
  const N = 8, ROUNDS = 20;
  for (let r = 0; r < ROUNDS; r++) {
    const p = path.join(tmpDir(), 'race.db');
    const results = await Promise.all(Array.from({ length: N }, (_, i) => runChild(p, i)));
    for (const res of results) assert.equal(res.code, 0, `round ${r}: ${res.err}`);
    const db = openDb(p, opts(false));
    assert.equal(db.prepare('SELECT count(*) AS n FROM t').get().n, N, `round ${r}`);
    db.close();
  }
});

test('quarantine renames all three files', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'adapter.db');
  const db = openDb(p, opts(true));
  tx(db, () => db.prepare('INSERT INTO t VALUES (1)').run());
  db.close();
  // A clean close may checkpoint and remove -wal/-shm; make sure all three exist.
  for (const s of ['-wal', '-shm']) if (!fs.existsSync(p + s)) fs.writeFileSync(p + s, '');
  const q = quarantine(p);
  assert.match(path.basename(q), /^adapter\.db\.quarantine-\d+$/);
  assert.equal(fs.existsSync(p), false);
  assert.equal(fs.existsSync(p + '-wal'), false);
  assert.equal(fs.existsSync(p + '-shm'), false);
  assert.ok(fs.existsSync(q));
  assert.ok(fs.existsSync(q + '-wal'));
  assert.ok(fs.existsSync(q + '-shm'));
});

test('quarantine never overwrites an earlier quarantine', () => {
  const dir = tmpDir();
  const p = path.join(dir, 'adapter.db');
  fs.writeFileSync(p, 'one');
  const q1 = quarantine(p);
  fs.writeFileSync(p, 'two');
  const q2 = quarantine(p);
  assert.notEqual(q1, q2);
  assert.equal(fs.readFileSync(q1, 'utf8'), 'one');
  assert.equal(fs.readFileSync(q2, 'utf8'), 'two');
});
