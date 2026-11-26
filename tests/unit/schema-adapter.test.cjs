'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb, tx } = require('../../src/store/db.cjs');
const schema = require('../../src/store/schema-adapter.cjs');

function fresh() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-schema-'));
  return openDb(path.join(dir, 'adapter.db'), { create: true, version: schema.VERSION, init: schema.init });
}

const insertEvent = (db) => db.prepare(
  `INSERT INTO audit_events (seq, gen, ts_ms, kind, prev_hash, hash) VALUES (1, 0, 0, 'setup', x'00', x'00')`).run();

test('VERSION matches limits', () => {
  assert.equal(schema.VERSION, 1);
  assert.equal(schema.VERSION, require('../../src/core/limits.cjs').SCHEMA_VERSION_ADAPTER);
});

test('init creates tables and meta', () => {
  const db = fresh();
  const names = db.prepare(`SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name`).all()
    .map((r) => `${r.type}:${r.name}`);
  assert.deepEqual(names, [
    'table:assets', 'index:audit_by_actor', 'index:audit_by_req', 'table:audit_events',
    'trigger:audit_no_delete', 'trigger:audit_no_update', 'table:meta', 'table:revoked_actors',
  ]);
  assert.match(schema.getMeta(db, 'db_id'), /^[0-9a-f]{32}$/);
  assert.equal(schema.getMeta(db, 'current_gen'), '0');
  assert.equal(schema.getMeta(db, 'epoch'), '0');
  db.close();
});

test('db_id differs per database', () => {
  const a = fresh(), b = fresh();
  assert.notEqual(schema.getMeta(a, 'db_id'), schema.getMeta(b, 'db_id'));
  a.close(); b.close();
});

test('setMeta and getMeta', () => {
  const db = fresh();
  tx(db, () => schema.setMeta(db, 'current_gen', '3'));
  assert.equal(schema.getMeta(db, 'current_gen'), '3');
  tx(db, () => schema.setMeta(db, 'new_key', 'v'));
  assert.equal(schema.getMeta(db, 'new_key'), 'v');
  assert.throws(() => schema.getMeta(db, 'absent'));
  db.close();
});

test('audit_events UPDATE aborts', () => {
  const db = fresh();
  insertEvent(db);
  assert.throws(() => db.exec(`UPDATE audit_events SET decision = 'allow'`), /append-only/);
  db.close();
});

test('audit_events DELETE aborts', () => {
  const db = fresh();
  insertEvent(db);
  assert.throws(() => db.exec('DELETE FROM audit_events'), /append-only/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM audit_events').get().n, 1);
  db.close();
});

test('tables are STRICT', () => {
  const db = fresh();
  assert.throws(() => db.prepare(`INSERT INTO revoked_actors (actor, source, epoch) VALUES ('"a"', 'revoke', 'abc')`).run());
  db.close();
});

test('constraints: revoked source and audit decision', () => {
  const db = fresh();
  assert.throws(() => db.prepare(`INSERT INTO revoked_actors VALUES ('"a"', 'other', 1)`).run(), /CHECK/);
  assert.throws(() => db.prepare(
    `INSERT INTO audit_events (seq, gen, ts_ms, kind, decision, prev_hash, hash) VALUES (1,0,0,'access','maybe',x'00',x'00')`).run(), /CHECK/);
  db.close();
});

test('assets owner/body nullable', () => {
  const db = fresh();
  db.prepare(`INSERT INTO assets (asset, owner, body) VALUES ('"x"', NULL, NULL)`).run();
  assert.deepEqual({ ...db.prepare('SELECT owner, body FROM assets').get() }, { owner: null, body: null });
  db.close();
});

test('adapterDbPath', () => {
  assert.equal(schema.adapterDbPath(path.join('s', 'd')), path.join('s', 'd', 'kig', 'adapter.db'));
});
