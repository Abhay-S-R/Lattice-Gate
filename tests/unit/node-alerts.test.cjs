'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDb, tx } = require('../../src/store/db.cjs');
const schema = require('../../src/store/schema-node.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const alerts = require('../../src/node/alerts.cjs');

test('node auth-burst alert only fires on a deny, after the fifth denial', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-node-alert-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const db = openDb(path.join(dir, 'node.db'), { create: true, version: schema.VERSION, init: schema.init });
  t.after(() => db.close());
  const device = 'burst-device';
  tx(db, () => {
    for (let i = 0; i < 5; i++) audit.append(db, { gen: 0, kind: 'access', op: 'policy.probe', actor: device, decision: 'deny', rule: 'bad_signature' });
  });
  alerts.record(db, { id: 'A', body: { device_id: device, op: 'policy.probe' }, decision: { decision: 'allow', rule: 'allowed' } });
  assert.equal(db.prepare("SELECT count(*) AS n FROM audit_events WHERE kind='alert' AND rule='N-AUTH-BURST'").get().n, 0);
  tx(db, () => audit.append(db, { gen: 0, kind: 'access', op: 'policy.probe', actor: device, decision: 'deny', rule: 'bad_signature' }));
  alerts.record(db, { id: 'A', body: { device_id: device, op: 'policy.probe' }, decision: { decision: 'deny', rule: 'bad_signature' } });
  assert.equal(db.prepare("SELECT count(*) AS n FROM audit_events WHERE kind='alert' AND rule='N-AUTH-BURST'").get().n, 1);
  const detail = JSON.parse(db.prepare("SELECT detail FROM audit_events WHERE kind='alert' AND rule='N-AUTH-BURST'").get().detail);
  assert.deepEqual(detail, { severity: 'high', reason: 'repeated authentication failures within the alert window' });
  assert.equal(ids.dec(db.prepare("SELECT actor FROM audit_events WHERE kind='alert' AND rule='N-AUTH-BURST'").get().actor), device);
});
