'use strict';
// Phase 3 M0: pinned contracts between Developer A and Developer B (docs/split_phase3.md §2).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const c = require('../../src/core/contracts.cjs');
const { CONTEXTS } = require('../../src/crypto/provider.cjs');

test('contracts object is deeply frozen', () => {
  const walk = (o, p) => {
    if (o && typeof o === 'object') {
      assert.ok(Object.isFrozen(o), `${p} not frozen`);
      for (const [k, v] of Object.entries(o)) walk(v, `${p}.${k}`);
    }
  };
  walk(c, 'contracts');
});

test('C1 KIG_HOME: env override, default under os.tmpdir()', () => {
  assert.equal(c.kigHome({ KIG_HOME: '/x/y' }), path.resolve('/x/y'));
  assert.equal(c.kigHome({}), path.join(os.tmpdir(), 'kig-demo'));
});

test('C1 layout paths are fixed and stay inside KIG_HOME', () => {
  const home = path.resolve('/h');
  const L = c.layout(home);
  assert.equal(L.cp.db, path.join(home, 'cp', 'registry.db'));
  assert.equal(L.cp.keys.policy.key, path.join(home, 'cp', 'keys', 'policy.key'));
  assert.equal(L.cp.keys.policy.pub, path.join(home, 'cp', 'keys', 'policy.pub'));
  assert.equal(L.cp.keys.masterKem.key, path.join(home, 'cp', 'keys', 'master-kem.key'));
  assert.equal(L.node('B').db, path.join(home, 'nodes', 'B', 'node.db'));
  assert.equal(L.node('B').key.pub, path.join(home, 'nodes', 'B', 'node.pub'));
  assert.equal(L.device('alice-phone').db, path.join(home, 'devices', 'alice-phone', 'device.db'));
  assert.equal(L.operator.recoveryKey.key, path.join(home, 'operator', 'recovery.key'));
  assert.equal(L.anchor.cpPolicyPub, path.join(home, 'anchor', 'cp-policy.pub'));
  assert.equal(L.anchor.store('abc'), path.join(home, 'anchor', 'abc.json'));
  assert.equal(L.run.pid('A'), path.join(home, 'run', 'A.pid'));
  assert.equal(L.run.log('cp'), path.join(home, 'run', 'cp.log'));
});

test('C1 device/node/store ids that are not safe path segments are refused', () => {
  const L = c.layout(path.resolve('/h'));
  for (const bad of ['', '.', '..', '../x', 'a/b', 'a\\b', 'x\u0000', ' lead', 'a'.repeat(65), 'Ä']) {
    assert.throws(() => L.device(bad), TypeError, JSON.stringify(bad));
  }
  assert.throws(() => L.node('D'), TypeError);
  assert.throws(() => L.anchor.store('../etc'), TypeError);
  assert.doesNotThrow(() => L.device('alice-phone_2.x'));
});

test('C1 ports: loopback only, CP + A/B/C from a base', () => {
  assert.equal(c.LOOPBACK, '127.0.0.1');
  assert.deepEqual([...c.NODE_IDS], ['A', 'B', 'C']);
  assert.deepEqual({ ...c.ports() }, { cp: 7400, A: 7401, B: 7402, C: 7403 });
  assert.deepEqual({ ...c.ports({ KIG_PORT_BASE: '9100' }) }, { cp: 9100, A: 9101, B: 9102, C: 9103 });
  for (const bad of ['0', '-1', '65533', 'abc', '80.5']) assert.throws(() => c.ports({ KIG_PORT_BASE: bad }), TypeError, bad);
  assert.equal(c.url(c.ports().B), 'http://127.0.0.1:7402');
});

test('C2 every store shares the audit base; Phase 3 events use gen 0', () => {
  assert.deepEqual([...c.STORE_BASE.tables], ['meta', 'audit_events']);
  assert.equal(c.STORE_BASE.metaDbIdKey, 'db_id');
  assert.equal(c.STORE_BASE.auditGen, 0);
  assert.equal(c.STORE_BASE.schemaVersion, 1);
});

test('C3 snapshot: labels, context, defaults, field names', () => {
  assert.equal(c.SNAPSHOT.label, 'kig/v1/snapshot');
  assert.equal(c.SNAPSHOT.headLabel, 'kig/v1/policy-head');
  assert.equal(c.SNAPSHOT.ackLabel, 'kig/v1/ack');
  assert.equal(c.SNAPSHOT.context, CONTEXTS.revocation);
  assert.equal(c.SNAPSHOT.leaseMs, 5000);
  assert.equal(c.SNAPSHOT.pullIntervalMs, 250);
  assert.equal(c.SNAPSHOT.headNonceBytes, 16);
  assert.deepEqual([...c.SNAPSHOT.fields], ['epoch', 'issued_at_ms', 'lease_ms', 'devices', 'revoked_devices', 'files', 'grants']);
  assert.deepEqual([...c.SNAPSHOT.deviceFields], ['device_id', 'account', 'sign_pk_sha256', 'kem_pk_sha256', 'status']);
});

test('C4 registry read API names', () => {
  assert.deepEqual([...c.REGISTRY_API], ['listDevices', 'listGrants', 'listFiles', 'getDevice']);
  assert.deepEqual([...c.SNAPSHOT_API], ['buildSnapshot', 'publish', 'current']);
});

test('C5 table ownership: no table owned twice, base tables owned by nobody', () => {
  for (const store of ['registry', 'node', 'device']) {
    const t = c.TABLES[store];
    assert.ok(t, store);
    const all = [...t.A, ...t.B];
    assert.equal(new Set(all).size, all.length, `duplicate table in ${store}`);
    for (const base of c.STORE_BASE.tables) assert.ok(!all.includes(base), `${store}: ${base} is shared base`);
  }
  assert.deepEqual([...c.TABLES.device.A], []);
  assert.ok(c.TABLES.node.B.includes('used_nonces'));
  assert.ok(c.TABLES.registry.A.includes('snapshots'));
});

test('C6 HTTP conventions and route table', () => {
  assert.equal(c.HTTP.maxBodyBytes, 1024 * 1024);
  assert.equal(c.HTTP.decisionStatus, 200);
  assert.equal(c.HTTP.malformedStatus, 400);
  for (const routes of Object.values(c.ROUTES)) {
    const keys = Object.values(routes);
    assert.equal(new Set(keys).size, keys.length, 'duplicate route within server');
    for (const k of keys) assert.match(k, /^(GET|POST) \/v1\/[a-z/-]+$/);
  }
  assert.equal(c.ROUTES.cp.policyHead, 'GET /v1/policy/head');
  assert.equal(c.ROUTES.node.challenge, 'GET /v1/challenge');
  assert.equal(c.ROUTES.node.fileRead, 'POST /v1/files/read');
});

test('C6 decision rules are unique, lower_snake, and include every §8.2 rejection', () => {
  const rules = Object.values(c.RULES);
  assert.equal(new Set(rules).size, rules.length);
  for (const r of rules) assert.match(r, /^[a-z][a-z0-9_]*$/);
  for (const r of ['lease_expired', 'unknown_device', 'device_revoked', 'nonce_unknown', 'nonce_expired',
    'nonce_reused', 'bad_signature', 'old_key_version', 'not_granted', 'allowed']) {
    assert.ok(rules.includes(r), r);
  }
});

test('C7 request transcript', () => {
  assert.equal(c.REQUEST.label, 'kig/v1/request');
  assert.equal(c.REQUEST.context, CONTEXTS.request);
  assert.equal(c.REQUEST.version, 1);
  assert.deepEqual([...c.REQUEST.fields], ['version', 'op', 'account', 'device_id', 'resource', 'request_id', 'nonce', 'key_version']);
  assert.equal(c.REQUEST.nonceBytes, 32);
  assert.equal(c.REQUEST.challengeTtlMs, 30000);
});

test('C8 CLI command ownership: no name claimed twice', () => {
  const all = [...c.COMMANDS.A, ...c.COMMANDS.B];
  assert.equal(new Set(all).size, all.length);
  assert.ok(c.COMMANDS.A.includes('up') && c.COMMANDS.B.includes('init'));
});

test('C9 shared cluster test helper API is pinned', () => {
  assert.deepEqual([...c.TEST_HELPERS], ['freshHome', 'startCluster']);
});

test('device status values and signing contexts exist in the provider', () => {
  assert.deepEqual([...c.DEVICE_STATUS], ['pending', 'active', 'revoked']);
  for (const ctx of [c.SNAPSHOT.context, c.REQUEST.context, c.ENROL.context]) {
    assert.ok(Object.values(CONTEXTS).includes(ctx), ctx);
  }
  const labels = [c.SNAPSHOT.label, c.SNAPSHOT.headLabel, c.SNAPSHOT.ackLabel, c.REQUEST.label, c.ENROL.label, c.ENROL.approvalLabel,
    c.WRAP.label, c.WRAP.envelopeLabel, c.WRAP.custodianLabel, c.WRAP.fileAadLabel];
  assert.equal(new Set(labels).size, labels.length, 'encode labels must be distinct');
  for (const l of labels) assert.match(l, /^kig\/v1\/[a-z-]+$/);
});
