'use strict';
// Phase 3 M0: shared, frozen interface constants (docs/split_phase3.md §2).
// Keep behavior in the owning modules; changes here require agreement by A and B.
const os = require('node:os');
const path = require('node:path');
const { CONTEXTS } = require('../crypto/provider.cjs');

/** @typedef {'A'|'B'|'C'} NodeId */
/** @typedef {'pending'|'active'|'revoked'} DeviceStatus */
/** @typedef {{ device_id:string, account:string, sign_pk_sha256:string, kem_pk_sha256:string, status:DeviceStatus }} SnapshotDevice */
/** @typedef {{ epoch:number, issued_at_ms:number, lease_ms:number, devices:SnapshotDevice[], revoked_devices:string[], files:{file_id:string, active_version:number, cutoff:null}[], grants:{file_id:string, account:string}[] }} PolicySnapshot */
/** @typedef {{ decision:'allow'|'deny', rule:string }} Decision */
/** @typedef {{ freshHome():string, startCluster(home:string, options:{nodes:NodeId[]}):{cpUrl:string,nodeUrls:Record<NodeId,string>,stop():Promise<void>} }} ClusterTestHelpers */

const freeze = (value) => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};

const safeSegment = (value, label) => {
  if (typeof value !== 'string' || value === '.' || value === '..' ||
      !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value)) {
    throw new TypeError(`invalid ${label}`);
  }
  return value;
};

const NODE_IDS = Object.freeze(['A', 'B', 'C']);
const LOOPBACK = '127.0.0.1';
const kigHome = (env = process.env) => path.resolve(env.KIG_HOME || path.join(os.tmpdir(), 'kig-demo'));
const layout = (home) => {
  const root = path.resolve(home);
  const cpKeys = path.join(root, 'cp', 'keys');
  const operatorRecovery = path.join(root, 'operator', 'recovery.key');
  const anchor = path.join(root, 'anchor');
  const run = path.join(root, 'run');
  return freeze({
    root,
    cp: {
      db: path.join(root, 'cp', 'registry.db'),
      keys: {
        policy: { key: path.join(cpKeys, 'policy.key'), pub: path.join(cpKeys, 'policy.pub') },
        audit: { key: path.join(cpKeys, 'audit.key'), pub: path.join(cpKeys, 'audit.pub') },
        backup: { key: path.join(cpKeys, 'backup.key'), pub: path.join(cpKeys, 'backup.pub') },
        masterKem: { key: path.join(cpKeys, 'master-kem.key') },
      },
    },
    node: (id) => {
      safeSegment(id, 'node id');
      if (!NODE_IDS.includes(id)) throw new TypeError('invalid node id');
      const dir = path.join(root, 'nodes', id);
      return { dir, db: path.join(dir, 'node.db'), key: { private: path.join(dir, 'node.key'), pub: path.join(dir, 'node.pub') } };
    },
    device: (id) => {
      safeSegment(id, 'device id');
      const dir = path.join(root, 'devices', id);
      return { dir, db: path.join(dir, 'device.db') };
    },
    operator: { recoveryKey: { key: operatorRecovery } },
    anchor: {
      cpPolicyPub: path.join(anchor, 'cp-policy.pub'),
      store: (id) => path.join(anchor, `${safeSegment(id, 'store id')}.json`),
    },
    run: {
      pid: (id) => path.join(run, `${safeSegment(id, 'process id')}.pid`),
      log: (id) => path.join(run, `${safeSegment(id, 'process id')}.log`),
    },
  });
};

const ports = (env = process.env) => {
  const raw = env.KIG_PORT_BASE;
  const base = raw === undefined ? 7400 : Number(raw);
  if (!Number.isInteger(base) || base < 1 || base > 65532 || (raw !== undefined && String(base) !== String(raw))) {
    throw new TypeError('invalid KIG_PORT_BASE');
  }
  return Object.freeze({ cp: base, A: base + 1, B: base + 2, C: base + 3 });
};
const url = (port) => `http://${LOOPBACK}:${port}`;

const STORE_BASE = freeze({ tables: ['meta', 'audit_events'], metaDbIdKey: 'db_id', auditGen: 0, schemaVersion: 1 });
const SNAPSHOT = freeze({
  label: 'kig/v1/snapshot', headLabel: 'kig/v1/policy-head', ackLabel: 'kig/v1/ack',
  context: CONTEXTS.revocation, leaseMs: 5000, pullIntervalMs: 250, headNonceBytes: 16,
  fields: ['epoch', 'issued_at_ms', 'lease_ms', 'devices', 'revoked_devices', 'files', 'grants'],
  deviceFields: ['device_id', 'account', 'sign_pk_sha256', 'kem_pk_sha256', 'status'],
});
const REQUEST = freeze({
  label: 'kig/v1/request', context: CONTEXTS.request, version: 1,
  fields: ['version', 'op', 'account', 'device_id', 'resource', 'request_id', 'nonce', 'key_version'],
  nonceBytes: 32, challengeTtlMs: 30000,
});
const ENROL = freeze({ label: 'kig/v1/enrol', approvalLabel: 'kig/v1/enrol-approval', context: CONTEXTS.request });
const WRAP = freeze({ label: 'kig/v1/wrap', envelopeLabel: 'kig/v1/envelope', custodianLabel: 'kig/v1/custodian-wrap', fileAadLabel: 'kig/v1/file-aad' });
const REGISTRY_API = Object.freeze(['listDevices', 'listGrants', 'listFiles', 'getDevice']);
const SNAPSHOT_API = Object.freeze(['buildSnapshot', 'publish', 'current']);
const TABLES = freeze({
  registry: { A: ['snapshots', 'node_acks'], B: ['accounts', 'devices', 'approvals', 'files', 'file_versions', 'grants', 'envelopes', 'custodian_wraps'] },
  node: { A: ['policy', 'lease'], B: ['challenges', 'used_nonces', 'ciphertexts', 'node_envelopes'] },
  device: { A: [], B: ['keys', 'pinned'] },
});
const HTTP = freeze({ maxBodyBytes: 1024 * 1024, decisionStatus: 200, malformedStatus: 400, timeoutMs: 5000 });
const ROUTES = freeze({
  cp: { health: 'GET /v1/health', policyHead: 'GET /v1/policy/head', policyPull: 'POST /v1/policy/pull', policyAck: 'POST /v1/policy/ack', enrol: 'POST /v1/devices/enrol', revoke: 'POST /v1/devices/revoke' },
  node: { health: 'GET /v1/health', policyHead: 'GET /v1/policy/head', policyPull: 'POST /v1/policy/pull', challenge: 'GET /v1/challenge', authenticate: 'POST /v1/auth', fileRead: 'POST /v1/files/read' },
});
const RULES = freeze({
  leaseExpired: 'lease_expired', unknownDevice: 'unknown_device', deviceRevoked: 'device_revoked',
  nonceUnknown: 'nonce_unknown', nonceExpired: 'nonce_expired', nonceReused: 'nonce_reused',
  badSignature: 'bad_signature', oldKeyVersion: 'old_key_version', notGranted: 'not_granted', allowed: 'allowed',
});
const DEVICE_STATUS = Object.freeze(['pending', 'active', 'revoked']);
const COMMANDS = freeze({
  A: ['up', 'down', 'status', 'policy', 'revoke', 'bench', 'node'],
  B: ['init', 'account', 'device', 'file', 'share'],
});
const TEST_HELPERS = Object.freeze(['freshHome', 'startCluster']);

module.exports = freeze({
  kigHome, layout, ports, url, LOOPBACK, NODE_IDS, STORE_BASE, SNAPSHOT, REQUEST,
  ENROL, WRAP, REGISTRY_API, SNAPSHOT_API, TABLES, HTTP, ROUTES, RULES,
  DEVICE_STATUS, COMMANDS, TEST_HELPERS,
});
