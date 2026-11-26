'use strict';
const path = require('node:path');
const fs = require('node:fs');
const contracts = require('../core/contracts.cjs');
const provider = require('../crypto/provider.cjs');
const { encode } = require('../core/encoding.cjs');
const { ENROL } = contracts;
const registry = require('../cp/registry.cjs');
const keystore = require('../device/keystore.cjs');
const { openDb } = require('../store/db.cjs');
const schema = require('../store/schema-cp.cjs');
const { UsageError, CommandError } = require('./main.cjs');
function cpDb(home) { const l = contracts.layout(home); return openDb(l.cp.db, { create: false, version: schema.VERSION, init: schema.init }); }
module.exports = { name: 'device', describe: 'enrol and approve devices', usage: 'usage: node kig.cjs device <enrol|approve> ...', options: { home: { type: 'string' }, account: { type: 'string' }, by: { type: 'string' }, operator: { type: 'boolean' }, 'approval-id': { type: 'string' } }, run({ values, positionals, io }) {
  const home = path.resolve(values.home || contracts.kigHome());
  if (positionals[0] === 'enrol' && positionals.length === 2) {
    if (!values.account) throw new UsageError('missing --account <account>');
    const deviceId = positionals[1];
    let pub;
    try { pub = keystore.create(home, deviceId); } catch (e) { throw new CommandError('device keystore could not be created'); }
    const keys = keystore.load(home, deviceId);
    const payload = encode(ENROL.label, [values.account, deviceId, pub.signPublic, pub.kemPublic]);
    const proof = provider.sign(keys.signPrivate, ENROL.context, payload);
    const db = cpDb(home);
    try {
      registry.enrol(db, { account: values.account, device_id: deviceId, sign_pk: pub.signPublic, kem_pk: pub.kemPublic, proof });
      const l = contracts.layout(home); const policyPub = fs.readFileSync(l.anchor.cpPolicyPub); keystore.pinPolicy(home, deviceId, policyPub);
    } catch (e) { throw new CommandError(`enrolment failed (${e.message})`); } finally { db.close(); }
    io.out(`DEVICE ${deviceId} pending\n`); return 0;
  }
  if (positionals[0] === 'approve' && positionals.length === 2) {
    if (!values['approval-id']) throw new UsageError('missing --approval-id <id>');
    if (!!values.operator === !!values.by) throw new UsageError('give exactly one of --by <device> or --operator');
    let proof = null;
    if (values.by) {
      const keys = keystore.load(home, values.by);
      proof = provider.sign(keys.signPrivate, ENROL.context, registry.approvalPayload(positionals[1], values.by, values['approval-id']));
    }
    const db = cpDb(home);
    let issued;
    try {
      try { registry.approve(db, { device_id: positionals[1], approver_device: values.by || null, operator: values.operator, approval_id: values['approval-id'], proof }); }
      catch (e) { throw new CommandError(`approval denied (${e.message})`); }
      // Phase 4: an approved device receives envelopes for the active version of its account's files.
      try { issued = require('../cp/files.cjs').provisionDevice(db, positionals[1], home); }
      catch { throw new CommandError(`device ${positionals[1]} is active, but its file envelopes could not be issued; kig share <file> --with <account> re-issues them`); }
    } finally { db.close(); }
    io.out(`DEVICE ${positionals[1]} active\n`);
    if (issued.length) io.out(`PROVISIONED ${positionals[1]}: ${issued.map((f) => `${require('./text.cjs').safe(f.file_id)} v${f.version}`).join(', ')}\n`);
    return 0;
  }
  throw new UsageError('expected enrol <device> --account <account> or approve <device> --by <device>|--operator --approval-id <id>');
} };
