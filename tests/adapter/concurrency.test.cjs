'use strict';
// Parallel adapter processes (Task 1.15, review focus 2; features R9 / P0-03).
// Each round: 8 processes at once. Expected every round: every process exits 0
// with the right response shape, no revocation is lost, the audit chain verifies.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runAdapter } = require('../helpers/run-adapter.cjs');
const audit = require('../../src/core/audit.cjs');
const ids = require('../../src/core/ids.cjs');
const { withState } = require('../helpers/state.cjs');

const N = 8, ROUNDS = 20;
// Under CPU emulation each process can cost ~1 s; natively ~0.1 s.
const T = { timeout: 1800000 };
const freshDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kig-conc-'));
// Hang guard per process, not a performance budget: 8 emulated processes
// starting together can take ~8 s each in the judge replica. Natively a round is < 1 s.
const PER_CALL_MS = 120000;

function check(res, label) {
  assert.equal(res.timedOut, false, `${label}: timed out`);
  assert.equal(res.code, 0, `${label}: exit ${res.code} ${res.stderr}`);
  assert.equal(res.stderr, '', label);
  return res.json;
}

const revokedActors = (dir) => withState({ stateDir: dir }, (db) =>
  new Set(db.prepare('SELECT actor FROM revoked_actors').all().map((r) => ids.dec(r.actor))));
const chainOk = (dir) => withState({ stateDir: dir }, (db) => audit.verifyChain(db));

test('warm: 8 parallel mixed read/revoke/audit after setup, x20', T, async () => {
  const dir = freshDir();
  const owners = {}, contents = {};
  for (let i = 0; i < N; i++) { owners[`a${i}`] = `u${i}`; contents[`a${i}`] = `body ${i} ✓`; }
  check(await runAdapter(dir, { op: 'setup', owners, contents, disabled: [] }), 'setup');

  const revoked = new Set();
  for (let r = 0; r < ROUNDS; r++) {
    const jobs = Array.from({ length: N }, (_, i) => {
      const kind = (i + r) % 4;
      if (kind === 0) return { req: { op: 'revoke', actor: `x${r}-${i}` }, expect: (j) => assert.deepEqual(j, {}) };
      if (kind === 3) return { req: { op: 'audit', request_id: `r${r - 1}-${i}` }, expect: (j) => assert.ok(j.decision === 'allow' || j.decision === 'deny') };
      // owners u0..u7 are never revoked, so their reads must allow throughout
      return { req: { op: 'read', actor: `u${i}`, asset: `a${i}`, request_id: `r${r}-${i}` }, expect: (j) => assert.deepEqual(j, { decision: 'allow', body: `body ${i} ✓` }) };
    });
    const results = await Promise.all(jobs.map((j) => runAdapter(dir, j.req, { timeoutMs: PER_CALL_MS })));
    results.forEach((res, i) => {
      jobs[i].expect(check(res, `round ${r} job ${i} ${jobs[i].req.op}`));
      if (jobs[i].req.op === 'revoke') revoked.add(jobs[i].req.actor);
    });
    const have = revokedActors(dir);
    for (const a of revoked) assert.ok(have.has(a), `round ${r}: lost revocation of ${a}`);
    const chain = chainOk(dir);
    assert.equal(chain.ok, true, `round ${r}: chain ${JSON.stringify(chain)}`);
  }
});

test('cold: empty dir, 8 parallel revokes of distinct actors, x20', T, async () => {
  for (let r = 0; r < ROUNDS; r++) {
    const dir = freshDir();
    const actors = Array.from({ length: N }, (_, i) => `actor-${r}-${i}`);
    const results = await Promise.all(actors.map((actor) => runAdapter(dir, { op: 'revoke', actor }, { timeoutMs: PER_CALL_MS })));
    results.forEach((res, i) => assert.deepEqual(check(res, `round ${r} revoke ${i}`), {}));
    assert.deepEqual([...revokedActors(dir)].sort(), [...actors].sort(), `round ${r}`);
    assert.equal(chainOk(dir).ok, true, `round ${r}`);
    assert.equal(chainOk(dir).count, N, `round ${r}: one revoke event each`);
  }
});

test('cold: empty dir, revokes racing reads and audits, x20', T, async () => {
  for (let r = 0; r < ROUNDS; r++) {
    const dir = freshDir();
    const jobs = Array.from({ length: N }, (_, i) => (i % 2 === 0
      ? { op: 'revoke', actor: `v${i}` }
      : i % 4 === 1 ? { op: 'read', actor: `v${i}`, asset: 'a', request_id: `q${i}` } : { op: 'audit', request_id: `q${i}` }));
    const results = await Promise.all(jobs.map((req) => runAdapter(dir, req, { timeoutMs: PER_CALL_MS })));
    results.forEach((res, i) => {
      const j = check(res, `round ${r} ${jobs[i].op}`);
      if (jobs[i].op === 'revoke') assert.deepEqual(j, {});
      if (jobs[i].op === 'read') assert.deepEqual(j, { decision: 'deny' });
      if (jobs[i].op === 'audit') assert.deepEqual(j, { request_id: jobs[i].request_id, decision: 'deny' });
    });
    const want = jobs.filter((j) => j.op === 'revoke').map((j) => j.actor).sort();
    assert.deepEqual([...revokedActors(dir)].sort(), want, `round ${r}: lost revocation`);
    assert.equal(chainOk(dir).ok, true, `round ${r}`);
  }
});
