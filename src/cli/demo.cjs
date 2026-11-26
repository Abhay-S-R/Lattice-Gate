'use strict';
// `kig demo`: 12 narrated steps covering all Track 4 goals (architecture §17.2, Phase 7 Task 7.2).
// Never imports node:crypto directly; uses src/crypto/provider.cjs and real CLI/core modules.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const provider = require('../crypto/provider.cjs');
const wrap = require('../core/wrap.cjs');
const { encode } = require('../core/encoding.cjs');
const ids = require('../core/ids.cjs');
const { openReadOnly } = require('../store/db.cjs');
const { NODE_IDS, ROTATION, layout, ports, url } = require('../core/contracts.cjs');
const client = require('../device/client.cjs');
const deviceFiles = require('../device/files.cjs');
const keystore = require('../device/keystore.cjs');
const nodePolicy = require('../node/policy.cjs');
const supervisor = require('./supervisor.cjs');
const { crashCpAt } = require('./crash-test.cjs');
const { UsageError } = require('./main.cjs');

const REPO = path.resolve(__dirname, '..', '..');
const KIG = path.join(REPO, 'kig.cjs');
const SERVICE = path.join(REPO, 'track4_service.cjs');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, what, ms = 12000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() >= end) throw new Error(`timed out waiting for ${what}`);
    await sleep(40);
  }
}

async function reserveBase() {
  for (let i = 0; i < 24; i++) {
    const base = 15000 + (provider.random(4).readUInt32BE(0) % 10000);
    const open = [];
    try {
      for (let p = base; p < base + 4; p++) {
        const s = net.createServer();
        open.push(s);
        await new Promise((ok, no) => s.once('error', no).listen(p, '127.0.0.1', ok));
      }
      await Promise.all(open.map((s) => new Promise((ok) => s.close(ok))));
      return base;
    } catch {
      await Promise.all(open.filter((s) => s.listening).map((s) => new Promise((ok) => s.close(ok))));
    }
  }
  throw new Error('could not reserve four consecutive loopback ports');
}

function findPracticeDir(explicit) {
  if (explicit) {
    const p = path.resolve(explicit);
    return fs.existsSync(path.join(p, 'events.csv')) && fs.existsSync(path.join(p, 'approvals.json')) ? p : null;
  }
  const candidates = [
    process.env.TOOLKIT_DIR ? path.resolve(process.env.TOOLKIT_DIR, 'practice') : null,
    '/toolkit/practice',
    path.resolve(REPO, '..', 'Track-4-Toolkit', 'practice'),
  ].filter(Boolean);
  return candidates.find((d) => fs.existsSync(path.join(d, 'events.csv')) && fs.existsSync(path.join(d, 'approvals.json'))) || null;
}

function walkDbFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkDbFiles(full));
    else if (ent.name.endsWith('.db') || ent.name.endsWith('.db-wal')) out.push(full);
  }
  return out;
}

function gitShortCommit() {
  const r = spawnSync('git', ['-C', REPO, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : 'nogit';
}

const STEP_DEFS = [
  { n: 1, title: 'Cluster initialization and startup', goal: 'setup' },
  { n: 2, title: 'Device enrolment and second-factor approval', goal: '2' },
  { n: 3, title: 'Post-quantum file encryption, sharing, and multi-node reads', goal: 'confidentiality' },
  { n: 4, title: 'Versioned key rotation with in-flight grace and hard cutoff', goal: '1' },
  { n: 5, title: 'Lost device revocation across all service nodes', goal: '2' },
  { n: 6, title: 'Replacement device re-enrolment and peer continuity', goal: '2' },
  { n: 7, title: 'Control-plane crash during rotation and journal recovery', goal: '3' },
  { n: 8, title: 'Signed, encrypted backups and anti-rollback restore', goal: '4' },
  { n: 9, title: 'Offline audit-log verification and log-injection resistance', goal: '5' },
  { n: 10, title: 'Explainable privilege & lateral-movement detection + benchmark', goal: '6, 7, 8' },
  { n: 11, title: 'Post-quantum E2EE messaging, replay, loss/reordering, forward secrecy', goal: '9, 10, 11, 12' },
  { n: 12, title: 'Security self-monitoring alerts across cluster and adapter', goal: 'self-monitoring' },
];

async function runDemo({ values, io }) {
  const fast = Boolean(values.fast);
  const keep = Boolean(values.keep);
  const jsonOut = Boolean(values.json);
  const seed = values.seed === undefined ? 2026 : Number(values.seed);
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) {
    throw new UsageError('--seed must be an integer from 0 to 4294967295');
  }

  const startedUtc = new Date().toISOString();
  const demoStartMs = Date.now();
  const ownHome = !values.home;
  const home = values.home ? path.resolve(values.home) : fs.mkdtempSync(path.join(os.tmpdir(), 'kig-demo-run-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-demo-work-'));
  const portBase = await reserveBase();
  const kenv = { KIG_HOME: home, KIG_PORT_BASE: String(portBase) };
  const env = { ...process.env, ...kenv };
  delete env.NODE_TEST_CONTEXT;

  const L = layout(home);
  const nodeUrls = Object.fromEntries(NODE_IDS.map((id) => [id, url(ports(kenv)[id])]));
  let reqSeq = 0;
  let clusterUp = false;

  const kig = (args, timeoutMs = 90000) => {
    const r = spawnSync(process.execPath, [KIG, ...args], {
      cwd: REPO, env, encoding: 'utf8', timeout: timeoutMs,
    });
    return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
  };
  const ok = (args, timeoutMs) => {
    const r = kig(args, timeoutMs);
    assert.equal(r.code, 0, `kig ${args.join(' ')} failed (${r.code}): ${r.stderr || r.stdout}`);
    return r;
  };
  const req = (node, device, account, op, v) => client.request(nodeUrls[node], L.device(device).dir, op, {
    home, version: 1, op, account, device_id: device, resource: 'brief',
    request_id: `demo-${++reqSeq}`, key_version: v,
  });
  const fetchChunk = (node, transferId, idx) => client.transferChunk(nodeUrls[node], transferId, idx);
  const readDecrypted = async (node, device, account, v) => {
    const r = await until(async () => {
      const ans = await req(node, device, account, 'file.read', v);
      return ans.decision === 'allow' ? ans : null;
    }, `${device} reading v${v} via node ${node}`);
    return deviceFiles.read(home, device, r);
  };
  const cpQuery = (fn) => {
    const db = openReadOnly(L.cp.db);
    try { return fn(db); } finally { db.close(); }
  };
  const cpEpoch = () => cpQuery((db) => Number(db.prepare("SELECT v FROM meta WHERE k='epoch'").get().v));
  const nodeState = (id) => {
    const db = openReadOnly(L.node(id).db);
    try { return nodePolicy.current(db); } finally { db.close(); }
  };

  // Shared across steps.
  const plaintext = Buffer.from(`KIG-DEMO-SECRET-${provider.random(20000).toString('hex')}`, 'utf8'); // ~40 KB (3 chunks)
  let phoneV1 = null;
  const oldBackup = path.join(work, 'backup-step3');
  const adapterStateDir = path.join(work, 'adapter-state');

  const steps = STEP_DEFS.map((d) => ({ ...d, status: 'NOT_RUN', details: [], duration_ms: 0 }));

  const say = (line) => { if (!jsonOut) io.out(`${line}\n`); };

  const stepFns = [
    // Step 1
    async (detail) => {
      ok(['init', '--force']);
      ok(['up']);
      clusterUp = true;
      const st = ok(['status']);
      assert.match(st.stdout, /healthy/i);
      await until(() => NODE_IDS.every((id) => {
        const s = nodeState(id);
        return s.lease_valid && s.applied_epoch >= 1;
      }), 'all nodes applying initial snapshot');
      const epochs = NODE_IDS.map((id) => `${id}=epoch:${nodeState(id).applied_epoch}`).join(', ');
      detail(`CP + nodes A, B, C healthy on loopback base ${portBase} (${epochs})`);
    },

    // Step 2
    async (detail) => {
      ok(['account', 'add', 'alice']);
      ok(['device', 'enrol', 'alice-phone', '--account', 'alice']);
      ok(['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'demo-alice-1']);
      ok(['device', 'enrol', 'alice-laptop', '--account', 'alice']);
      ok(['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'demo-alice-2']);
      ok(['account', 'add', 'bob']);
      ok(['device', 'enrol', 'bob-laptop', '--account', 'bob']);
      ok(['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'demo-bob-1']);
      await until(() => NODE_IDS.every((id) => {
        const devs = nodeState(id).snapshot?.devices || [];
        return ['alice-phone', 'alice-laptop', 'bob-laptop'].every((d) => devs.some((x) => x.device_id === d && x.status === 'active'));
      }), 'enrolled devices active on all nodes');
      detail('enrolled & activated alice-phone, alice-laptop (peer-device approved), and bob-laptop across A, B, C');
    },

    // Step 3
    async (detail) => {
      const input = path.join(work, 'brief.txt');
      fs.writeFileSync(input, plaintext);
      ok(['file', 'publish', 'brief', '--as', 'alice-phone', '--input', input]);
      ok(['share', 'brief', '--with', 'bob']);
      for (const id of NODE_IDS) {
        const pt = await readDecrypted(id, 'bob-laptop', 'bob', 1);
        assert.ok(pt.equals(plaintext), `Bob decrypted mismatch on node ${id}`);
      }
      phoneV1 = await req('A', 'alice-phone', 'alice', 'file.read', 1);
      assert.equal(phoneV1.decision, 'allow');
      // Verify zero plaintext leakage across all SQLite files in KIG_HOME.
      const probeSlice = plaintext.subarray(0, 48);
      for (const dbFile of walkDbFiles(home)) {
        assert.equal(fs.readFileSync(dbFile).includes(probeSlice), false, `plaintext found in ${dbFile}`);
      }
      ok(['backup', '--out', oldBackup]);
      detail(`published "brief" (${plaintext.length} B, 3 chunks), Bob decrypted v1 via A/B/C; 0 plaintext bytes in any DB`);
    },

    // Step 4
    async (detail) => {
      const inflight = await req('A', 'bob-laptop', 'bob', 'file.transfer', 1);
      assert.equal(inflight.decision, 'allow');
      assert.equal(inflight.chunk_count, 3);
      const parts = [await fetchChunk('A', inflight.transfer_id, 0)];

      const rot = ok(['rotate', '--file', 'brief']);
      const cutoffAt = Date.now();
      assert.match(rot.stdout, /^ROTATED "brief" 1 -> 2 epoch=\d+ \(complete/);

      for (const idx of [1, 2]) {
        const c = await fetchChunk('A', inflight.transfer_id, idx);
        assert.equal(c.rule, 'grace');
        parts.push(c);
      }
      assert.ok(deviceFiles.readTransfer(home, 'bob-laptop', inflight, parts).equals(plaintext));

      for (const id of NODE_IDS) {
        assert.equal((await req(id, 'bob-laptop', 'bob', 'file.transfer', 1)).rule, 'old_key_version');
        assert.equal((await req(id, 'bob-laptop', 'bob', 'file.read', 1)).rule, 'old_key_version');
        assert.ok((await readDecrypted(id, 'bob-laptop', 'bob', 2)).equals(plaintext));
        const cut = nodeState(id).snapshot.files.find((f) => f.file_id === 'brief').cutoff;
        assert.deepEqual([cut.old_version, cut.grace_ms], [1, ROTATION.graceMs]);
      }
      detail('in-flight v1 transfer finished under 30 s grace; new v1 requests rejected (old_key_version) on A, B, C; v2 active');

      if (fast) {
        detail('grace expiry wait: not waited (--fast)');
      } else {
        await sleep(Math.max(0, ROTATION.graceMs + 1200 - (Date.now() - cutoffAt)));
        const late = await fetchChunk('A', inflight.transfer_id, 0);
        assert.equal(late.decision, 'deny');
        assert.ok(late.rule === 'grace_expired' || (late.rule === 'transfer_terminated' && late.reason === 'grace_expired'));
        detail('after 30 s grace cutoff: old v1 transfer terminated with grace_expired');
      }
    },

    // Step 5
    async (detail) => {
      const lost = ok(['lost', '--device', 'alice-phone']);
      const firstLine = lost.stdout.trim().split(/\r?\n/)[0];
      assert.match(lost.stdout, /^LOST "alice-phone": revoked at epoch \d+; signed node acks after A [\d.]+ ms, B [\d.]+ ms, C [\d.]+ ms/);
      assert.match(lost.stdout, /ROTATED "brief" 2 -> 3 epoch=\d+ \(complete/);
      for (const id of NODE_IDS) {
        assert.equal((await req(id, 'alice-phone', 'alice', 'file.read', 3)).rule, 'device_revoked');
      }
      detail(firstLine);
      detail('alice-phone denied (device_revoked) on A, B, C; "brief" automatically re-keyed 2 -> 3');
    },

    // Step 6
    async (detail) => {
      ok(['device', 'enrol', 'alice-phone-2', '--account', 'alice']);
      for (const id of NODE_IDS) {
        assert.equal((await req(id, 'alice-phone-2', 'alice', 'file.read', 3)).rule, 'unknown_device');
      }
      const badApprove = kig(['device', 'approve', 'alice-phone-2', '--by', 'alice-phone', '--approval-id', 'demo-bad']);
      assert.equal(badApprove.code, 1);
      assert.match(badApprove.stderr, /approver_not_active/);

      const goodApprove = ok(['device', 'approve', 'alice-phone-2', '--by', 'alice-laptop', '--approval-id', 'demo-phone-2']);
      assert.match(goodApprove.stdout, /PROVISIONED alice-phone-2: "brief" v3/);

      for (const id of NODE_IDS) {
        assert.ok((await readDecrypted(id, 'alice-phone-2', 'alice', 3)).equals(plaintext));
        assert.ok((await readDecrypted(id, 'bob-laptop', 'bob', 3)).equals(plaintext));
      }
      const bobV3 = await req('C', 'bob-laptop', 'bob', 'file.read', 3);
      const oldDek = wrap.kemUnwrap(
        keystore.load(home, 'alice-phone').kemPrivate,
        phoneV1.envelope,
        ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope'],
      );
      assert.throws(() => provider.aeadOpen(
        oldDek,
        Buffer.from(bobV3.nonce, 'base64'),
        encode('kig/v1/file-aad', ['brief', 3, 'kig/v1/file']),
        Buffer.from(bobV3.ciphertext, 'base64'),
      ));
      detail('pending device denied; lost-phone approval refused; alice-laptop approved replacement; Bob & alice-phone-2 read v3; old v1 DEK fails on v3');
    },

    // Step 7
    async (detail) => {
      const epochBefore = cpEpoch();
      const killed = await crashCpAt(home, kenv, 'before_commit', 'brief');
      assert.equal(killed.died, true, 'CP did not SIGKILL at before_commit');
      const crashedRot = cpQuery((db) => db.prepare("SELECT rotation_id, to_version FROM rotation_journal WHERE phase='STAGE' ORDER BY rowid DESC LIMIT 1").get());
      assert.equal(crashedRot.to_version, 4);

      await supervisor.restartService(home, kenv, 'cp');
      await until(() => cpQuery((db) => db.prepare("SELECT 1 FROM rotation_journal WHERE rotation_id=? AND phase='ABORTED'").get(crashedRot.rotation_id)), 'recovery aborting uncommitted v4');
      assert.equal(cpQuery((db) => db.prepare('SELECT active_version FROM files WHERE file_id=?').get(ids.enc('brief')).active_version), 3);
      assert.ok(cpEpoch() >= epochBefore);
      for (const id of NODE_IDS) {
        await until(() => nodeState(id).lease_valid, `node ${id} lease refresh`);
        assert.equal(nodeState(id).snapshot.files.find((f) => f.file_id === 'brief').active_version, 3);
        assert.equal((await req(id, 'alice-phone', 'alice', 'file.read', 3)).rule, 'device_revoked');
        assert.ok((await readDecrypted(id, 'bob-laptop', 'bob', 3)).equals(plaintext));
      }
      detail('CP SIGKILLed at before_commit (v4 staged); restart aborted v4, kept v3 active, preserved alice-phone revocation and Bob access on A/B/C');
    },

    // Step 8
    async (detail) => {
      const currentBackup = path.join(work, 'backup-current');
      ok(['backup', '--out', currentBackup]);
      ok(['down']);
      clusterUp = false;

      const liveHex = () => fs.readFileSync(L.cp.db).toString('hex');
      const baselineHex = liveHex();

      const flipped = path.join(work, 'bk-flipped');
      fs.cpSync(currentBackup, flipped, { recursive: true });
      { const p = path.join(flipped, 'payload.bin'); const b = fs.readFileSync(p); b[64] ^= 0x80; fs.writeFileSync(p, b); }

      const truncated = path.join(work, 'bk-truncated');
      fs.cpSync(currentBackup, truncated, { recursive: true });
      { const p = path.join(truncated, 'payload.bin'); fs.writeFileSync(p, fs.readFileSync(p).subarray(0, 4096)); }

      const badSig = path.join(work, 'bk-badsig');
      fs.cpSync(currentBackup, badSig, { recursive: true });
      { const p = path.join(badSig, 'manifest.sig'); const b = fs.readFileSync(p); b[10] ^= 0x01; fs.writeFileSync(p, b); }

      const tryRestore = (dir) => kig(['restore', dir, '--recovery-key', L.operator.recoveryKey.key, '--anchor', path.join(home, 'anchor', 'keys.json')]);
      for (const [dir, cat] of [[badSig, 'bad_signature'], [flipped, 'digest_mismatch'], [truncated, 'digest_mismatch'], [oldBackup, 'stale_backup']]) {
        const r = tryRestore(dir);
        assert.equal(r.code, 1);
        assert.match(r.stderr, new RegExp(`RESTORE REFUSED: ${cat}`));
        assert.equal(liveHex(), baselineHex, `${cat} mutated live registry.db`);
      }

      const good = tryRestore(currentBackup);
      assert.equal(good.code, 0, good.stderr);
      ok(['up']);
      clusterUp = true;
      for (const id of NODE_IDS) {
        assert.ok((await readDecrypted(id, 'bob-laptop', 'bob', 3)).equals(plaintext));
      }
      detail('refused bad_signature, flipped & truncated payload (digest_mismatch), and older epoch (stale_backup) with live DB unchanged; valid restore succeeded');
    },

    // Step 9
    async (detail) => {
      const stores = [L.cp.db, ...NODE_IDS.map((id) => L.node(id).db)];
      for (const s of stores) {
        const v = ok(['verify-log', '--db', s]);
        assert.match(v.stdout, /^OK \d+ [0-9a-f]{64}/);
      }

      // Tamper a copy (never the live store, P7-D9).
      const copyDb = path.join(work, 'tampered-copy.db');
      {
        const db = openReadOnly(L.cp.db);
        try { db.prepare('VACUUM INTO ?').run(copyDb); } finally { db.close(); }
      }
      {
        const rw = new DatabaseSync(copyDb);
        try {
          rw.exec('DROP TRIGGER IF EXISTS audit_no_update');
          rw.exec("UPDATE audit_events SET rule = '\"forged\"' WHERE seq = 2");
        } finally { rw.close(); }
      }
      const broken = kig(['verify-log', '--db', copyDb]);
      assert.equal(broken.code, 1);
      assert.match(broken.stdout, /^BROKEN seq=2 content_edit/);
      assert.match(ok(['verify-log', '--db', L.cp.db]).stdout, /^OK /);

      // Log-injection test on an isolated Round 1 adapter store (also feeds Step 12 alerts).
      fs.mkdirSync(adapterStateDir, { recursive: true, mode: 0o700 });
      const callAd = (obj) => {
        const r = spawnSync(process.execPath, [SERVICE], {
          cwd: REPO, env: { ...process.env, TRACK4_STATE_DIR: adapterStateDir },
          input: JSON.stringify(obj), encoding: 'utf8', timeout: 15000,
        });
        assert.equal(r.status, 0);
        return JSON.parse(r.stdout);
      };
      const injActor = 'mallory\n{"actor":"admin","decision":"allow"}';
      callAd({ op: 'setup', owners: { doc: 'alice' }, contents: { doc: 'x' }, disabled: ['revoked-u'] });
      callAd({ op: 'read', actor: injActor, asset: 'doc', request_id: 'inj-1' });
      callAd({ op: 'read', actor: 'revoked-u', asset: 'doc', request_id: 'rev-1' });
      assert.match(ok(['verify-log', '--adapter', adapterStateDir]).stdout, /^OK /);
      {
        const adb = openReadOnly(path.join(adapterStateDir, 'kig', 'adapter.db'));
        try {
          const row = adb.prepare("SELECT actor FROM audit_events WHERE kind='access' AND request_id=?").get(ids.enc('inj-1'));
          assert.equal(ids.dec(row.actor), injActor);
        } finally { adb.close(); }
      }
      detail('CP + 3 node logs verified OK; edited copy flagged BROKEN seq=2 content_edit; newline-JSON actor injection stayed a single record');
    },

    // Step 10
    async (detail) => {
      const practice = findPracticeDir(values.practice);
      if (!practice) throw new Error('practice data not found (set TOOLKIT_DIR or pass --practice <dir>)');
      const det = ok(['detect', '--events', path.join(practice, 'events.csv'), '--approvals', path.join(practice, 'approvals.json'), '--json']);
      const parsed = JSON.parse(det.stdout);
      assert.equal(parsed.rejects.length, 0);
      assert.equal(parsed.timeline.length, 22);
      assert.equal(parsed.alerts.length, 2);
      assert.equal(parsed.alerts[0].rule_id, 'PRIV-1');
      assert.deepEqual(parsed.alerts[0].event_ids, ['evt-008', 'evt-009']);
      assert.equal(parsed.alerts[1].rule_id, 'LM-1');
      assert.deepEqual(parsed.alerts[1].event_ids, ['evt-010', 'evt-011', 'evt-012']);
      const idx13 = parsed.timeline.findIndex((e) => e.event_id === 'evt-013');
      const idx14 = parsed.timeline.findIndex((e) => e.event_id === 'evt-014');
      assert.ok(idx13 >= 0 && idx13 < idx14, 'evt-013 must precede evt-014 in event-time timeline');
      const e15 = parsed.timeline.find((e) => e.event_id === 'evt-015');
      assert.equal(e15.corrected_time_utc, '2026-01-15T09:06:01.000Z');
      assert.equal(e15.delivery_delay_ms, 200);

      const benchOut = path.join(work, 'detect-demo-bench.json');
      const bd = ok(['bench', 'detect', '--seeds', '101', '--holdout', '201,202', '--out', benchOut, '--json']);
      const bjson = JSON.parse(bd.stdout);
      const h = bjson.holdout;
      detail(`practice 22 events -> PRIV-1 (evt-008..009) & LM-1 (evt-010..012), evt-013/014 reordered, evt-015 corrected (+2000 ms -> 200 ms delay)`);
      detail(`synthetic holdout (seeds 201,202): incident F1=${h.incident.f1.toFixed(3)}, median TTA=${Math.round(h.median_tta_ms)} ms, false alerts/1k benign=${h.false_alerts_per_1000_benign.toFixed(2)}`);
    },

    // Step 11
    async (detail) => {
      const m = ok(['msg', 'demo', '--seed', String(seed)]);
      const lines = m.stdout.trim().split(/\r?\n/);
      const passes = lines.filter((l) => l.startsWith('PASS '));
      assert.equal(passes.length, 12);
      assert.ok(lines.includes('Session resumption: NOT SUPPORTED (D-05)'));
      detail(`12/12 messaging checks passed (seed ${seed}): mutual PQ handshake, AAD recipient binding, replay cache, chunked loss/reordering, forward secrecy`);
      detail('Goal 12 session resumption: NOT SUPPORTED (D-05) — old session IDs/keys after close or revocation rejected');
    },

    // Step 12
    async (detail) => {
      const clusterAlerts = JSON.parse(ok(['alerts', '--json']).stdout);
      assert.ok(clusterAlerts.length >= 1, 'expected cluster self-monitoring alerts from revoked-device probes');
      const adapterAlertsTxt = ok(['alerts', '--adapter', adapterStateDir]).stdout;
      assert.match(adapterAlertsTxt, /A-REVOKED-RETRY/);
      assert.match(adapterAlertsTxt, /A-HOSTILE-ID/);
      assert.equal(/[\x00-\x08\x0b-\x1f\x7f]/.test(adapterAlertsTxt), false, 'unescaped control character in alerts output');
      detail(`collected ${clusterAlerts.length} cluster alert(s) + adapter A-REVOKED-RETRY & A-HOSTILE-ID (all untrusted IDs terminal-escaped)`);
    },
  ];

  let failedStep = null;
  try {
    say(`KIG Round 2 Demo (commit ${gitShortCommit()}, seed ${seed}${fast ? ', --fast' : ''})`);
    for (let i = 0; i < STEP_DEFS.length; i++) {
      const s = steps[i];
      const t0 = Date.now();
      say(`\n[${s.n}/12] ${s.title} (Goal: ${s.goal})`);
      try {
        await stepFns[i]((msg) => {
          s.details.push(msg);
          say(`       ${msg}`);
        });
        s.duration_ms = Date.now() - t0;
        s.status = 'PASS';
        say(`       PASS step ${s.n} (${(s.duration_ms / 1000).toFixed(1)} s)`);
      } catch (e) {
        s.duration_ms = Date.now() - t0;
        s.status = 'FAIL';
        const reason = String(e && e.message || e).split(/\r?\n/)[0];
        s.details.push(`error: ${reason}`);
        say(`       FAIL step ${s.n}: ${reason}`);
        failedStep = s;
        break;
      }
    }
  } finally {
    if (clusterUp) await supervisor.stop(home, kenv).catch(() => {});
    if (ownHome && !keep) fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(work, { recursive: true, force: true });
  }

  const totalMs = Date.now() - demoStartMs;
  const passedCount = steps.filter((s) => s.status === 'PASS').length;
  const report = {
    commit: gitShortCommit(),
    started_utc: startedUtc,
    duration_ms: totalMs,
    fast,
    seed,
    pass: failedStep === null && passedCount === 12,
    passed_steps: passedCount,
    total_steps: 12,
    steps,
  };

  if (jsonOut) {
    io.out(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    say('\n==================== DEMO SUMMARY ====================');
    for (const s of steps) {
      say(`  [${s.status.padEnd(7)}] Step ${String(s.n).padStart(2, ' ')}: ${s.title}`);
    }
    say(`RESULT: ${passedCount}/12 PASS in ${(totalMs / 1000).toFixed(1)} s${keep ? ` (kept home: ${home})` : ''}`);
  }
  return report.pass ? 0 : 1;
}

module.exports = {
  name: 'demo',
  describe: 'run the 12-step narrated KIG end-to-end demonstration (architecture §17.2)',
  usage: 'usage: node kig.cjs demo [--home <dir>] [--keep] [--fast] [--json] [--practice <dir>] [--seed <uint32>]',
  options: {
    home: { type: 'string' },
    keep: { type: 'boolean', default: false },
    fast: { type: 'boolean', default: false },
    json: { type: 'boolean', default: false },
    practice: { type: 'string' },
    seed: { type: 'string' },
  },
  async run({ values, positionals, io }) {
    if (positionals.length) throw new UsageError('unexpected positional argument');
    return runDemo({ values, io });
  },
};
