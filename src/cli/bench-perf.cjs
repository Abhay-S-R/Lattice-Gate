'use strict';
// `kig bench perf`: latency, size, and storage-growth measurements (Phase 7 Task 7.1, P1-20).
// Never imports node:crypto directly; all cryptographic calls go through src/crypto/provider.cjs.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const provider = require('../crypto/provider.cjs');
const wrap = require('../core/wrap.cjs');
const { openDb, tx } = require('../store/db.cjs');
const adapterSchema = require('../store/schema-adapter.cjs');
const cpSchema = require('../store/schema-cp.cjs');
const audit = require('../core/audit.cjs');
const { detect } = require('../detect/index.cjs');
const { loadEventsFile } = require('../detect/ingest.cjs');
const { loadApprovalsFile } = require('../detect/approvals.cjs');
const { generateDataset } = require('../detect/generator.cjs');
const identity = require('../messaging/identity.cjs');
const handshake = require('../messaging/handshake.cjs');
const record = require('../messaging/record.cjs');
const supervisor = require('./supervisor.cjs');
const client = require('../device/client.cjs');
const deviceFiles = require('../device/files.cjs');
const keystore = require('../device/keystore.cjs');
const { publish } = require('../cp/snapshot.cjs');
const { revoke } = require('../cp/revoke.cjs');
const { layout, ports, url, NODE_IDS, RULES } = require('../core/contracts.cjs');
const { summarize, seededDeviceId } = require('./bench-revocation.cjs');
const { UsageError } = require('./main.cjs');

const REPO = path.resolve(__dirname, '..', '..');
const SERVICE = path.join(REPO, 'track4_service.cjs');
const KIG = path.join(REPO, 'kig.cjs');

const round3 = (x) => Math.round(x * 1000) / 1000;

function stats(samples) {
  const s = summarize(samples);
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return {
    n: samples.length,
    p50_ms: round3(s.p50),
    p95_ms: round3(s.p95),
    max_ms: round3(s.max),
    mean_ms: round3(mean),
  };
}

function timeSync(n, fn) {
  const samples = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    fn(i);
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  return stats(samples);
}

async function timeAsync(n, fn) {
  const samples = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    await fn(i);
    samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  return stats(samples);
}

/** Extract raw BIT STRING payload byte length from an ASN.1 SPKI DER public key. */
function spkiRawKeyBytes(spkiDer) {
  // SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING (0x03, len, 0x00 unused-bits, payload) }
  // Walk top-level SEQUENCE -> skip AlgorithmIdentifier SEQUENCE -> read BIT STRING length.
  let p = 0;
  const readTagLen = () => {
    const tag = spkiDer[p++];
    let len = spkiDer[p++];
    if (len & 0x80) {
      const nBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < nBytes; i++) len = (len << 8) | spkiDer[p++];
    }
    return { tag, len };
  };
  const outer = readTagLen();
  if (outer.tag !== 0x30) throw new Error('invalid SPKI outer SEQUENCE');
  const alg = readTagLen();
  p += alg.len;
  const bitStr = readTagLen();
  if (bitStr.tag !== 0x03) throw new Error('invalid SPKI BIT STRING');
  const unusedBits = spkiDer[p];
  if (unusedBits !== 0) throw new Error('unexpected unused bits in SPKI');
  return bitStr.len - 1;
}

async function reserveBase() {
  for (let i = 0; i < 24; i++) {
    const base = 14000 + (provider.random(4).readUInt32BE(0) % 10000);
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
  throw new Error('could not reserve loopback ports');
}

function findPracticeDir() {
  const candidates = [
    process.env.TOOLKIT_DIR ? path.resolve(process.env.TOOLKIT_DIR, 'practice') : null,
    '/toolkit/practice',
    path.resolve(REPO, '..', 'Track-4-Toolkit', 'practice'),
  ].filter(Boolean);
  return candidates.find((d) => fs.existsSync(path.join(d, 'events.csv')) && fs.existsSync(path.join(d, 'approvals.json'))) || null;
}

function parsePositiveInt(raw, flag, def, max) {
  if (raw === undefined) return def;
  if (!/^[1-9]\d{0,5}$/.test(String(raw))) throw new UsageError(`--${flag} must be an integer from 1 to ${max}`);
  const v = Number(raw);
  if (!Number.isSafeInteger(v) || v < 1 || v > max) throw new UsageError(`--${flag} must be an integer from 1 to ${max}`);
  return v;
}

function parseSeed(raw, def) {
  if (raw === undefined) return def;
  if (!/^\d{1,10}$/.test(String(raw))) throw new UsageError('--seed must be an integer from 0 to 4294967295');
  const v = Number(raw);
  if (!Number.isSafeInteger(v) || v < 0 || v > 0xffffffff) throw new UsageError('--seed must be an integer from 0 to 4294967295');
  return v;
}

function kigCli(env, args) {
  const r = spawnSync(process.execPath, [KIG, ...args], {
    cwd: os.tmpdir(), env, encoding: 'utf8', timeout: 60000,
  });
  if (r.status !== 0) throw new Error(`kig ${args.slice(0, 2).join(' ')} failed: ${r.stderr || r.stdout}`);
  return r;
}

async function run({ values = {}, io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) } } = {}) {
  const runs = parsePositiveInt(values.runs, 'runs', 30, 500);
  const seed = parseSeed(values.seed, 2026);
  const withCluster = !values['no-cluster'];
  const inProcRuns = runs <= 5 ? runs * 4 : 200;
  const largeRuns = Math.min(runs, 5);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-bench-perf-'));
  try {
    // 1. Process baseline + Round 1 adapter whole-process latencies.
    const emptyNode = timeSync(runs, () => {
      const r = spawnSync(process.execPath, ['-e', ''], { encoding: 'utf8', timeout: 15000 });
      if (r.status !== 0) throw new Error('empty node failed');
    });

    const adapterDir = path.join(root, 'adapter');
    fs.mkdirSync(adapterDir, { recursive: true, mode: 0o700 });
    const adapterEnv = { ...process.env, TRACK4_STATE_DIR: adapterDir };
    const callAdapter = (payload) => {
      const r = spawnSync(process.execPath, [SERVICE], {
        cwd: REPO, env: adapterEnv, input: payload, encoding: 'utf8', timeout: 30000,
      });
      if (r.status !== 0) throw new Error(`adapter failed: ${r.stderr}`);
    };

    const setupSmallPayload = JSON.stringify({
      op: 'setup',
      owners: { brief: 'alice', doc2: 'bob' },
      contents: { brief: 'classified-brief-body', doc2: 'peer-body' },
      disabled: [],
    });
    const setupSmall = timeSync(runs, () => callAdapter(setupSmallPayload));

    const readAllow = timeSync(runs, (i) => callAdapter(JSON.stringify({
      op: 'read', actor: 'alice', asset: 'brief', request_id: `allow-${i}`,
    })));
    const readDeny = timeSync(runs, (i) => callAdapter(JSON.stringify({
      op: 'read', actor: 'mallory', asset: 'brief', request_id: `deny-${i}`,
    })));
    const revokeOp = timeSync(runs, (i) => callAdapter(JSON.stringify({
      op: 'revoke', actor: `revoked-${i}`,
    })));
    const auditHit = timeSync(runs, () => callAdapter(JSON.stringify({
      op: 'audit', request_id: 'allow-0',
    })));
    const auditMiss = timeSync(runs, () => callAdapter(JSON.stringify({
      op: 'audit', request_id: 'no-such-request',
    })));

    const kemKey = provider.kemGenerate();
    const rawPub = await provider.kemExportRawPublic(kemKey.publicKey);
    const rawPubB64 = rawPub.toString('base64');
    const badPubB64 = Buffer.alloc(1184, 0xff).toString('base64');

    const protectedReadAllow = timeSync(runs, (i) => callAdapter(JSON.stringify({
      op: 'protected_read', actor: 'alice', asset: 'brief', challenge: `ch-${i}`, public_key: rawPubB64,
    })));
    const protectedReadInvalidKey = timeSync(runs, (i) => callAdapter(JSON.stringify({
      op: 'protected_read', actor: 'alice', asset: 'brief', challenge: `bad-${i}`, public_key: badPubB64,
    })));

    const largeDir = path.join(root, 'adapter-large');
    fs.mkdirSync(largeDir, { recursive: true, mode: 0o700 });
    const largeEnv = { ...process.env, TRACK4_STATE_DIR: largeDir };
    const callLarge = (payload) => {
      const r = spawnSync(process.execPath, [SERVICE], {
        cwd: REPO, env: largeEnv, input: payload, encoding: 'utf8', timeout: 30000, maxBuffer: 16 * 1024 * 1024,
      });
      if (r.status !== 0) throw new Error(`large setup failed: ${r.stderr}`);
    };
    const payload1MiB = JSON.stringify({
      op: 'setup', owners: { big: 'alice' }, contents: { big: 'A'.repeat(1024 * 1024) }, disabled: [],
    });
    const payloadNear4MiB = JSON.stringify({
      op: 'setup', owners: { big: 'alice' }, contents: { big: 'B'.repeat(4 * 1024 * 1024 - 2048) }, disabled: [],
    });
    const setup1MiB = timeSync(largeRuns, () => callLarge(payload1MiB));
    const setupNear4MiB = timeSync(largeRuns, () => callLarge(payloadNear4MiB));

    // 2. In-process cryptography.
    const mlKemKeygen = timeSync(inProcRuns, () => provider.kemGenerate());
    const kemEncSample = provider.kemEncapsulate(kemKey.publicKey);
    const mlKemEncaps = timeSync(inProcRuns, () => provider.kemEncapsulate(kemKey.publicKey));
    const mlKemDecaps = timeSync(inProcRuns, () => provider.kemDecapsulate(kemKey.privateKey, kemEncSample.ciphertext));

    const sigKey = provider.sigGenerate();
    const msgBuf = Buffer.from('benchmark-transcript-payload-2026', 'utf8');
    const sigSample = provider.sign(sigKey.privateKey, provider.CONTEXTS.request, msgBuf);
    const mlDsaKeygen = timeSync(Math.min(inProcRuns, 60), () => provider.sigGenerate());
    const mlDsaSign = timeSync(inProcRuns, () => provider.sign(sigKey.privateKey, provider.CONTEXTS.request, msgBuf));
    const mlDsaVerify = timeSync(inProcRuns, () => {
      if (!provider.verify(sigKey.publicKey, provider.CONTEXTS.request, msgBuf, sigSample)) throw new Error('verify failed');
    });

    const aesKey = provider.random(32);
    const aesNonce = provider.random(12);
    const aesAad = Buffer.from('kig/v1/bench-aad', 'utf8');
    const pt1 = provider.random(1024);
    const pt64 = provider.random(64 * 1024);
    const pt256 = provider.random(256 * 1024);
    const ct1 = provider.aeadSeal(aesKey, aesNonce, aesAad, pt1);
    const ct64 = provider.aeadSeal(aesKey, aesNonce, aesAad, pt64);
    const ct256 = provider.aeadSeal(aesKey, aesNonce, aesAad, pt256);

    const aesSeal1 = timeSync(inProcRuns, () => provider.aeadSeal(aesKey, aesNonce, aesAad, pt1));
    const aesOpen1 = timeSync(inProcRuns, () => provider.aeadOpen(aesKey, aesNonce, aesAad, ct1));
    const aesSeal64 = timeSync(inProcRuns, () => provider.aeadSeal(aesKey, aesNonce, aesAad, pt64));
    const aesOpen64 = timeSync(inProcRuns, () => provider.aeadOpen(aesKey, aesNonce, aesAad, ct64));
    const aesSeal256 = timeSync(Math.min(inProcRuns, 80), () => provider.aeadSeal(aesKey, aesNonce, aesAad, pt256));
    const aesOpen256 = timeSync(Math.min(inProcRuns, 80), () => provider.aeadOpen(aesKey, aesNonce, aesAad, ct256));

    const hkdfSalt = provider.random(32);
    const hkdfInfo = Buffer.from('kig/v1/bench-hkdf', 'utf8');
    const hkdf32 = timeSync(inProcRuns, () => provider.hkdf(aesKey, hkdfSalt, hkdfInfo, 32));
    const hmac1k = timeSync(inProcRuns, () => provider.hmac(aesKey, pt1));

    const dek = provider.random(32);
    const wrapCtx = ['brief', 1, 'alice', 'alice-phone', 'kig/v1/envelope'];
    const envSample = wrap.kemWrap(kemKey.publicKey, dek, wrapCtx);
    const kemWrapDek = timeSync(inProcRuns, () => wrap.kemWrap(kemKey.publicKey, dek, wrapCtx));
    const kemUnwrapDek = timeSync(inProcRuns, () => wrap.kemUnwrap(kemKey.privateKey, envSample, wrapCtx));

    // 3. In-process SQLite audit storage & verification.
    const auditDbFile = path.join(root, 'audit-bench.db');
    const adb = openDb(auditDbFile, { create: true, version: adapterSchema.VERSION, init: adapterSchema.init });
    let auditAppendTx;
    let verifyChain1000;
    try {
      const appendN = Math.min(inProcRuns, 200);
      auditAppendTx = timeSync(appendN, (i) => tx(adb, () => {
        audit.append(adb, { gen: 1, kind: 'access', op: 'read', request_id: `r-${i}`, actor: 'alice', asset: 'brief', decision: 'allow', rule: 'owner_allowed' });
      }));
      tx(adb, () => {
        for (let i = appendN; i < 1000; i++) {
          audit.append(adb, { gen: 1, kind: 'access', op: 'read', request_id: `r-${i}`, actor: 'alice', asset: 'brief', decision: 'allow', rule: 'owner_allowed' });
        }
      });
      verifyChain1000 = timeSync(Math.min(runs, 10), () => {
        const v = audit.verifyChain(adb);
        if (!v.ok || v.count !== 1000) throw new Error('chain verify failed');
      });
    } finally {
      adb.close();
    }
    const auditTotalBytes = ['', '-wal', '-shm']
      .map((suf) => (fs.existsSync(auditDbFile + suf) ? fs.statSync(auditDbFile + suf).size : 0))
      .reduce((a, b) => a + b, 0);
    const auditBytesPerEvent = Math.round(auditTotalBytes / 1000);

    // 4. Detector in-process.
    const synth = generateDataset(seed);
    const detectSynth = timeSync(Math.min(runs, 15), () => detect(synth.events, synth.approvals));
    const p50EventsPerSec = Math.round((synth.events.length / Math.max(detectSynth.p50_ms, 0.001)) * 1000);

    const practiceDir = findPracticeDir();
    let detectPractice22 = null;
    if (practiceDir) {
      const pEvents = loadEventsFile(path.join(practiceDir, 'events.csv')).events;
      const pApprovals = loadApprovalsFile(path.join(practiceDir, 'approvals.json'));
      detectPractice22 = timeSync(Math.min(runs, 20), () => detect(pEvents, pApprovals));
    }

    // 5. Messaging + KIG home sizes + optional Round 2 cluster latencies.
    const home = path.join(root, 'kig-home');
    const portBase = await reserveBase();
    const kenv = { ...process.env, KIG_HOME: home, KIG_PORT_BASE: String(portBase) };
    kigCli(kenv, ['init']);
    kigCli(kenv, ['account', 'add', 'alice']);
    kigCli(kenv, ['device', 'enrol', 'alice-phone', '--account', 'alice']);
    kigCli(kenv, ['device', 'approve', 'alice-phone', '--operator', '--approval-id', 'perf-a1']);
    kigCli(kenv, ['device', 'enrol', 'alice-laptop', '--account', 'alice']);
    kigCli(kenv, ['device', 'approve', 'alice-laptop', '--by', 'alice-phone', '--approval-id', 'perf-a2']);
    kigCli(kenv, ['account', 'add', 'bob']);
    kigCli(kenv, ['device', 'enrol', 'bob-laptop', '--account', 'bob']);
    kigCli(kenv, ['device', 'approve', 'bob-laptop', '--operator', '--approval-id', 'perf-b1']);

    const briefInput = path.join(root, 'brief-4k.bin');
    const briefPlain = Buffer.from(provider.random(2048).toString('hex'), 'utf8'); // 4096 B
    fs.writeFileSync(briefInput, briefPlain);
    kigCli(kenv, ['file', 'publish', 'brief', '--as', 'alice-phone', '--input', briefInput]);
    kigCli(kenv, ['share', 'brief', '--with', 'bob']);

    const backupDir = path.join(root, 'backup-sample');
    kigCli(kenv, ['backup', '--out', backupDir]);
    const backupBytes = ['manifest.json', 'manifest.sig', 'wrap.bin', 'payload.bin']
      .map((f) => fs.statSync(path.join(backupDir, f)).size)
      .reduce((a, b) => a + b, 0);

    const L = layout(home);
    let snapshotBytes;
    {
      const cdb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
      try {
        const snapRow = cdb.prepare('SELECT body, sig FROM snapshots ORDER BY epoch DESC LIMIT 1').get();
        snapshotBytes = Buffer.byteLength(snapRow.body, 'utf8') + snapRow.sig.length;
      } finally {
        cdb.close();
      }
    }

    const aliceId = identity.load(home, 'alice-phone');
    const bobId = identity.load(home, 'bob-laptop');
    const hsRuns = Math.min(inProcRuns, 25);
    const handshakeM1M3 = timeSync(hsRuns, () => {
      const init = handshake.initiate(aliceId, 'bob-laptop');
      const resp = handshake.respond(bobId, init.m1);
      const fin = handshake.finish(init.state, resp.m2);
      handshake.confirm(resp.session, fin.m3);
      handshake.close(fin.session);
      handshake.close(resp.session);
    });

    const msgChunk = provider.random(16 * 1024);
    let recordSeal16k;
    let recordOpen16k;
    {
      const init = handshake.initiate(aliceId, 'bob-laptop');
      const resp = handshake.respond(bobId, init.m1);
      const fin = handshake.finish(init.state, resp.m2);
      handshake.confirm(resp.session, fin.m3);
      try {
        const recN = Math.min(inProcRuns, 40);
        const sealed = [];
        recordSeal16k = timeSync(recN, (i) => {
          sealed.push(record.seal(fin.session, msgChunk, { msg_id: provider.sha256(Buffer.from(`m-${i}`)).toString('hex').slice(0, 32) }));
        });
        recordOpen16k = timeSync(recN, (i) => {
          record.open(resp.session, sealed[i]);
        });
      } finally {
        handshake.close(fin.session);
        handshake.close(resp.session);
      }
    }

    let clusterRound2 = null;
    if (withCluster) {
      const revN = Math.min(runs, 10);
      const revDevs = [];
      {
        const cdb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
        try {
          tx(cdb, () => {
            for (let i = 0; i < revN; i++) {
              const devId = seededDeviceId(seed, i);
              const pub = keystore.create(home, devId);
              keystore.pinPolicy(home, devId, fs.readFileSync(L.anchor.cpPolicyPub));
              cdb.prepare("INSERT INTO devices(device_id,account,sign_pk,kem_pk,status,key_version,created_ms) VALUES(?,?,?,?,'active',1,?)")
                .run(JSON.stringify(devId), JSON.stringify('alice'), pub.signPublic, pub.kemPublic, Date.now());
              revDevs.push(devId);
            }
          });
          publish(cdb, { env: kenv });
        } finally {
          cdb.close();
        }
      }

      await supervisor.start(home, kenv);
      try {
        const readN = Math.min(runs, 20);
        let reqSeq = 0;
        const authFileRead = await timeAsync(readN, async () => {
          const r = await client.request(url(ports(kenv).A), L.device('bob-laptop').dir, 'file.read', {
            home, version: 1, op: 'file.read', account: 'bob', device_id: 'bob-laptop',
            resource: 'brief', request_id: `perf-read-${++reqSeq}`, key_version: 1,
          });
          if (r.decision !== 'allow') throw new Error(`cluster read denied: ${r.rule}`);
          const pt = deviceFiles.read(home, 'bob-laptop', r);
          if (!pt.equals(briefPlain)) throw new Error('decrypted content mismatch');
        });

        const rotN = Math.min(runs, 5);
        const fileRotateE2E = timeSync(rotN, () => kigCli(kenv, ['rotate', '--file', 'brief']));
        const currentVer = 1 + rotN;

        const revokeLastNode = await timeAsync(revN, async (i) => {
          const devId = revDevs[i];
          const cdb = openDb(L.cp.db, { create: false, version: cpSchema.VERSION, init: cpSchema.init });
          let rev;
          try { rev = revoke(cdb, devId, { env: kenv }); } finally { cdb.close(); }
          const t0 = BigInt(rev.committed_mono_ns);
          const deadline = Date.now() + 10000;
          await Promise.all(NODE_IDS.map(async (nid) => {
            while (Date.now() < deadline) {
              const ans = await client.request(url(ports(kenv)[nid]), L.device(devId).dir, 'policy.probe', {
                home, version: 1, op: 'policy.probe', account: 'alice', device_id: devId,
                resource: 'probe', request_id: `probe-${i}-${nid}-${++reqSeq}`, key_version: currentVer,
              });
              if (ans.decision === 'deny' && ans.rule === RULES.deviceRevoked) return;
              await new Promise((r) => setTimeout(r, 1));
            }
            throw new Error(`node ${nid} did not enforce revocation in time`);
          }));
          return Number(process.hrtime.bigint() - t0) / 1e6;
        });

        clusterRound2 = {
          authenticated_file_read: authFileRead,
          file_rotate_e2e: fileRotateE2E,
          revoke_to_all_nodes_denied: revokeLastNode,
        };
      } finally {
        await supervisor.stop(home, kenv).catch(() => {});
      }
    }

    const sigSpki = provider.exportPublic(sigKey.publicKey);
    const sizesBytes = {
      ml_kem_768_pk_raw: rawPub.length,
      ml_kem_768_sk_pkcs8: provider.exportPrivate(kemKey.privateKey).length,
      ml_kem_768_ct: kemEncSample.ciphertext.length,
      ml_kem_768_ss: kemEncSample.sharedKey.length,
      ml_dsa_65_pk_raw: spkiRawKeyBytes(sigSpki),
      ml_dsa_65_pk_spki: sigSpki.length,
      ml_dsa_65_sk_pkcs8: provider.exportPrivate(sigKey.privateKey).length,
      ml_dsa_65_sig: sigSample.length,
      aes_256_gcm_nonce: aesNonce.length,
      aes_256_gcm_tag: ct1.length - pt1.length,
      device_dek_envelope_json: Buffer.byteLength(JSON.stringify(wrap.serialize(envSample)), 'utf8'),
      signed_policy_snapshot_3_devices: snapshotBytes,
      backup_bundle_3_devices_1_file: backupBytes,
      audit_db_bytes_per_event_at_1000: auditBytesPerEvent,
    };

    const cpus = os.cpus();
    const inReplica = fs.existsSync('/app/track4_service.cjs') && fs.existsSync('/toolkit/validate.py');
    const report = {
      generated_at: new Date().toISOString(),
      environment: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        openssl: process.versions.openssl,
        sqlite: process.versions.sqlite,
        cpu_model: cpus[0] ? cpus[0].model.trim() : 'unknown',
        cpu_cores: cpus.length,
        total_mem_mib: Math.round(os.totalmem() / (1024 * 1024)),
        in_judging_replica: inReplica,
      },
      config: { runs, in_process_runs: inProcRuns, large_input_runs: largeRuns, seed, cluster: withCluster },
      results: {
        process_baseline: { empty_node: emptyNode },
        adapter_whole_process: {
          setup_small: setupSmall,
          read_allow: readAllow,
          read_deny: readDeny,
          revoke: revokeOp,
          audit_hit: auditHit,
          audit_miss: auditMiss,
          protected_read_allow: protectedReadAllow,
          protected_read_invalid_key: protectedReadInvalidKey,
          setup_1mib: setup1MiB,
          setup_near_4mib_cap: setupNear4MiB,
        },
        crypto_in_process: {
          ml_kem_768_keygen: mlKemKeygen,
          ml_kem_768_encapsulate: mlKemEncaps,
          ml_kem_768_decapsulate: mlKemDecaps,
          ml_dsa_65_keygen: mlDsaKeygen,
          ml_dsa_65_sign: mlDsaSign,
          ml_dsa_65_verify: mlDsaVerify,
          aes_256_gcm_seal_1kib: aesSeal1,
          aes_256_gcm_open_1kib: aesOpen1,
          aes_256_gcm_seal_64kib: aesSeal64,
          aes_256_gcm_open_64kib: aesOpen64,
          aes_256_gcm_seal_256kib: aesSeal256,
          aes_256_gcm_open_256kib: aesOpen256,
          hkdf_sha256_32b: hkdf32,
          hmac_sha256_1kib: hmac1k,
          kem_wrap_dek: kemWrapDek,
          kem_unwrap_dek: kemUnwrapDek,
        },
        storage_in_process: {
          audit_append_tx: auditAppendTx,
          verify_chain_1000: verifyChain1000,
        },
        detector_in_process: {
          synthetic_events_count: synth.events.length,
          detect_synthetic_dataset: detectSynth,
          p50_events_per_sec: p50EventsPerSec,
          detect_practice_22: detectPractice22,
        },
        messaging_in_process: {
          handshake_m1_m3: handshakeM1M3,
          record_seal_16kib: recordSeal16k,
          record_open_16kib: recordOpen16k,
        },
        cluster_round2: clusterRound2,
        sizes_bytes: sizesBytes,
      },
      limits: [
        'Single-host measurements; cluster timings use loopback HTTP on 127.0.0.1 and exclude real WAN latency.',
        'Round 1 adapter timings spawn a fresh Node.js process per request (matching the organizer worker), so Node startup dominates.',
        'Numbers depend on host CPU and filesystem; the local x86-64 replica is a stand-in, not the organizer hardware.',
      ],
    };

    const outFile = values.out
      ? path.resolve(values.out)
      : path.join(REPO, 'evidence', `bench-perf-${report.generated_at.replace(/[:.]/g, '-')}.json`);
    let saveNotice;
    try {
      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(outFile, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
      saveNotice = `report: ${outFile}`;
    } catch (e) {
      saveNotice = `report not saved (${e.code || 'error'}): ${outFile} is not writable here`;
    }

    if (values.json) {
      io.out(`${JSON.stringify(report, null, 2)}\n`);
      io.err(`${saveNotice}\n`);
    } else {
      const fmt = (t) => `p50=${t.p50_ms.toFixed(2)} ms  p95=${t.p95_ms.toFixed(2)} ms  max=${t.max_ms.toFixed(2)} ms (n=${t.n})`;
      const lines = [
        `kig bench perf (${report.environment.node} ${report.environment.platform}-${report.environment.arch}, replica=${inReplica})`,
        `  empty node process          : ${fmt(emptyNode)}`,
        `  adapter setup (2 assets)    : ${fmt(setupSmall)}`,
        `  adapter read (allow)        : ${fmt(readAllow)}`,
        `  adapter read (deny)         : ${fmt(readDeny)}`,
        `  adapter revoke              : ${fmt(revokeOp)}`,
        `  adapter audit (hit)         : ${fmt(auditHit)}`,
        `  adapter protected_read      : ${fmt(protectedReadAllow)}`,
        `  adapter setup (near 4 MiB)  : ${fmt(setupNear4MiB)}`,
        `  in-proc ML-KEM-768 encaps   : ${fmt(mlKemEncaps)}`,
        `  in-proc ML-KEM-768 decaps   : ${fmt(mlKemDecaps)}`,
        `  in-proc ML-DSA-65 sign      : ${fmt(mlDsaSign)}`,
        `  in-proc ML-DSA-65 verify    : ${fmt(mlDsaVerify)}`,
        `  in-proc AES-256-GCM 64 KiB  : seal ${fmt(aesSeal64)} | open ${fmt(aesOpen64)}`,
        `  in-proc audit append (tx)   : ${fmt(auditAppendTx)} (~${auditBytesPerEvent} B/event at 1k)`,
        `  in-proc verifyChain (1,000) : ${fmt(verifyChain1000)}`,
        `  detector (${synth.events.length} events)     : ${fmt(detectSynth)} (~${p50EventsPerSec} events/s)`,
        `  messaging handshake M1..M3  : ${fmt(handshakeM1M3)}`,
        ...(clusterRound2 ? [
          `  cluster signed file.read    : ${fmt(clusterRound2.authenticated_file_read)}`,
          `  cluster kig rotate e2e      : ${fmt(clusterRound2.file_rotate_e2e)}`,
          `  cluster revoke->all-3-deny  : ${fmt(clusterRound2.revoke_to_all_nodes_denied)}`,
        ] : []),
        `  sizes (B): ML-KEM pk=${sizesBytes.ml_kem_768_pk_raw} ct=${sizesBytes.ml_kem_768_ct} | ML-DSA pk=${sizesBytes.ml_dsa_65_pk_raw} sig=${sizesBytes.ml_dsa_65_sig} | envelope=${sizesBytes.device_dek_envelope_json} | snapshot=${sizesBytes.signed_policy_snapshot_3_devices} | backup=${sizesBytes.backup_bundle_3_devices_1_file}`,
        `  ${saveNotice}`,
      ];
      io.out(`${lines.join('\n')}\n`);
    }
    return 0;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

module.exports = { run, stats };
