# Phase 3 Work Split: Developer A and Developer B

This splits **Phase 3 (control plane, nodes, devices, files, revocation)** of `docs/implementation-plan.md` (tasks 3.1–3.9) between two developers. The plan pins files, interfaces and acceptance tests per task, and the design lives in `docs/architecture.md` §6–§11. This file covers **who owns what, the contracts both sides code against, the order of merges and where the two meet**. If this file and the plan disagree, the plan wins (and the spec wins over the plan).

**Precondition:** Phases 0, 1, 2 and 5 are on `main` (Phase 2's command router `src/cli/main.cjs`, `store-arg.cjs`, `text.cjs`, `checkpoint.cjs` are available). All checks target **x86-64**.

---

## 1. How the split works (and why)

Phase 3 has two halves that only touch through a few well-defined objects:

| | **Developer A: platform and distribution** | **Developer B: identity and data** |
|---|---|---|
| Owns | Processes, HTTP, the signed policy snapshot, lease, revocation propagation and its measurement, partition, alerts | Stores and `kig init`, accounts and devices, request authentication, files and envelopes |
| Tasks | **3.1, 3.3, 3.4, 3.8, 3.9** | **3.2, 3.5, 3.6, 3.7** |
| Main question answered | "Does every node learn the current policy, fast, and fail closed when it can't?" | "Who is this device, is it allowed, and can it decrypt only what it should?" |
| Track goals | Goal 2 (revocation across nodes, latency), self-monitoring (P1-17) | Goal 2 (re-enrolment), identity controls (PS §4), file protection (P1-02) |
| Rough size | ≈ 2.3 days | ≈ 2.2 days |

The split is by responsibility, not by layer: each developer owns whole files end to end, so they rarely edit the same file. The few shared files are listed in §4 with explicit rules.

---

## 2. Contracts to agree in the kick-off (both developers, ≈ 1 hour, before any code)

Write these as JSDoc typedefs in `src/core/contracts.cjs` (no logic, only shapes and constants) and merge it first. Everything below is already decided by the architecture; the kick-off is about pinning names so that neither side guesses.

### C1. `KIG_HOME` layout (architecture §6.1)

```
$KIG_HOME (default <os.tmpdir()>/kig-demo)
├── cp/registry.db          cp/keys/{policy,audit,backup}.key|.pub, cp/keys/master-kem.key
├── nodes/<A|B|C>/node.db   nodes/<id>/node.key|.pub
├── devices/<device>/device.db
├── operator/recovery.key   (offline in spirit; never read by CP/nodes)
├── anchor/<store_id>.json  + anchor/cp-policy.pub (pinned by nodes and devices)
└── run/<cp|A|B|C>.pid, run/<id>.log
```

Ports: CP `127.0.0.1:7400`, nodes A/B/C `7401–7403`, overridable with `KIG_PORT_BASE`. Everything binds loopback only (this also works inside the judging replica, whose `--network none` still has `lo`).

### C2. Every store has the same audit base (owner: B, used by A)

Every new store (`registry.db`, `node.db`, `device.db`) contains, verbatim from the adapter schema:
- `meta(k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT` with `db_id` (16 random bytes, hex);
- `audit_events` with **the same columns, indexes and append-only triggers** as architecture §5.4.

Consequence: `src/core/audit.cjs`, `src/core/checkpoint.cjs`, `kig verify-log --db`, `kig checkpoint --db` and `kig alerts --db` work on every Phase 3 store **unchanged**. Phase 3 events use `gen = 0` (there are no setup generations outside the adapter). Do not fork `audit.cjs`.

### C3. Policy snapshot (owner: A produces, B consumes)

Architecture §10.1, plus `kem_pk_sha256` per device (envelope key binding for 3.7), encoded for signing with `encode('kig/v1/snapshot', [...])` and signed with ctx `kig/v1/revocation`:

```
PolicySnapshot { epoch, issued_at_ms, lease_ms,
  devices: [{ device_id, account, sign_pk_sha256, kem_pk_sha256, status: 'active'|'revoked' }],
  revoked_devices: [device_id],
  files: [{ file_id, active_version, cutoff: null }],      // cutoff filled in Phase 4
  grants: [{ file_id, account }] }
```

- A provides `cp/snapshot.cjs: buildSnapshot(cpDb) → PolicySnapshot` and `publish(cpDb) → epoch` (commit + sign + push).
- B's registry and file code call **only** `publish(cpDb)` after a committed change. Until A's 3.4 merges, `publish` is a stub that returns the next epoch without pushing.
- Nodes read the current snapshot only through `node/policy.cjs: current(db) → { snapshot, applied_epoch, lease_valid }`. B's auth code uses this and nothing else.

### C4. Registry read API (owner: B produces, A consumes)

`cp/registry.cjs` exports, for A's `buildSnapshot`:
`listDevices(cpDb) → [{ device_id, account, sign_pk, kem_pk, status }]`, `listGrants(cpDb)`, `listFiles(cpDb)`, and `getDevice(cpDb, deviceId)` for request authentication/enrolment lookups. Until B's 3.5 merges, A tests `buildSnapshot` against a tiny fixture that inserts rows into B's agreed tables (C5).

### C5. Table names (each owner adds only their own tables)

| Store | A's tables | B's tables |
|---|---|---|
| `registry.db` | `snapshots(epoch PK, body, sig, created_ms)`, `node_acks(node_id, epoch, acked_ms, sig)` | `accounts`, `devices`, `approvals`, `files`, `file_versions`, `grants`, `envelopes`, `custodian_wraps` |
| `node.db` | `policy(epoch PK, body, sig, applied_ms, applied_mono_ns)`, `lease(k, v)` | `challenges`, `used_nonces`, `ciphertexts`, `node_envelopes` |
| `device.db` | none | `keys`, `pinned` (CP policy public key) |

Schema files (`src/store/schema-cp.cjs`, `schema-node.cjs`, `schema-device.cjs`) are created by **B in 3.2** with the C2 base and B's tables, plus **clearly marked sections** for A's tables. A appends A's DDL inside A's section only. Schema version stays `1` for the whole of Phase 3 (no migrations before release; recreate dev stores with `kig init --force`).

### C6. HTTP conventions (owner: A, used by B)

- `core/http.cjs` (3.1): `serve(port, routes: Map<'METHOD /path', handler>)`, `call(url, method, json, { timeoutMs })`. JSON only, 1 MiB body cap, `Buffer`s as base64 fields.
- Every decision endpoint answers **HTTP 200** with `{ decision: 'allow'|'deny', rule }` (plus payload on allow). Malformed requests → 400 `{ error }`. Never 500 with details; never stack traces.
- Route strings are unique within each server's `contracts.ROUTES` map. CP and node servers may share paths because they listen on separate loopback ports; both expose `GET /v1/health`.
- **Route registration without shared edits:** `node/server.cjs` and `cp/server.cjs` (A) build their route map from a fixed list of modules: `node/routes-policy.cjs` (A), `node/routes-auth.cjs` and `node/routes-files.cjs` (B); likewise for the CP. Each module exports `[[ 'METHOD /path', handler ], …]`. Adding B's module to the list is a one-line change agreed in the kick-off.

### C7. Signed request transcript (owner: B, read by A's revocation probes)

`encode('kig/v1/request', [version, op, account, device_id, resource, request_id, nonce, key_version])`, signed with ctx `kig/v1/request`. B exposes `device/client.cjs: request(nodeUrl, deviceDir, op, fields) → { decision, rule, ... }`. A's revocation benchmark (3.8) uses only this function to probe nodes; it never builds transcripts itself.

### C8. CLI registration

New commands are modules with the Phase 2 shape `{ name, describe, usage, options, run }` and are added to the list in `src/cli/main.cjs`. Each developer adds only their own entries:

| A | B |
|---|---|
| `up`, `down`, `status`, `policy`, `revoke`, `bench` (extend with `bench revocation`), `node` (`partition`/`heal`) | `init`, `account`, `device`, `file`, `share` |

`bench` already exists (Phase 5 `bench detect`): A adds a `revocation` subcommand inside it and must not change `bench detect`.

### C9. Test helpers (owner: A, used by both)

`tests/helpers/kig-home.cjs`: `freshHome() → dir` (temp `KIG_HOME`), `startCluster(home, { nodes: ['A','B','C'] }) → { cpUrl, nodeUrls, stop() }`. Clusters are always stopped in `after()`; tests use random free ports (`KIG_PORT_BASE`), never the fixed defaults, so suites can run in parallel.

The helper's public names and result shape are declared by the `ClusterTestHelpers` JSDoc typedef and `TEST_HELPERS` constant in `src/core/contracts.cjs`. The helper implementation is part of A's 3.3 work, not M0.

---

## 3. Order of work and merge points

```
            Developer A                                   Developer B
M0  ─────── kick-off: contracts.cjs (C1–C9) merged ───────────────────────────
M1  3.1 http.cjs                                   3.2 schemas + kig init + CP keys
    3.3 supervisor: kig up/down/status, /v1/health     (stores incl. A's marked sections)
    tests/helpers/kig-home.cjs (C9)
    ── merge M1: `kig init && kig up && kig status` shows CP + 3 nodes healthy ──
M2  3.4 snapshots: build/sign/publish, node apply,  3.5 accounts, devices, approvals,
    push + 250 ms pull, signed fresh head, lease        device keystore, `kig device ...`
    (uses C5 fixture until 3.5 lands)                   (calls publish() stub until 3.4 lands)
    ── merge M2: enrolment changes reach all 3 nodes in a signed snapshot ──
M3  3.8 CP-side revoke + snapshot + acks           3.6 request auth: challenge, nonce cache,
    (probe step waits for 3.6's client)                 transcript verify, check order (§8.2)
    ── merge M3: a revoked device is denied by A, B, C; peer still allowed ──
M4  3.8 `kig bench revocation --n 100 --seed`      3.7 core/wrap.cjs (kemWrap/kemUnwrap),
    3.9 partition/heal, lease fail-closed,              publish, envelopes, share, file read
        P1-17 alerts on CP and nodes, `kig alerts`      through every node
        merges all stores
    ── merge M4 → Gate 3 (together, §6) ──
```

Rules:
- Merge to `main` at each M-point once `npm test` and `npm run judge -- npm test` are green (the judge run is native on x86-64, about 1–2 minutes). Small, frequent merges beat one big one.
- If one side is early, use the time on the other side's **tests**, not their code: A writes 3.6's rejection-rule tests from §8.2; B writes 3.8's "every node denies" test. Reviewing each other's changes is mandatory, so both understand the whole system before Phase 4 (rotation and crash recovery touch both halves).

---

## 4. Shared files and how to avoid conflicts

| File | Rule |
|---|---|
| `src/core/contracts.cjs` | Changed only by agreement, in its own small commit |
| `src/store/schema-*.cjs` | B creates; A edits only inside the `// ---- A: …` sections |
| `src/cli/main.cjs` | One line per new command module; each developer adds only their own (C8) |
| `node/server.cjs`, `cp/server.cjs` | A owns; B never edits; B's routes live in B's route modules (C6) |
| `README.md` | Each developer adds their commands to the Round 2 table in their last change |
| `docs/` | No changes to features/architecture without telling the other developer; record decisions in the commit message |

---

## 5. Per-task notes (what is easy to get wrong)

### Developer A

| Task | Watch for |
|---|---|
| **3.1** http | Loopback only; body cap enforced while streaming (not after buffering); JSON parse errors → 400, never a crash; timeouts on `call`. |
| **3.3** supervisor | `kig up` twice is a no-op; `kig down` leaves no process (check pids, not ports); child logs go to `run/<id>.log`, never to the CLI's stdout; Windows: spawn `process.execPath`, not `node`. |
| **3.4** snapshots | Verify signature with the **pinned** CP key before anything else; reject `epoch ≤ applied`; the pull reply is signed together with the node's random nonce (an old reply can't be replayed); applying a snapshot and recording `applied_epoch` happen in one transaction; lease uses `process.hrtime.bigint()`, never wall-clock. |
| **3.8** revocation | The measured interval is CP commit → node's first denial (monotonic, one process); acks are signed by the node key; results go to `evidence/revocation-<ts>.json` with seed, N, p50/p95/max per node and last node. |
| **3.9** partition, alerts | A partitioned node must **deny** (fail closed) once its lease expires and must record why; the test-only partition control is reachable only on loopback and only with `NODE_ENV=test` or from `kig node partition`; reuse `core/alerts.cjs` style (fixed reasons, no client data in `detail`). |

### Developer B

| Task | Watch for |
|---|---|
| **3.2** stores, init | C2 base copied exactly (verify-log must work on the new stores: add that test); key files 0600; `kig init` twice refuses without `--force`; anchor directory holds **public** keys only. |
| **3.5** devices | First device of an account needs an operator approval; later devices need an active device of the same account **or** the operator; an approval from a revoked device is refused; enrol request carries proof of possession (signed by the new key). |
| **3.6** auth | Check order from architecture §8.2: lease → device active in snapshot → not revoked → nonce fresh and unused (marked used **in the same transaction**) → signature (ctx `kig/v1/request`) → key-version rule. One test per rejection reason; denials return a rule, never details. |
| **3.7** files | No plaintext in any store (byte-scan test); DEK and shared secret wiped after use; device ID in both HKDF `info` and AES-GCM AAD so an envelope for A fails as B; tampered ciphertext, tag, nonce or AAD each fail; nodes never hold DEKs. |

---

## 6. Gate 3 checklist (together)

All inside `npm run judge -- …` (x86-64 replica), plus green CI:

- [ ] `kig init && kig up && kig status` → CP and nodes A, B, C healthy; `kig down` leaves nothing running
- [ ] Enrol `alice-phone` (operator approval), `alice-laptop` (approved by `alice-phone`), `bob-laptop`; publish `brief`, share with Bob; both read it through **each** of A, B, C
- [ ] `kig revoke --device alice-phone` → every node denies it; `alice-laptop` and `bob-laptop` still allowed
- [ ] `kig bench revocation --n 100 --seed <s>` → p50/p95/max per node and last node, written to `evidence/`, reproducible from the seed
- [ ] `kig node partition B` → B denies everything after lease expiry and reports the bound; `heal` restores it
- [ ] Every negative test from 3.6 (one per rejection reason) and 3.7 (tamper, wrong device, plaintext scan) passes
- [ ] `kig verify-log --db` OK on `registry.db` and each `node.db`; `kig alerts` shows the revoked-device retries
- [ ] Adapter untouched: `npm run validate` still passes (Phase 3 must not change Round 1 behaviour)
- [ ] `evidence/phase3.md` written (commands, results, limits: single host, one monotonic clock, loopback only)

---

## 7. Summary of ownership

| | Developer A | Developer B |
|---|---|---|
| Kick-off | `contracts.cjs` (C1–C9) together | `contracts.cjs` (C1–C9) together |
| Tasks | 3.1, 3.3, 3.4, 3.8, 3.9 | 3.2, 3.5, 3.6, 3.7 |
| Files owned | `src/core/http.cjs`, `src/cp/{server,snapshot,revoke,alerts}.cjs`, `src/node/{server,policy,lease,alerts,routes-policy}.cjs`, `src/cli/{supervisor,revoke,node,bench-revocation}.cjs`, `tests/helpers/kig-home.cjs` | `src/store/schema-{cp,node,device}.cjs`, `src/cp/{keys,registry,files}.cjs`, `src/core/wrap.cjs`, `src/node/{auth,files,routes-auth,routes-files}.cjs`, `src/device/{keystore,client,files}.cjs`, `src/cli/{init,device,file}.cjs` |
| Gate 3 | Items 1, 3, 4, 5, 7 | Items 2, 6, 7, 8 |
| Together | Gate 3, `evidence/phase3.md` | Gate 3, `evidence/phase3.md` |
