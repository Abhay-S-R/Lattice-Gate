# Phase 4 step-level plan: rotation, lost-device re-key, crash recovery, backups

**Spec:** features P1-03 (re-key half), P1-04, P1-06, P1-07, D-06, D-07; architecture §10–§13, §17.2 steps 4–8.
**Plan row:** `docs/implementation-plan.md` Phase 4 (tasks 4.1–4.5). If this file and the spec disagree, the spec wins.
**Branch:** `phase-4-rotation`. **Target:** linux x86-64 (amd64) judging replica, Node 24.11.1.
**Builds on:** Phase 3 as merged on `main` (control plane, three nodes, devices, envelopes, signed snapshots, lease).

---

## 1. Gate 4

All of these must pass locally **and** in `npm run judge -- …` (linux/amd64, read-only root, offline):

- [x] §17.2 demo steps 4–8 as one scripted test (`tests/e2e/phase4-demo.test.cjs`):
  - 4: `brief` rotated while a transfer is in flight; the in-flight transfer finishes inside the grace window; a **new** request for the old version is rejected on **every** node; after 30 s the old transfer is terminated (`grace_expired`).
  - 5: `kig lost --device alice-phone` → every node denies it; per-node propagation latency printed.
  - 6: `alice-phone-2` enrols; before approval it is denied everywhere; approval by the revoked phone is refused; approval by `alice-laptop` works; `brief` was re-keyed; Bob and the replacement read the new version; the lost phone's old envelope cannot open it.
  - 7: CP crashed at `before_commit`, restarted: old version still active, revocation still in force, data readable, epoch not lower.
  - 8: backup; flipped byte → `digest_mismatch`; truncated → `digest_mismatch`; bad signature → `bad_signature`; old backup → `stale_backup`; live state byte-identical after each failure; good backup restores and the system works after restart.
- [x] `kig crash-test` passes at all 5 points (`after_prepare`, `after_stage`, `before_commit`, `after_commit`, `during_distribute`).
- [x] Unit/acceptance tests listed per task below.
- [x] Round 1 adapter untouched: `npm run validate` passes.
- [x] `evidence/phase4.md` written (commands, results, limits).

---

## 2. Decisions taken here (not fixed by the spec)

| # | Decision | Why |
|---|---|---|
| P4-D1 | **Rotation runs inside the CP process** (`POST /v1/files/rotate`); `kig rotate` and `kig lost` are thin clients. | Architecture §12.3: "the CP `SIGKILL`s itself at that exact point". Crash injection must kill the process that owns the journal. |
| P4-D2 | **Staging goes over signed HTTP** (`POST /v1/stage`, `POST /v1/stage/drop`), not direct DB writes. The CP signs `{op, rotation_id, file_id, version, content digest}` with its policy key (ctx `kig/v1/revocation`); the node verifies it, stores, and answers with an ack signed by its node key over the same digest. | §12.1 needs real per-node staged acks; "missing node ack aborts before commit" is only testable if an unreachable or partitioned node cannot ack. Publish/share keep Phase 3's direct writes. |
| P4-D3 | **COMMIT is one CP transaction:** active version, old version → `retiring`, cutoff row, signed snapshot `E` and journal `COMMIT` together. | `from_epoch` is then exactly the epoch of the snapshot that first carries the cutoff, and roll-forward can re-push a durable `E`. |
| P4-D4 | **Version numbers are never reused.** Next version = max(active, any journalled target) + 1. | An aborted v+1 that a node failed to drop can never be confused with a later committed version. Stage acks also bind the content digest. |
| P4-D5 | **Chunk fetch is `POST /v1/transfer/chunk {transfer_id, index}`**, not `GET /v1/transfer/<id>/chunk/<n>`. | `core/http.cjs` routes are exact `METHOD path` matches. Keeping the 32-byte bearer transfer ID out of URLs also keeps it out of any access log. The plan row is updated. |
| P4-D6 | **Rule names:** the node keeps the Phase 3 rule `old_key_version` for "new request names a version that is not active" (architecture §12.2 calls it `old_key_after_cutoff`). New rules: `transfer_unknown`, `transfer_terminated`, `grace_expired`, `transfer_expired`. | Phase 3 contracts, auth and the N-OLD-KEY alert already use `old_key_version`. |
| P4-D7 | **Grace is node-local:** each node records `applied_mono_ns` for every cutoff when it applies the snapshot (`INSERT OR IGNORE`, never reset by a later snapshot). A transfer may continue only if it was created **before** that moment and the node's monotonic clock is still before `applied + grace_ms`. Default grace 30 000 ms (`kig rotate` cannot change it; the library takes `graceMs` so unit tests can use a short window). | D-06. |
| P4-D8 | **Transfers also have a hard TTL of 10 minutes** and are terminated immediately when their device is revoked (in the same transaction that applies the snapshot) or when the node's lease is invalid. | Bearer IDs must not live forever; revocation must kill live transfers (§10.2 step 3). |
| P4-D9 | **File size cap 256 KiB** at publish and rotation. | A stage message (base64 ciphertext plus envelopes) must fit the 1 MiB HTTP body cap. Stated as a limit. |
| P4-D10 | **Newly approved devices are provisioned:** after `kig device approve`, the CP issues that device an envelope for the active version of every file granted to its account. | Without it a replacement device enrolled after `kig lost` re-keyed the file could never read it. Only an approved, active device gets one. |
| P4-D11 | **COMMIT checks the device set:** if any device holding a v+1 envelope is no longer active, or an active device of a granted account has none, the rotation aborts (`device_set_changed`). | A revocation or approval racing a rotation can never leave a revoked device with an envelope for the new version, or a new device without one. |
| P4-D12 | **Store schema version 2** for `registry.db` and `node.db` (new tables; `file_versions.status` gains `retiring`). Device stores and the adapter stay at 1. Old Phase 3 homes are refused with a schema error; recreate them with `kig init --force`. | Same rule as Phase 3: no migrations before release. The adapter (Round 1, frozen) is not touched. |
| P4-D13 | **Node anti-rollback uses a high-water file** `node.db.epoch` next to the store, written atomically after every applied snapshot. A node whose store is behind it fails closed (lease invalid) and refuses any snapshot older than it. | §12.3 extra rules, P1-06 [NEW]. A copy of an old `node.db` alone cannot resurrect a revoked device. Limit: an attacker who controls the whole node directory is out of scope. |
| P4-D14 | **Backup payload = registry snapshot (`VACUUM INTO`) + CP key files** (policy, audit, backup, master KEM), and `kig backup` raises `min_backup_epoch` in `anchor/keys.json`. | P1-07 "encrypted key material/state"; §13.2 check 6 "contains the required key material"; check 4 "minimum pinned in the anchor". |
| P4-D15 | **Restore validates in a temp directory** (checks 1–6) and touches live state only in step 7: stop the cluster if it runs → quarantine (rename, never delete) the live registry and its WAL/SHM → rename the validated file into place → write key files atomically → restart if it was running (CP start runs recovery). | "Live state untouched" after any failed check. |

---

## 3. Data model (schema v2)

`registry.db` adds:

```sql
file_versions.status CHECK IN ('staged','active','retiring','retired')
rotation_journal(rotation_id, phase, file_id, from_version, to_version, epoch, reason, ts_ms,
                 PRIMARY KEY(rotation_id, phase))       -- phases PREPARE REWRAP STAGE COMMIT DISTRIBUTE COMPLETE ABORTED
rotation_stage_acks(rotation_id, node_id, digest, sig, acked_ms, PRIMARY KEY(rotation_id, node_id))
file_cutoffs(file_id PRIMARY KEY, old_version, from_epoch, grace_ms, committed_ms)
```

`node.db` adds:

```sql
cutoffs(file_id, old_version, from_epoch, grace_ms, applied_mono_ns, applied_ms, PRIMARY KEY(file_id, old_version))
transfers(transfer_id PRIMARY KEY, file_id, version, device_id, account, created_mono_ns, created_ms,
          chunk_count, total_bytes, state CHECK IN ('open','terminated'), reason)
```

Snapshot `files[].cutoff` becomes `null | { old_version, from_epoch, grace_ms }` (well-formed: integers, `1 ≤ old_version < active_version`, `1 ≤ from_epoch ≤ epoch`, `0 < grace_ms ≤ 600000`).

---

## 4. Tasks

### Task 4.0: Contracts and schema v2

**Files:** `src/core/contracts.cjs`, `src/store/schema-cp.cjs`, `src/store/schema-node.cjs`, `tests/unit/contracts.test.cjs`.
- Add `ROTATION` (phases, crash points, grace 30 000 ms, chunk 16 KiB, max file 256 KiB, stage/ack labels, transfer TTL), `STORE_VERSIONS`, new routes and rules; Phase 4 tables under `TABLES.*.P4`.
- Commit `feat(store): phase 4 contracts and schema v2`.

### Task 4.5: Node anti-rollback and cutoff application (built first: 4.1 needs it)

**Files:** `src/node/policy.cjs`, `tests/unit/node-rollback.test.cjs`.
- `wellFormed` accepts cutoffs; `applySnapshot` records cutoffs (`INSERT OR IGNORE`, mono time), terminates open transfers of revoked devices, writes the high-water file after commit; rejects `epoch ≤ applied` or `epoch < high-water`.
- `current()` reports `lease_valid: false` while the store is behind the high-water mark; `acceptHead` refuses heads older than it.
- **Tests:** `old node db fails closed and refuses the old snapshot`; `current snapshot re-applies and the revoked device stays denied`; `cutoff applied once, not reset by a later snapshot`; `malformed cutoff rejected`.

### Task 4.1: Rotation, staging, transfers, cutoff and grace

**Files:** `src/cp/rotate.cjs`, `src/cp/routes-rotate.cjs`, `src/cp/snapshot.cjs` (commit-in-tx helpers, cutoff in snapshot), `src/node/transfers.cjs`, `src/node/routes-transfer.cjs`, `src/node/server.cjs`, `src/device/client.cjs`, `src/device/files.cjs`, `src/cli/rotate.cjs`.
- Journal phases in their own transactions **before** acting; COMMIT per P4-D3; DISTRIBUTE pushes `E` and waits for acks ≥ `E` (10 s); COMPLETE.
- Node: `stage`/`drop` (signed, refused when partitioned, drop never removes the active version); `transfer/start` (authenticated request, op `file.transfer`, grant + key version checked) → `{transfer_id, chunk_count, …, envelope}`; `transfer/chunk` checks, in order: transfer known → not terminated → TTL → lease → device still active → version active, or inside its cutoff's grace and created before the cutoff applied → serve; failures terminate the transfer where final. Retired ciphertext is purged after grace.
- **Tests:** `in-flight transfer completes within grace`; `new old-version request rejected on every node after cutoff`; `transfer terminated after grace` (short grace via library, real 30 s in the e2e test); `missing node ack aborts before commit` (partitioned node); `stage signature required`; `concurrent rotation refused`; `revocation terminates transfers`.

### Task 4.2: Lost device and re-key

**Files:** `src/cp/lostdevice.cjs`, `src/cp/files.cjs` (provisioning), `src/cli/lost.cjs`, `src/cli/device.cjs`.
- `kig lost --device <d>` → CP route: revoke (idempotent if already revoked) → wait for node acks and report per-node latency → rotate every file granted to the device's account.
- **Tests:** `old envelope cannot open new version`; `peer and replacement read`; `re-enrol without approval refused` (pending device denied everywhere; revoked approver refused).

### Task 4.3: Crash injection and recovery

**Files:** `src/cp/recover.cjs`, `src/cp/server.cjs`, `src/cli/supervisor.cjs` (restart one service), `src/cli/crash-test.cjs`.
- `KIG_CRASH_AT` honoured only with `NODE_ENV=test` or `KIG_CRASH_HARNESS=1` (set by `kig crash-test`).
- `recover(cpDb)` → `{action: 'none'|'abort'|'roll_forward', …}`; runs at CP start and retries until roll-forward completes; retires versions past grace; test-decrypts every active version through the custodian wrap (audit `recovery_verified`, or alert `CP-RECOVERY-UNREADABLE`).
- **Tests:** per crash point: one active version (v for the first three points, v+1 for the last two) on the CP and on every node; revoked device denied on every node; committed data decrypts for the peer on every node; CP and node epochs never decrease; journal terminal; `verify-log` OK.

### Task 4.4: Backup and restore

**Files:** `src/cp/backup.cjs`, `src/cli/backup.cjs` (`backup`, `restore`).
- §13.1/§13.2 exactly; failure categories `bad_signature`, `unsupported_schema`, `digest_mismatch`, `stale_backup`, `decrypt_failed`, `incomplete_backup`.
- **Tests:** valid restore; flipped bit; truncation; bad signature; unsupported schema (validly signed); older epoch (live and anchor minimum); wrong recovery key; missing key material; live files byte-identical after every failure.

### Task 4.6: Gate test, evidence, docs

**Files:** `tests/e2e/phase4-demo.test.cjs`, `tests/crash/rotation-crash.test.cjs`, `evidence/phase4.md`, `README.md`, `docs/implementation-plan.md`.

---

## 5. Limits to state in the evidence

- One host, one monotonic clock, loopback HTTP; grace and lease are node-local monotonic.
- The CP is the key custodian (KMS model): it decrypts during rotation. Content or keys a lost device copied before the loss cannot be recalled.
- Envelopes at rest are not forward-secret.
- Files are capped at 256 KiB (P4-D9).
- Node anti-rollback protects against restoring an old `node.db`, not against an attacker who controls the node's whole directory.
- The recovery private key sits in `KIG_HOME/operator/` for the demo; in a real deployment it is offline.
