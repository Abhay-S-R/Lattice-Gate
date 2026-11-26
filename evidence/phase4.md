# Phase 4 evidence: rotation, lost-device re-key, crash recovery, backups (Gate 4)

Code under test: commit `83f2294` (branch `phase-4-rotation`, merged with `main` incl. Phase 6 messaging, with D12 revised to add tables in place). Earlier passing runs of the same checks: `6984769` (Phase 4 alone) and `cca2fa5` (after the merge, before the D12 revision); their logs are kept in [`superseded/`](superseded/) as `*-6984769.txt` and `*-cca2fa5.txt`. Every command below ran inside the judging-container replica (`node scripts/judge.cjs …`): linux/amd64 (x86-64, native), Node.js v24.11.1, OpenSSL 3.5.4, SQLite 3.50.4, read-only root, no network, writable `/tmp` only. Plan and design decisions: [`docs/plans/phase-4.md`](../docs/plans/phase-4.md).

Specs: features P1-03 (re-key half), P1-04, P1-06, P1-07, D-06, D-07; architecture §11–§13, §17.2.

## 1. Gate 4 result

| Gate item | Result | Evidence |
|---|---|---|
| §17.2 demo steps 4–8 as one scripted test | **PASS** (34.3 s, including the real 30 s grace) | `tests/e2e/phase4-demo.test.cjs`, [`phase4-npm-test-83f2294.txt`](phase4-npm-test-83f2294.txt) |
| `kig crash-test` at all 5 crash points | **PASS 5/5** | [`crash-test-83f2294.txt`](crash-test-83f2294.txt) |
| Full suite | **414 tests, 414 pass, 0 fail, 0 skipped** (Phase 1–5 included) | [`phase4-npm-test-83f2294.txt`](phase4-npm-test-83f2294.txt) |
| Round 1 adapter untouched | **PASS** `Local scenario passed.` | [`validate-83f2294.txt`](validate-83f2294.txt) |

## 2. What each demo step showed (one cluster: CP + nodes A, B, C)

| Step | Goal | Shown |
|---|---|---|
| 4 Rotation in flight | 1 | Bob opened a 3-chunk transfer of `brief` v1 on node A and fetched chunk 0. `kig rotate --file brief` → `1 -> 2 (complete)`. Chunks 1–2 were then served with rule `grace` and the file decrypted. A **new** v1 transfer and a v1 one-shot read were refused (`old_key_version`) on **each** of A, B, C, while v2 reads succeeded. Every node's snapshot carried `cutoff {old_version: 1, grace_ms: 30000}`. After cutoff + 30 s the old transfer was ended with reason `grace_expired`, and the retired ciphertext was purged from the nodes. |
| 5 Lost device | 2 | `kig lost --device alice-phone` revoked it, printed each node's signed-ack latency from the revocation commit, and re-keyed `brief` 2 → 3. alice-phone was denied (`device_revoked`) on every node. |
| 6 Re-enrol, peer, old material | 2 | `alice-phone-2` while pending: `unknown_device` on every node. Approval signed by the lost phone was refused (`approver_not_active`); approval by `alice-laptop` worked and issued its v3 envelope. Replacement and Bob read v3 through every node. The phone's v1 key cannot open v3 ciphertext. |
| 7 CP crash | 3 | CP restarted with `KIG_CRASH_AT=before_commit`; `kig rotate` lost its connection as the CP SIGKILLed itself after staging v4. After a normal restart, recovery aborted the rotation: v3 still active on the CP and every node, alice-phone still denied everywhere, Bob reads v3 everywhere, and the epoch is not lower. |
| 8 Backup | 4 | Backup with the cluster up; then cluster down. A flipped byte and a truncated payload were each refused with `digest_mismatch`, and the backup taken at step 3 with `stale_backup`. `registry.db` stayed byte-identical after every refusal. The current backup restored, `kig up` worked, Bob read v3 through every node, and `verify-log` was OK. |
| Anti-rollback (4.5) | 3 | Node A's store from step 3 (alice-phone active) was copied back in place. After `kig up`, node A re-applied a snapshot at least as new as its high-water mark and denied alice-phone. It served no stale data: v3, staged after the copy, is refused with `unknown_file` on A, while B and C serve it. |

## 3. Crash test (`node kig.cjs crash-test`)

All five points run in order on one isolated cluster. Each point: arm the CP with `KIG_CRASH_AT`, ask it to rotate, confirm it died with the expected last durable journal phase, restart normally, then check 10 invariants.

```
PASS after_prepare     abort        rotation v1->v2, active after recovery v1
PASS after_stage       abort        rotation v1->v3, active after recovery v1
PASS before_commit     abort        rotation v1->v4, active after recovery v1
PASS after_commit      roll_forward rotation v1->v5, active after recovery v5
PASS during_distribute roll_forward rotation v5->v6, active after recovery v6
```

Checks per point: CP killed at the point with no answer; journal phase at the crash (PREPARE, STAGE, STAGE, COMMIT, DISTRIBUTE); recovery outcome (ABORTED or COMPLETE); exactly one active version on the CP and no staged leftovers; the same active version on A, B and C; CP and node epochs never lower; revoked device denied on every node; 6/6 reads (Bob and alice-laptop × 3 nodes) decrypt the expected version; custodian test-decrypt after recovery; audit chain intact. Aborted versions 2–4 are never reused.

## 4. Other acceptance tests (all in the suite above)

- **Rotation:** a partitioned node gives no stage ack, so the rotation aborts before commit with `missing_stage_ack: B`, no epoch is published and A/C drop the staged data. Version numbers are not reused. Stage and drop need the CP signature, and the signature binds the content. The active version can never be overwritten or dropped. A concurrent rotation is refused. Revocation ends the device's open transfers.
- **Backup/restore:** every category — `bad_signature` (flipped sig, edited field, foreign signer, unsigned extra field, missing sig), `unsupported_schema`, `digest_mismatch` (nonce/ciphertext/tag flips, truncation, missing payload), `stale_backup` (versus the live CP and versus the anchor minimum after losing the live registry), `decrypt_failed` (wrong recovery key), `incomplete_backup` (missing master key, garbage DB, foreign policy key, wrong master key). Live files are byte-identical after each refusal. Checks run in §13.2 order.
- **Node anti-rollback (unit):** a rolled-back store fails closed (`lease_expired`) even while its recorded lease is fresh, and refuses the old snapshot and head. A corrupt high-water file fails closed until the next apply. Cutoffs are recorded once and not reset by later snapshots.
- **Size cap:** publish accepts 256 KiB and refuses one byte more.

## 5. Limits (read before quoting anything above)

- One host, one monotonic clock, loopback HTTP. Grace (30 s) and lease (5 s) are node-local monotonic times; latencies exclude real networks.
- The CP is the key custodian (KMS model). It decrypts during rotation. Plaintext or keys a lost device copied before the loss cannot be recalled; revocation and re-keying stop new access only.
- Envelopes at rest are not forward-secret.
- Transfer IDs are 32-byte bearer tokens. They are bound to one device and version on one node, ended at revocation, grace expiry or 10 minutes.
- Files are capped at 256 KiB, so a staged version fits one signed HTTP message.
- Node anti-rollback protects against an old `node.db` being put back, not against an attacker controlling a node's whole directory. A rolled-back node does not receive versions staged after its copy; it fails closed for them.
- At the CP an old version is `retired` from commit; its grace window is enforced only by the nodes, on their own clocks.
- Stores stay at schema version 1; Phase 4 tables are added in place (P4-D12), so homes created before Phase 4 keep working (`tests/unit/phase4-upgrade.test.cjs`).
- The recovery private key sits in `KIG_HOME/operator/` for the demo; operationally it is kept offline. `kig backup` raises `min_backup_epoch` in the anchor, so after a newer backup an older one is refused even if the live CP is lost.
- Results are from the local replica. No hosted CI run is recorded here.
