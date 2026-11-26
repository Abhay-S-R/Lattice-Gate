# Key Identity Guard (KIG)

Post-quantum protected file sharing and end-to-end messaging that continues enforcing access decisions as keys rotate, devices are lost, and user permissions change — backed by an offline-verifiable audit log and an explainable, zero-ML anomaly detector. Built for **DevForge Track 4: "Trust, but verify"**.

> **Primary security claim:** After a device credential is revoked and every participating service node has applied the signed revocation epoch, that device cannot obtain new protected file content or establish/continue a protected messaging session. Every connection performs a full authenticated handshake (session resumption is not supported by design). Other authorized devices retain uninterrupted access, and operators can verify the recorded security event chain offline against an external ML-DSA-65 checkpoint. *(Scope: governs future access only; revocation cannot erase plaintext or keys copied before device loss.)*

Design & evidence: [`docs/features.md`](docs/features.md) (specification & decisions) · [`docs/architecture.md`](docs/architecture.md) (architecture & protocols) · [`evidence/evidence-sheet.md`](evidence/evidence-sheet.md) (12-goal evidence sheet) · [`evidence/final-5410c49/SUMMARY.md`](evidence/final-5410c49/SUMMARY.md) (11/11 replica run)

---

## Dependencies

- **Runtime dependencies: None.** KIG uses **only Node.js `24.11.1` built-in modules** (`node:crypto` with OpenSSL `3.5.4` FIPS 203 `ML-KEM-768`, FIPS 204 `ML-DSA-65`, `AES-256-GCM`, `HKDF-SHA-256`, `HMAC-SHA-256`; `node:sqlite` with SQLite `3.50.4` WAL; `node:http`; `node:child_process`; `node:util`; `node:test`). There is **no `npm install` step** and `package.json` declares zero `dependencies` or `devDependencies`.
- **Optional development / verification tools (never loaded by runtime code):**
  - [ScalerOpenSourceLabs/Track-4-Toolkit](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit) cloned alongside this repo as `../Track-4-Toolkit` (or pointed to via `TOOLKIT_DIR`) — supplies `validate.py` and the 22-event `practice/` dataset used in `kig demo` Step 10 and detector regression tests.
  - Python `3.12` + `pqcrypto==0.4.0` — used solely by `tests/interop/` to verify independent `ML-KEM-768` + `HMAC-SHA-256` decapsulation against `protected_read` (skipped with a visible notice if absent).
  - Docker (Docker Desktop on Windows/macOS, or Docker Engine on Linux) — runs the exact offline, read-only `linux/amd64` judging container replica via `scripts/judge.cjs` and `scripts/collect-evidence.cjs`.

---

## Clean-Machine Quick Start

### Path A: Native Node.js `24.11.1` (Linux, macOS, WSL, Windows)

1. **Install Node.js `24.11.1`:**
   - Linux / macOS / WSL (`nvm`): `nvm install 24.11.1 && nvm use 24.11.1` (`.nvmrc` pins `24.11.1`)
   - Windows / macOS installer: download `v24.11.1` from https://nodejs.org/en/blog/release/v24.11.1 (or `nvm install 24.11.1` via `nvm-windows`)
2. **Clone this repository and the organizer toolkit side by side:**
   ```sh
   git clone https://github.com/Abhay-S-R/devforge.git
   git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git
   cd devforge
   ```
3. **Verify the runtime and run the full 12-step narrated demo (no `npm install` needed):**
   ```sh
   node --version              # must print v24.11.1
   npm run compat              # 11/11 crypto & SQLite concurrency/crash self-checks PASS
   node kig.cjs demo           # 12/12 narrated steps PASS (~40 s incl. real 30 s grace; --fast runs in ~9 s)
   npm run validate            # official toolkit validate.py -> "Local scenario passed."
   npm test                    # 423 unit, contract, negative, concurrency, crash, interop & e2e tests
   ```

### Path B: Docker Judging Replica (no host Node `24.11.1` or `pqcrypto` install required)

If Docker is installed (with any Node `>= 18` on the host to invoke the wrapper script), run inside the exact `linux/amd64` (`--read-only`, `--network none`, non-root, Node `24.11.1` + Python `3.12` + `pqcrypto==0.4.0`) replica:

```sh
git clone https://github.com/Abhay-S-R/devforge.git
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git
cd devforge

node scripts/judge.cjs node kig.cjs compat
node scripts/judge.cjs node scripts/validate.cjs
node scripts/judge.cjs node kig.cjs demo
node scripts/judge.cjs npm test
```

---

## Measured Results Summary (`commit 5410c49`, `linux/amd64` replica)

Full pre-defined expectations, procedures, raw artifacts, and limits are in [`evidence/evidence-sheet.md`](evidence/evidence-sheet.md) and [`evidence/final-5410c49/SUMMARY.md`](evidence/final-5410c49/SUMMARY.md).

| # | Track 4 Goal | Status | Observed Result (`linux/amd64` replica) | Evidence |
|---:|---|---|---|---|
| 1 | **Key rotation** | `measured` | Epoch-based cutoff; **30 s node-local grace** allows pre-authenticated in-flight transfers to finish, then terminates (`grace_expired`); new old-key requests rejected (`old_key_version`) on all 3 nodes (`rotate` `p50 = 134.7 ms`) | [`demo.json`](evidence/final-5410c49/demo.json), [`phase4.md`](evidence/phase4.md) |
| 2 | **Revocation across nodes** | `measured` | `100/100` revocations enforced on nodes `A, B, C`; first-denial `p50 = 32.7–33.7 ms` (`p95 = 45.8–48.3 ms`, last-node max `160.5 ms`); partitioned node fails closed at `5,000 ms` lease (`lease_expired`); peer keeps access; second-factor re-enrolment verified | [`bench-revocation.json`](evidence/final-5410c49/bench-revocation.json), [`demo.json`](evidence/final-5410c49/demo.json) |
| 3 | **Crash recovery** | `measured` | `5/5` `SIGKILL` rotation phases (`50/50` invariant checks): pre-commit crashes abort (`v1` kept), post-commit crashes roll forward (`v5, v6`); revocations persist; rolled-back `node.db` blocked by high-water mark | [`crash-test.json`](evidence/final-5410c49/crash-test.json), [`phase4.md`](evidence/phase4.md) |
| 4 | **Backup integrity** | `measured` | ML-DSA-65 signed + ML-KEM-768 / AES-256-GCM encrypted backup (`317 KiB`); all 6 tamper/rollback classes (`bad_signature`, `unsupported_schema`, `digest_mismatch`, `stale_backup`, `decrypt_failed`, `incomplete_backup`) refused with live DB byte-identical | [`demo.json`](evidence/final-5410c49/demo.json), [`test.txt`](evidence/final-5410c49/test.txt) |
| 5 | **Log integrity** | `measured` | Length-prefixed binary encoding + SHA-256 chain + external ML-DSA-65 anchor; detects edits, deletions, reorderings, and post-checkpoint truncation; newline-JSON actor injection stays a single record (`verifyChain` 1k events `p50 = 21.0 ms`, `~229 B/event`) | [`adapter-walkthrough.txt`](evidence/final-5410c49/adapter-walkthrough.txt), [`demo.json`](evidence/final-5410c49/demo.json) |
| 6 | **Routine vs. suspicious activity** | `measured` *(synthetic)* | Practice set: `22/22` events handled (`0` false alerts). Held-out synthetic seeds `201–205` (`6,784` events): Incident **F1 `0.895`** (`P = 1.000, R = 0.810`; `1.000` on detectable, `20` evasive misses reported), **Median TTA `4,810 ms`**, **False alerts / 1k benign `0.00`** | [`detect-practice.json`](evidence/final-5410c49/detect-practice.json), [`bench-detect.json`](evidence/final-5410c49/bench-detect.json), [`phase5.md`](evidence/phase5.md) |
| 7 | **Lateral movement** | `measured` | `evt-010..012` grouped into one `LM-1` `candidate_lateral_movement` alert (`reports->billing->archive->identity`, all `deny`); post-revocation `evt-017/018` excluded as `expected_enforcement`; `evt-020` quiet; invariant across `30–120 s` windows | [`detect-practice.json`](evidence/final-5410c49/detect-practice.json), [`phase5.md`](evidence/phase5.md) |
| 8 | **Clock differences** | `measured` | `±5,000 ms` supported offset, `5,000 ms` reorder watermark, `±250 ms` uncertainty; `evt-015` corrected (`+2,000 ms` -> `200 ms` delay), `evt-013/014` reordered with raw/receipt times preserved; out-of-range flagged `clock_unsupported` & never clamped | [`detect-practice.json`](evidence/final-5410c49/detect-practice.json), [`test.txt`](evidence/final-5410c49/test.txt) |
| 9 | **Replay & recipient binding** | `measured` | Ephemeral ML-KEM-768 + ML-DSA-65 mutual handshake; length-prefixed AEAD AAD binds sender/recipient/session/epoch/seq/chunk; wrong recipient, tampered `recipient_device`, altered AAD, duplicates, and cross-restart replays rejected | [`msg-demo.txt`](evidence/final-5410c49/msg-demo.txt), [`test.txt`](evidence/final-5410c49/test.txt) |
| 10 | **Forward secrecy** | `measured` *(stated scope)* | Ephemeral KEM private key nulled & traffic keys zeroed on close; post-close exposure of long-term ML-DSA-65 signing key signs transcript but cannot open recorded session ciphertexts (`handshake` `p50 = 47.5 ms`) | [`msg-demo.txt`](evidence/final-5410c49/msg-demo.txt), [`bench-perf.json`](evidence/final-5410c49/bench-perf.json) |
| 11 | **Delivery under loss/reordering** | `measured` | Seeded loss/duplication/reordering simulator (`16 KiB` chunks, authenticated `chunk_total`, max 3 retries); receipt (`4/4`), reassembly (`1`), and delivery (`exact once`) reported separately; incomplete/oversize discarded | [`msg-demo.txt`](evidence/final-5410c49/msg-demo.txt), [`demo.json`](evidence/final-5410c49/demo.json) |
| 12 | **Session resumption** | **`not supported`** | Intentionally unsupported (D-05): every session runs a fresh authenticated handshake; closed or post-revocation session IDs/keys are rejected | [`msg-demo.txt`](evidence/final-5410c49/msg-demo.txt), [`demo.json`](evidence/final-5410c49/demo.json) |

**Selected latency & size benchmarks** ([`evidence/final-5410c49/bench-perf.json`](evidence/final-5410c49/bench-perf.json)):
- **Round 1 whole-process (`track4_service.cjs`):** empty Node `p50 = 23.1 ms`; `read` (allow) `p50 = 47.7 ms` (`p95 = 54.1 ms`); `revoke` `p50 = 51.1 ms`; `protected_read` `p50 = 54.1 ms`; near-4 MiB `setup` `p50 = 107.6 ms` (`< 1.5%` of `8 s` validator budget).
- **In-process primitives:** `ML-KEM-768` encaps `0.033 ms` / decaps `0.041 ms` (`pk 1184 B, ct 1088 B, ss 32 B`); `ML-DSA-65` sign `1.03 ms` / verify `0.232 ms` (`pk 1952 B, sig 3309 B`); `AES-256-GCM` `64 KiB` seal `0.066 ms` / open `0.047 ms`; SQLite `audit.append` tx `0.096 ms`; detector `~111,696 events/s`; Round 2 authenticated `file.read` `p50 = 11.6 ms`.

---

## Round 1 Adapter (`track4_service.cjs`)

`track4_service.cjs` at the repository root is the automated Stage 1 entry point. Each invocation reads **one** UTF-8 JSON object from stdin (capped at `4 MiB`), executes inside a SQLite `BEGIN IMMEDIATE` transaction under `$TRACK4_STATE_DIR/kig/adapter.db`, writes **one** JSON object plus `\n` on stdout, and exits without leaving background processes.

```sh
# Bash / Zsh / WSL:
export TRACK4_STATE_DIR=$(mktemp -d)
# PowerShell:
# $env:TRACK4_STATE_DIR = (New-Item -ItemType Directory -Force "$env:TEMP\kig-r1").FullName

echo '{"op":"setup","owners":{"brief":"maya","doc2":"bob"},"contents":{"brief":"demo note","doc2":"peer note"},"disabled":[],"key_material":"synthetic-only"}' | node track4_service.cjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r01"}' | node track4_service.cjs
echo '{"op":"revoke","actor":"maya"}' | node track4_service.cjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r02"}' | node track4_service.cjs
echo '{"op":"audit","request_id":"r02"}' | node track4_service.cjs
echo '{"op":"read","actor":"bob","asset":"doc2","request_id":"r03"}' | node track4_service.cjs
```

| Operation | Response |
|---|---|
| `setup` | `{"ready":true}`, after the new generation is durably committed (audit chain carries across generations) |
| `read` | `{"decision":"allow","body":"…"}` or `{"decision":"deny"}` (revocation checked before ownership; no extra keys on deny) |
| `revoke` | `{}`, after the actor revocation and monotonic epoch bump are durably committed |
| `audit` | `{"request_id":"…","decision":"allow"\|"deny"}` (latest access attempt in current generation; unknown ID -> `deny`) |
| `protected_read` | `{"ciphertext":"<base64 ML-KEM-768 ct>","proof":"<hex HMAC-SHA-256(ss, challenge+body)>"}` or `{"decision":"deny"}` |
| unknown `op` / malformed input | `{"error":"unsupported_operation"}` / `{"error":"invalid_request"}` |

Exit code is `0` for every handled request (including denials and malformed input). Only a `setup` or `revoke` whose state change could not be persisted exits `1`, with empty stdout and one fixed generic stderr line (D-13). `key_material` is never stored, logged, or used as key material (P0-04). Suspicious adapter activity (`A-REVOKED-RETRY`, `A-CROSS-OWNER`, `A-INVALID-INPUT`, `A-INVALID-KEY`, `A-HOSTILE-ID`, `A-BURST`, `A-STATE-FAULT`) is recorded in the hash-chained audit table (P0-10).

---

## Round 2 Operator CLI (`kig.cjs`)

`node kig.cjs <command> [options]` (`node kig.cjs help` lists all commands; `<command> --help` shows flags). Exit codes: `0` ok, `1` check/operation failed, `2` usage error.

| Command | Description |
|---|---|
| `demo [--fast] [--keep] [--home <dir>] [--practice <dir>] [--seed <n>] [--json]` | **Full 12-step narrated end-to-end demonstration** covering all 12 goals on an isolated cluster (`CP` + nodes `A, B, C`) |
| `compat` | Verifies runtime crypto (`ML-KEM-768`, `ML-DSA-65`, `AES-256-GCM`, `HKDF` RFC 5869), SQLite 8-process WAL concurrency, `SIGKILL` atomicity, and `VACUUM INTO` |
| `init [--home <dir>] [--force]` | Creates `KIG_HOME` stores, CP `ML-DSA-65`/`ML-KEM-768` keys, offline operator recovery key, and public trust anchor |
| `up` / `down` / `status` | Starts, stops, and checks the Control Plane (`127.0.0.1:7400`) and Service Nodes `A, B, C` (`7401–7403`; override base with `KIG_PORT_BASE`) |
| `account add <account>` | Registers an account in the Control Plane |
| `device enrol <dev> --account <a>` / `device approve <dev> --by <dev>\|--operator --approval-id <id>` | Generates device `ML-DSA-65` + `ML-KEM-768` keystore with signed proof-of-possession; activates after operator or active peer-device approval |
| `file publish <file> --as <dev> --input <path>` / `file read <file> --device <dev> --node <A\|B\|C>` | Envelope-encrypts file (`<= 256 KiB`) under random `AES-256-GCM` DEK wrapped per device via `ML-KEM-768`; reads via challenge-signed node request |
| `share <file> --with <account>` | Grants an account access and issues device-bound DEK envelopes |
| `rotate --file <file>` | Stages `v+1` across all nodes with signed stage acks, commits epoch cutoff, allows 30 s node-local grace for in-flight transfers, rejects new old-version requests |
| `revoke --device <dev>` | Commits revocation epoch and pushes signed policy snapshot to all nodes |
| `lost --device <dev>` | Revokes lost device across all nodes (printing per-node signed-ack latency) and rotates every file it could access |
| `node partition <A\|B\|C>` / `node heal <A\|B\|C>` | Isolates a node from the CP to demonstrate fail-closed `lease_expired` enforcement after `5 s`, then heals |
| `crash-test [--point <p>] [--json] [--out <file>]` | `SIGKILL`s the CP at `after_prepare`, `after_stage`, `before_commit`, `after_commit`, and `during_distribute`, restarts, and checks 10 recovery invariants |
| `backup --out <dir>` / `restore <dir> --recovery-key <file> --anchor <file>` | Creates/restores `ML-DSA-65`-signed, `ML-KEM-768`-wrapped `AES-256-GCM` CP backups with strict 6-stage anti-rollback validation |
| `keys init --out <dir> [--force]` | Generates operator `ML-DSA-65` audit-signing keypair (`0600` private key) |
| `checkpoint (--adapter <dir> \| --db <file>) --key <file> --anchor <file>` | Signs current audit-chain head and appends to an external trust anchor |
| `verify-log (--adapter <dir> \| --db <file>) [--anchor <file>]` | Offline audit verification (`OK <count> <head>` or `BROKEN seq=<n> <reason>`) |
| `alerts [--adapter <dir> \| --db <file>] [--json] [--limit N]` | Displays self-monitoring alerts newest-first with terminal-safe control/bidi escaping |
| `detect --events <csv\|jsonl> [--approvals <json>] [--baseline <json>] [--json]` | Runs explainable privilege-escalation (`PRIV-1/2`), lateral-movement (`LM-1/2/3`), clock-offset, and reorder-buffer detection |
| `msg demo [--seed <uint32>]` | Runs the 13-check post-quantum E2EE messaging, replay, chunked loss/reordering, forward-secrecy, and revocation demo |
| `bench perf [--runs <n>] [--no-cluster] [--json] [--out <file>]` | Measures whole-process adapter, in-process PQC/AEAD/SQLite/detector/messaging, and Round 2 cluster latencies + byte sizes |
| `bench revocation --n 100 --seed <s> [--json] [--out <file>]` | Measures per-node first-denial & signed-ack percentiles (`n=100`) and partition lease bound |
| `bench detect --seeds <list> --holdout <list> [--json] [--out <file>]` | Runs disjoint tuning & held-out synthetic detection benchmark |

**Pinning and verifying an adapter audit log offline:**
```sh
node kig.cjs keys init --out ~/kig-operator
node kig.cjs checkpoint --adapter "$TRACK4_STATE_DIR" --key ~/kig-operator/audit-signing.key --anchor ~/kig-operator/adapter-anchor.json
node kig.cjs verify-log --adapter "$TRACK4_STATE_DIR" --anchor ~/kig-operator/adapter-anchor.json
node kig.cjs alerts --adapter "$TRACK4_STATE_DIR"
```

---

## Testing & Reproducing All Evidence

`npm test` executes all **423 tests** using Node's built-in `node:test` runner (`--test-concurrency=1`):

| Suite | Location | What it verifies |
|---|---|---|
| Unit | `tests/unit/` | Crypto provider (RFC 5869 HKDF vector, FIPS 203 bad-key rejection, ML-DSA context separation, AEAD tamper), single-importer `node:crypto` guard, opaque IDs, binary encoder, SQLite busy-retry/quarantine, schemas, audit chain, checkpoints, CLI router, HTTP caps, policy snapshots, leases, rotation, lost-device, backups, anti-rollback, detector stages, label-isolation guard, messaging cross-restart replay, `bench perf` |
| Adapter contract | `tests/adapter/contract.test.cjs` | Fresh `track4_service.cjs` process per request, error policy (D-13), response shapes (D-16), `4 MiB` stdin cap, invalid UTF-8 |
| Negative & leak scan | `tests/negative/` | Hostile IDs (`__proto__`, `constructor`, lone surrogates, embedded NUL, newline+fake JSON, `../`), strict Base64, `key_material` byte-scan across stdout/stderr/DB/WAL |
| Concurrency | `tests/adapter/concurrency.test.cjs` | 8 parallel processes × 20 rounds (warm and cold empty-dir start): zero lost revocations, linear valid hash chain |
| Crash recovery | `tests/crash/` | `SIGKILL` mid-transaction on adapter `revoke` + all 5 CP rotation crash phases |
| End-to-end | `tests/e2e/` | Full live-cluster Gate 4 scenario (incl. real 30 s grace + `node.db` rollback), `kig msg demo` (seeds `2026`, `42`), and 12-step `kig demo --fast` |
| Cross-impl interop | `tests/interop/` | Python `3.12` + `pqcrypto==0.4.0` decapsulates `protected_read` `ML-KEM-768` ciphertexts and verifies `HMAC-SHA-256` proofs (`25/25`, Unicode bodies). *Skips with a notice if `pqcrypto` is not installed.* |

*(Note: `tests/unit/detect/pipeline-practice.test.cjs` and `tests/e2e/demo.test.cjs` read `../Track-4-Toolkit/practice` or `$TOOLKIT_DIR/practice`.)*

**Reproduce the entire submission evidence bundle in one command** (builds the `linux/amd64` replica and runs all 11 verification checks, writing `evidence/final-<commit>/SUMMARY.md`):

```sh
node scripts/collect-evidence.cjs
```

See [`evidence/README.md`](evidence/README.md) for an index of all per-phase and final evidence reports.

---

## Limitations & Honest Scope Boundaries

### Round 1 Judging Adapter
- **Unauthenticated `actor` input (P0-05):** The Round 1 contract supplies `actor` as a plain string without a device signature. The adapter enforces authorization and revocation policy for that supplied actor; cryptographic device authentication is exercised in Round 2.
- **Input-channel threat boundary (D-14, D-15):** Round 1 defends stdin, stdout, stderr, exit codes, and SQLite transaction integrity. Because no key exists outside `TRACK4_STATE_DIR`, adapter asset bodies are stored in plaintext SQLite and direct host/filesystem access to `TRACK4_STATE_DIR` is out of scope.
- **`protected_read` scope:** Demonstrates authorization-gated `ML-KEM-768` encapsulation + `HMAC-SHA-256` proof interoperability, not end-to-end messaging, recipient binding, or forward secrecy (covered in Round 2 `kig msg demo`).
- **`threat-model.json` intentionally omitted (P0-09):** The toolkit's example `"boundary": "identity-check"` would over-claim identity verification for the unauthenticated Round 1 adapter input.

### Round 2 System, Cryptography & Detector
- **Control Plane is a trusted KMS custodian:** The CP holds a custodian `ML-KEM-768` wrap of file DEKs so it can re-key files during rotation and device loss. Service nodes (`A, B, C`) never see plaintext or raw DEKs, but a compromised CP can decrypt stored files. (Device-to-device messaging uses ephemeral KEM keys unknown to the CP.)
- **Future-access revocation only:** Revoking a lost device and rotating file DEKs prevents new reads and new/continued sessions, but cannot erase plaintext or keys copied onto the device before it was reported lost.
- **At-rest envelopes vs. completed sessions:** Messaging sessions achieve forward secrecy against later exposure of long-term `ML-DSA-65` signing keys; static per-device file DEK envelopes at rest are **not** forward-secret.
- **Best-effort memory zeroisation:** Ephemeral keys and shared secrets in `Buffer` objects are overwritten with zeros (`fill(0)`), but managed V8/JavaScript memory cannot guarantee physical RAM erasure.
- **Single-host loopback cluster & file cap:** CP and nodes `A, B, C` run as separate OS processes with separate SQLite databases over `127.0.0.1` sharing one host monotonic clock; measured propagation latencies exclude WAN jitter. Published files are capped at `256 KiB` so signed stage payloads stay under the `1 MiB` HTTP body cap.
- **Node rollback scope:** `node.db.epoch` prevents a restored stale `node.db` from re-enabling revoked devices, though a rolled-back node fails closed (`unknown_file`) for file versions staged after its backup until re-provisioned, and full node-directory compromise is out of scope.
- **Audit tail truncation without an external anchor:** A SHA-256 hash chain alone cannot detect deletion of trailing records; tail-truncation detection requires verifying against an externally retained `ML-DSA-65` checkpoint (`--anchor`).
- **Synthetic detection data & known evasions:** Detection benchmark metrics (`F1 = 0.895`, `0.00` false alerts/1k) come from a seeded synthetic generator, not production enterprise logs. Probes spaced wider than the `60 s` window (low-and-slow) and 2-edge denied probes fall below `LM-1`/`LM-3` thresholds (`0/20` detected, reported honestly in [`evidence/phase5.md`](evidence/phase5.md)). Clock offsets outside `±5,000 ms` are flagged `clock_unsupported` and ordered by receipt rather than corrected.
- **Unsupported optional features:** Session resumption is **not supported** (`D-05`, Goal 12); hybrid classical + PQ key exchange (`X-Wing`) is not built.
