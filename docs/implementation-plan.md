# Key Identity Guard: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to carry out this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Key Identity Guard. First build the Round 1 judging adapter (`track4_service.cjs`), hardened against hidden tests and exploits. Then build the Round 2 system (control plane, 3 nodes, devices, detector, messaging), presented through the `kig` CLI.

**Architecture:** A shared core (identifier encoding, audit chain, policy, alerts, crypto provider, SQLite helper) sits under two entry points:
- the one-process-per-request adapter, for Round 1;
- the `kig` CLI driving long-running local processes, for Round 2.

See `architecture.md` §1.

**Tech stack:** Node.js 24.11.1 built-ins only (`node:crypto`, `node:sqlite`, `node:fs`, `node:http`, `node:child_process`, `node:test`). No npm dependencies. CommonJS. Dev-only: Python 3.12 + `pqcrypto==0.4.0` (interop test), Docker, and GitHub Actions on ARM64.

**Spec:**
- `docs/features.md` v0.4 (what and why: D-01 to D-17, P0-xx/P1-xx)
- `docs/architecture.md` v1.0 (how: § references below)
- Executors read both. If this plan and the spec disagree, the spec wins; fix this plan.

---

## How this plan is organised (and why)

| Phase | Name | Round | Depends on | Why it sits here |
|---|---|---|---|---|
| **0** | Foundation and test environments | both | n/a | Nothing is trustworthy until the crypto works on **ARM64** and we can rehearse the judging container. Cheap, and it removes the biggest unknown first. |
| **1** | Round 1 adapter (S1) | 1 | 0 | Round 1 decides whether anyone ever sees Round 2. It is the only thing the automated stage runs. It is also the smallest complete product, and it builds the shared core every later phase reuses. |
| **2** | Audit verification and CLI skeleton (S2) | 2 | 1 | Every later component logs through the audit chain. Verifying it early means later phases get tamper evidence for free. It is also the first CLI command the judges will use. |
| **3** | Control plane, nodes, devices, files, revocation (S3 + revocation half of S4) | 2 | 2 | The Round 2 backbone. Goals 2 and 5, and everything in Phase 4, need enrolled devices, signed snapshots and three nodes. |
| **4** | Rotation, lost-device re-key, crash recovery, backups (rest of S4 + S5) | 2 | 3 | Goals 1, 3 and 4 are all built on rotation and the CP journal. |
| **5** | Detector and benchmark (S6) | 2 | 0 only | Pure functions over event files, with no dependency on Phases 1–4. **Can run in parallel from day 1** on a separate person or branch. |
| **6** | Secure messaging (S7) | 2 | 3.5 (device keystore) | Goals 9–12. The largest new attack surface, so it is built after the platform is stable. 6.3 is the first thing cut if time runs out. |
| **7** | Evidence, demo, submission (S8) | both | 1–6 | Measured numbers, `kig demo`, README, threat model, brief and video. Starts properly once Phase 1 has passed its gate, because the brief and README need its evidence. |

**Gates are hard.** A phase is done only when its gate commands pass, in the judging container where stated. After the Phase 1 gate, the adapter is **frozen**: changes only for bugs, each with a regression test.

**Cut order if time runs short** (features §9): P2 items → LM-2 → 6.3 chunking (mark Goal 11 `partial`) → 4.4 backup (mark Goal 4 `partial`) → dashboards. **Never cut:** Phase 1, Phase 2, P0-10 alerts, threat-model honesty.

**Parallel tracks for 2–4 people** (team capacity not yet confirmed, features Q9):

| Track | Phases |
|---|---|
| A, security core | 0 → 1 → 2 → 3 → 4 |
| B, detector | 0.1 → 5 (independent), then helps 7 |
| C, messaging | joins after 3.5 → 6 |
| D, evidence and docs | starts README, evidence sheet and threat model skeleton at Phase 1; owns 7 |

**Working rules:**
- One branch per phase (`phase-1-adapter`, …), merged by PR after its gate.
- Commit after every task: `feat(<area>): …`, `test(<area>): …`, `fix(<area>): …`.
- Develop inside WSL Ubuntu (Linux paths and permissions match the judging container).
- Every test file is named `*.test.cjs` and runs with `node --test`.

---

## Global constraints

Every task implicitly includes these. Values are copied from the spec.

- Runtime **Node.js 24.11.1**; judging is **linux-arm64**, offline, with a read-only root and only the temp dir writable (D-17, P0-02).
- **Zero npm dependencies.** `package.json` has no `dependencies` or `devDependencies`. Only `node:*` built-ins are allowed.
- CommonJS `.cjs` only; no build step.
- Only `src/crypto/provider.cjs` may `require('node:crypto')` (architecture §1.3). Enforced by a test in Task 0.2.
- Every client-supplied string, **including bodies**, is stored as `JSON.stringify(value)` (D-04). Client data is never used as a plain-object key, file name or SQL text.
- Adapter responses use exactly these shapes (D-16):
  - `setup` → `{"ready":true}`
  - `read` → `{"decision":"allow","body":…}` or `{"decision":"deny"}`
  - `revoke` → `{}`
  - `audit` → `{"request_id":…,"decision":…}`
  - `protected_read` → `{"ciphertext":…,"proof":…}` or `{"decision":"deny"}`
  - otherwise `{"error":"unsupported_operation"}` or `{"error":"invalid_request"}`
- Exit codes (D-13, architecture §5.6): only `revoke` and `setup` may exit 1, and only when state could not be persisted. stdout then stays empty and stderr carries exactly `Request failed; inspect team application locally.\n`.
- stdout is exactly one JSON object followed by `\n`; stderr is empty on success. `process.removeAllListeners('warning')` is the first statement of every entry point.
- `key_material` is never stored, logged, printed or used (P0-04).
- No AI/ML components in the code. No custom cryptographic primitives.
- Limits (`src/core/limits.cjs`):

  | Constant | Value |
  |---|---|
  | `MAX_STDIN_BYTES` | 4 MiB |
  | `MAX_ID_LEN` | 8192 UTF-16 code units |
  | `MAX_CHALLENGE_LEN` | 4096 |
  | `KEM_PK_BYTES` | 1184 |
  | `BUSY_TIMEOUT_MS` | 5000 |
  | `BUSY_RETRIES` | 3 |
  | jitter | 20–80 ms |
  | `BURST_N` | 5 |
  | `BURST_WINDOW_MS` | 60000 |

- ML-DSA context strings: `kig/v1/request`, `kig/v1/handshake`, `kig/v1/revocation`, `kig/v1/checkpoint`, `kig/v1/backup`.

## Review focus

The five input classes most likely to break the adapter that the spec implies but a happy-path test would never exercise. Each is pinned to a test in its owning task.

1. **Identifiers that are not "normal strings":** `__proto__`, `constructor`, lone surrogates, NUL, newline + fake JSON, the empty string, used as actor, asset, request_id and owners/contents **keys**. Expected: each is a distinct identity, round-trips exactly and never crashes. → Task 1.1 `ids.test.cjs`, Task 1.15 `negative.test.cjs` "prototype keys in setup maps".
2. **Parallel adapter processes on an empty state dir** (several `revoke`/`setup`/`read` racing to create the database). Expected: no non-zero exit on read/audit, no lost revocation, valid chain. → Task 1.3 `db.test.cjs` "parallel create", Task 1.15 `concurrency.test.cjs`.
3. **Operations out of the expected order:** `revoke` before any `setup`, `read`/`audit` before `setup`, `setup` twice in the same dir, and `audit` of an ID from the previous generation. Expected: an early `revoke` is persisted and acknowledged; `read`/`audit` before `setup` deny without crashing or creating files; a second `setup` serves only its own data; an old-generation request ID is unknown. → Tasks 1.8, 1.10, 1.11.
4. **`protected_read` keys that look almost right:** URL-safe Base64, Base64 with whitespace, 1183/1185 bytes, 1184 × `0xFF`. Expected: deny, exit 0, no ciphertext. → Task 1.12.
5. **Bodies and challenges with non-ASCII text** (`ünïcode ✓`, emoji, lone surrogate) in `read` round trips and `protected_read` HMAC. Expected: exact body back; proof computed over UTF-8 and verifiable by `pqcrypto`. → Task 1.9 "unicode body", Task 1.16 interop.

> Note on 3: a `revoke` that arrives before any `setup` is persisted in the current generation (generation 0). The next `setup` starts a new generation and **replaces** the revoked set with its own `disabled` list (D-01). Task 1.10 pins this exact behaviour, so it is a decision, not an accident.

---

## File map (Phases 0–2, exact; later phases list files per task)

```
package.json                     scripts + engines; no dependencies              (0.1)
.nvmrc                           24.11.1                                         (0.1)
.gitignore                                                                       (0.1)
README.md                        grows each phase; final in 7.4                  (0.1)
track4_service.cjs               Round 1 transport (adapted starter)             (1.14)
team_app.cjs                     handleRaw(buf) → src/adapter/index.cjs          (1.14)
kig.cjs                          CLI entry: node kig.cjs <cmd>                   (0.3, 2.1)
src/core/limits.cjs              all constants                                   (1.1)
src/core/ids.cjs                 D-04 encoding + hostile-ID check                (1.1)
src/core/encoding.cjs            length-prefixed encoder (D-08)                  (1.2)
src/core/audit.cjs               append + chain + verify                         (1.5, 2.2)
src/core/policy.cjs              authorizeOwnerRead                              (1.7)
src/core/alerts.cjs              P0-10 rules                                     (1.13)
src/crypto/provider.cjs          only node:crypto importer                       (0.2)
src/store/db.cjs                 open/retry/pragmas/tx/quarantine                (1.3)
src/store/schema-adapter.cjs     adapter DDL v1                                  (1.4)
src/adapter/validate.cjs         request schemas                                 (1.6)
src/adapter/ops.cjs              setup/read/revoke/audit/protectedRead           (1.8–1.12)
src/adapter/index.cjs            parse → route → op → error policy               (1.14)
src/cli/compat.cjs               kig compat                                      (0.3)
src/cli/main.cjs                 command router                                  (2.1)
src/cli/verify-log.cjs, checkpoint.cjs, alerts.cjs                               (2.2–2.4)
tests/helpers/run-adapter.cjs    spawn adapter like the worker                   (1.14)
tests/unit/*.test.cjs  tests/adapter/*.test.cjs  tests/negative/*.test.cjs
tests/crash/*.test.cjs tests/interop/*                                           (per task)
tools/judge/Dockerfile           judging-container replica                       (0.4)
scripts/judge.sh                 run anything inside the replica                 (0.4)
scripts/validate.sh              toolkit validate.py against root adapter        (0.5)
.github/workflows/ci.yml         ARM64 CI                                        (0.4)
evidence/                        validator output, bench results, evidence sheet
```

---

# Phase 0: Foundation and test environments

**Gate 0:** `node kig.cjs compat` prints all PASS on the GitHub `ubuntu-24.04-arm` runner inside `node:24.11.1`; `scripts/judge.sh node kig.cjs compat` passes locally under emulated arm64; `scripts/validate.sh` runs (behaviour checks may fail, because the stub isn't wired yet).

### Task 0.1: Repository skeleton

**Files:**
- Create: `package.json`, `.nvmrc`, `.gitignore`, `README.md`

**Interfaces:**
- Produces: npm scripts used by all later tasks:

  | Script | Runs |
  |---|---|
  | `test` | `node --test "tests/**/*.test.cjs"` |
  | `compat` | `node kig.cjs compat` |
  | `validate` | `sh scripts/validate.sh` |
  | `judge` | `sh scripts/judge.sh` |

- [ ] **Step 1:** Create `package.json` with `"name":"key-identity-guard"`, `"private":true`, `"engines":{"node":"24.11.1"}`, the scripts above, and **no** dependency fields. `.nvmrc` contains `24.11.1`.
- [ ] **Step 2:** Create `.gitignore` with `node_modules/`, `*.db`, `*.db-wal`, `*.db-shm`, `.kig/`, `evidence/tmp/`, `__pycache__/`, `.venv/`.
- [ ] **Step 3:** Create `README.md` with headings only: Overview, Requirements (Node 24.11.1, nothing else), Round 1 adapter, Round 2 CLI, Development, Testing, Limitations. Each section gets a one-line placeholder naming which task fills it.
- [ ] **Step 4:** Run `node -e "const p=require('./package.json');if(p.dependencies||p.devDependencies)process.exit(1)"`. Expected: exit 0.
- [ ] **Step 5:** Commit `chore: repository skeleton`.

### Task 0.2: Crypto provider

**Files:**
- Create: `src/crypto/provider.cjs`
- Test: `tests/unit/provider.test.cjs`, `tests/unit/crypto-boundary.test.cjs`

**Interfaces:**
- Produces (all `Buffer` in and out):
  - `random(n) → Buffer`
  - `sha256(buf) → Buffer`
  - `hmac(key, buf) → Buffer`
  - `hmacHex(key, buf) → string` (lowercase)
  - `hmacEqual(a, b) → boolean` (constant time, false if lengths differ)
  - `hkdf(ikm, salt, info, len) → Buffer`
  - `aeadSeal(key32, nonce12, aad, pt) → Buffer` (ct‖tag16)
  - `aeadOpen(key32, nonce12, aad, ctTag) → Buffer` (throws `AeadError`)
  - `async kemEncapsulateRaw(rawPub) → {ciphertext: Buffer, sharedKey: Buffer}` (WebCrypto `raw-public` import; throws `InvalidKeyError` on `DataError` or wrong length)
  - `kemGenerate() → {publicKey, privateKey}` (KeyObjects)
  - `kemExportRawPublic(publicKey) → Buffer`
  - `kemEncapsulate(publicKey) → {ciphertext, sharedKey}`
  - `kemDecapsulate(privateKey, ct) → Buffer`
  - `sigGenerate() → {publicKey, privateKey}` (ML-DSA-65)
  - `sign(privateKey, context, buf) → Buffer`
  - `verify(publicKey, context, buf, sig) → boolean`
  - `exportPrivate(key) → Buffer` (PKCS#8 DER)
  - `importPrivate(der) → KeyObject`
  - `exportPublic(key) → Buffer` (SPKI DER)
  - `importPublic(der) → KeyObject`
  - `selfTest() → Array<{name, pass}>`
  - classes `InvalidKeyError`, `AeadError`; constant `CONTEXTS` (the five strings)

- [ ] **Step 1: Write failing tests** in `provider.test.cjs`:
  - `hkdf RFC 5869 TC1`: ikm `0x0b`×22, salt `000102…0c`, info `f0…f9`, L=42 → `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865`
  - `aead round trip and AAD tamper`: open with changed AAD throws `AeadError`
  - `kem raw round trip`: `kemEncapsulateRaw(kemExportRawPublic(pk))`, then `kemDecapsulate` gives an equal secret; sizes ct 1088, ss 32, pk 1184
  - `kem rejects bad keys`: 1183 bytes and 1184×`0xFF` → `InvalidKeyError`
  - `ml-dsa context separation`: verify fails under a different context
  - `private key export/import round trip` for ML-DSA (sign after import verifies) and ML-KEM (decapsulate after import matches). This covers architecture §20 V2.
  - `hmacEqual` false for different lengths
  - `selfTest all pass`
- [ ] **Step 2:** In `crypto-boundary.test.cjs`, scan every `.cjs` under `src/`, `track4_service.cjs`, `team_app.cjs` and `kig.cjs`. Assert that only `src/crypto/provider.cjs` contains `node:crypto` or `require('crypto')`.
- [ ] **Step 3:** Run `node --test tests/unit/provider.test.cjs`. Expected: FAIL (module missing).
- [ ] **Step 4:** Implement `provider.cjs`. Algorithms per architecture §2.2. ML-DSA uses `crypto.sign(null, buf, {key, context})`. `kemEncapsulateRaw` uses `crypto.webcrypto.subtle.importKey('raw-public', …, {name:'ML-KEM-768'}, false, ['encapsulateBits'])` then `encapsulateBits`. If V2 fails, use `subtle.importKey('raw-seed', …)` and record that in the test name.
- [ ] **Step 5:** Run `node --test tests/unit`. Expected: PASS.
- [ ] **Step 6:** Commit `feat(crypto): provider with known-answer self-test`.

### Task 0.3: `kig compat`

**Files:**
- Create: `kig.cjs`, `src/cli/compat.cjs`
- Test: `tests/unit/compat.test.cjs`

**Interfaces:**
- Consumes: `provider.selfTest()`.
- Produces: `node kig.cjs compat` prints one line per check, `PASS <name>` or `FAIL <name>`, and exits 0 only if all pass. `compat.run() → Promise<Array<{name, pass}>>`.

Checks:
1. provider self-test entries;
2. `node:sqlite` opens, uses WAL and `STRICT`;
3. 8 child processes × 25 hash-chained appends with `BEGIN IMMEDIATE` → 200 rows, valid chain (**pre-created WAL DB**);
4. child `SIGKILL` inside an open transaction → no partial row;
5. `VACUUM INTO` produces a readable copy (architecture §20 V4);
6. stderr of a child that loads `node:sqlite` and ML-KEM after warning suppression is 0 bytes;
7. `process.arch` and `process.versions.node` printed as info.

- [ ] **Step 1:** Write the test `compat.run() returns only passes on this machine`.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement. `kig.cjs` calls `process.removeAllListeners('warning')` and routes `compat` to `src/cli/compat.cjs`. Child workers are the same file run with `--worker <mode>` arguments, so there is no temp code.
- [ ] **Step 4:** Run `node kig.cjs compat`. Expected: all PASS, exit 0.
- [ ] **Step 5:** Commit `feat(cli): kig compat`.

### Task 0.4: Judging-container replica and ARM CI

**Files:**
- Create: `tools/judge/Dockerfile`, `scripts/judge.sh`, `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `sh scripts/judge.sh <cmd…>` runs `<cmd…>` inside the replica (`/app` = repo, read-only; `/toolkit` = toolkit, read-only; `/tmp` = tmpfs).
- [ ] **Step 1:** Write the Dockerfile `FROM node:24.11.1-bookworm-slim`, installing `python3` (needed only for `validate.py`). Use a non-root `USER node`.
- [ ] **Step 2:** Write `scripts/judge.sh`. It builds the image once with `--platform linux/arm64` (tag `kig-judge`), then runs `docker run --rm --platform linux/arm64 --read-only --network none --tmpfs /tmp:rw,exec -v "$REPO":/app:ro -v "$TOOLKIT_DIR":/toolkit:ro -w /app kig-judge "$@"`. `TOOLKIT_DIR` defaults to `../Track-4-Toolkit`.
- [ ] **Step 3:** Write `ci.yml`:
  - `runs-on: ubuntu-24.04-arm`, `container: node:24.11.1`
  - steps: checkout; checkout `ScalerOpenSourceLabs/Track-4-Toolkit` at `8901dfb` into `toolkit/`
  - `node kig.cjs compat`; `npm test`; `python3 toolkit/validate.py --entry ./track4_service.cjs` (from Task 0.5 on); install `pqcrypto==0.4.0` and run the interop test (from Task 1.16 on)
  - upload `evidence/` as an artifact
- [ ] **Step 4:** Run `sh scripts/judge.sh node kig.cjs compat` locally. Expected: all PASS (emulated ARM; slow is fine). Push the branch; expected: CI green on ARM.
- [ ] **Step 5:** Commit `ci: arm64 judging replica and workflow`.

### Task 0.5: Toolkit hookup

**Files:**
- Create: `scripts/validate.sh`; temporary copies of the toolkit Node starter `track4_service.cjs` and `team_app.cjs` at the root (replaced in 1.14)

- [ ] **Step 1:** `validate.sh` runs `python3 "$TOOLKIT_DIR/validate.py" --entry "$REPO/track4_service.cjs"` and tees the output to `evidence/validate-$(git rev-parse --short HEAD).txt`.
- [ ] **Step 2:** Run `sh scripts/validate.sh`. Expected: the validator runs; the stub fails at "clean setup" (exit status 2). That proves the plumbing works.
- [ ] **Step 3:** Commit `chore: toolkit validator hookup`.

---

# Phase 1: Round 1 adapter (the Round 1 deliverable)

**Spec:** features P0-01 to P0-10, D-01 to D-04, D-13 to D-16; architecture §4 and §5.

**Gate 1, all inside `scripts/judge.sh` (arm64), plus green ARM CI:**
1. `sh scripts/validate.sh` → `Local scenario passed.`, exit 0, saved to `evidence/`
2. `npm test` → all pass (unit, adapter, negative, concurrency including cold start ×20, crash)
3. interop 25/25 (Task 1.16)
4. marker scan: `key_material` absent from stdout, stderr and every byte under the state dir

After Gate 1 the adapter is frozen.

### Task 1.1: Limits and opaque identifiers

**Files:**
- Create: `src/core/limits.cjs`, `src/core/ids.cjs`
- Test: `tests/unit/ids.test.cjs`

**Interfaces:**
- Produces:
  - `limits`: the constants listed under Global constraints, plus `SCHEMA_VERSION_ADAPTER = 1` and `PROTO_KEYS = new Set(['__proto__','constructor','prototype','toString','hasOwnProperty','valueOf'])`
  - `ids.enc(s: string) → string` (`JSON.stringify`)
  - `ids.dec(t: string) → string` (`JSON.parse`)
  - `ids.isId(x) → boolean` (string with `length ≤ MAX_ID_LEN`)
  - `ids.isHostile(s) → boolean`: true if any of the following:
    - a control char `\u0000–\u001f` or `\u007f`
    - `!s.isWellFormed()` (lone surrogate)
    - contains `../` or `..\\`
    - `PROTO_KEYS.has(s)`

- [ ] **Step 1: Write failing tests:**
  - `round trip`: for each of `['\ud800','\udc00\ud800','�','a\u0000b','x\n{"actor":"admin"}','../../etc/passwd',"';DROP TABLE t;--",'🙂','','__proto__','constructor','a'.repeat(2048)]`, `dec(enc(s)) === s`
  - `distinct`: `enc` of `'\ud800'` ≠ `enc` of `'�'`; the set of all encodings has the same size as the input list
  - `isHostile`: true for `'\ud800'`, `'a\u0000b'`, `'x\ny'`, `'../a'`, `'__proto__'`; false for `'maya'`, `'r01'`, `'🙂'`, `''`
  - `isId`: false for non-strings and for `'a'.repeat(8193)`
- [ ] **Step 2:** Run `node --test tests/unit/ids.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement both files.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit `feat(core): opaque identifier encoding and limits`.

### Task 1.2: Length-prefixed encoder

**Files:**
- Create: `src/core/encoding.cjs`
- Test: `tests/unit/encoding.test.cjs`

**Interfaces:**
- Produces `encode(label: string, fields: Array<Buffer|string|number|bigint|null>) → Buffer`:
  - `u32be(len(label)) ‖ label`
  - then per field:
    - `Buffer` → `u32be(len) ‖ bytes`
    - `string` → `u32be(len) ‖ UTF-8(ids.enc(s))`
    - `number`/`bigint` → `u32be(8) ‖ i64be`
    - `null` → `u32be(0xFFFFFFFF)`
  - integers must be safe integers or bigint, otherwise throw `TypeError`.

- [ ] **Step 1: Write failing tests:**
  - `null differs from empty string`: `encode('L',[null])` ≠ `encode('L',[''])`
  - `boundary safety`: `encode('L',['a','b'])` ≠ `encode('L',['ab'])` ≠ `encode('L',['a\u0000b'])`
  - `injection`: `encode('L',['x\n{"actor":"admin"}'])` contains exactly one field (parse it back with a test-only decoder in the test file)
  - `rejects 1.5`
  - `deterministic`
- [ ] **Step 2:** Run. Expected: FAIL. **Step 3:** Implement. **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit `feat(core): length-prefixed encoder`.

### Task 1.3: SQLite helper

**Files:**
- Create: `src/store/db.cjs`
- Test: `tests/unit/db.test.cjs`

**Interfaces:**
- Produces:
  - `class StateError extends Error { kind: 'missing'|'corrupt'|'locked'|'schema' }`
  - `openDb(path, { create: boolean, version: number, init: (db) => void }) → DatabaseSync`:
    - if `!create` and the file does not exist → throw `StateError('missing')`. **Check with `fs.existsSync` before constructing**: `DatabaseSync` creates missing files.
    - constructs with `{ timeout: BUSY_TIMEOUT_MS }`;
    - sets `synchronous=FULL` and `foreign_keys=ON`;
    - if `create`: `PRAGMA journal_mode=WAL` (retried on busy; accept `delete` if `wal` isn't returned), then `tx(db, () => { if user_version === 0 → init(db); set user_version = version })`;
    - if the `user_version` mismatches → `StateError('schema')`;
    - every step up to the first successful query is retried `BUSY_RETRIES` times with 20–80 ms jitter on busy/locked errors, then → `StateError('locked')`;
    - other open/query errors → `StateError('corrupt')`.
  - `tx(db, fn) → any`: `BEGIN IMMEDIATE`; on throw `ROLLBACK` and rethrow (busy at `BEGIN` is retried like above).
  - `quarantine(path) → string`: renames `path`, `-wal` and `-shm` to `<name>.quarantine-<Date.now()>`; returns the new main path.
  - `isBusy(err) → boolean`.

- [ ] **Step 1: Write failing tests:**
  - `missing file not created`: `openDb(p,{create:false})` throws kind `missing`, and `fs.existsSync(p)` is still false
  - `create sets wal and version`
  - `schema mismatch` → kind `schema`
  - `corrupt` (write 4 KiB of `0x00`…`garbage` over the file) → kind `corrupt`
  - `tx rollback leaves no row`
  - `parallel create`: spawn 8 children that each `openDb(p,{create:true,…})` and insert one row in `tx` on a **non-existent** file; repeat 20 times. Every child exits 0 and there are 8 rows each time. This is the cold-start race from features R9.
  - `quarantine renames all three files`
- [ ] **Step 2:** Run. Expected: FAIL. **Step 3:** Implement. **Step 4:** Run. Expected: PASS (`parallel create` 20/20).
- [ ] **Step 5:** Commit `feat(store): sqlite helper with busy retry and quarantine`.

### Task 1.4: Adapter schema

**Files:**
- Create: `src/store/schema-adapter.cjs`
- Test: `tests/unit/schema-adapter.test.cjs`

**Interfaces:**
- Consumes: `openDb`, `tx`.
- Produces:
  - `VERSION = 1`
  - `init(db)`: creates the DDL exactly as architecture §5.4 (tables `meta`, `assets`, `revoked_actors`, `audit_events`, indexes, triggers) and inserts meta `db_id` (16 random bytes as hex, via `provider.random`), `current_gen='0'` and `epoch='0'`
  - `getMeta(db, k) → string`
  - `setMeta(db, k, v)`
  - `adapterDbPath(stateDir) → path.join(stateDir, 'kig', 'adapter.db')`

- [ ] **Step 1: Write failing tests:**
  - `init creates tables and meta`
  - `audit_events UPDATE aborts` and `DELETE aborts` (error message contains `append-only`)
  - `tables are STRICT`: inserting a TEXT into `revoked_actors.epoch` throws
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(store): adapter schema v1`.

### Task 1.5: Audit chain (append and verify)

**Files:**
- Create: `src/core/audit.cjs`
- Test: `tests/unit/audit.test.cjs`

**Interfaces:**
- Consumes: `encoding.encode`, `provider.sha256`, `ids.enc`, `getMeta`.
- Produces:
  - `append(db, ev) → { seq: number, hash: Buffer }`. Must be called inside a `tx`. `ev = { gen, kind, op?, request_id?, actor?, asset?, decision?, rule?, detail? }`, where `detail` is a plain object serialised with `JSON.stringify`. `ts_ms = Date.now()`; `seq = last + 1`.
  - Hash: `prev = last hash or genesis`, where `genesis = sha256(encode('kig/v1/genesis',[db_id]))` and `hash = sha256(prev ‖ encode('kig/v1/event',[seq, gen, ts_ms, kind, op, request_id, actor, asset, decision, rule, detailJson]))`. Missing fields are `null`.
  - String fields are stored with `ids.enc`.
  - `verifyChain(db) → { ok: true, count, head: Buffer } | { ok: false, seq, reason: 'content_edit'|'missing_or_reordered' }`
  - `latestAccessDecision(db, gen, requestId) → 'allow'|'deny'|null`
  - `countRecentDenies(db, gen, actor, sinceMs) → number`

- [ ] **Step 1: Write failing tests:**
  - `chain of 50 verifies`
  - `edited row detected`: drop the triggers in a test copy, change `decision` → `ok:false, reason:'content_edit'`, `seq` = that row
  - `deleted row detected` → `missing_or_reordered`
  - `injection actor is one event`: append with actor `'x\n{"actor":"admin","decision":"allow"}'`; reading back gives one row whose decoded actor equals the input exactly
  - `latestAccessDecision returns last of reused id`
  - `scoped to generation`
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(core): hash-chained audit log`.

### Task 1.6: Request validation

**Files:**
- Create: `src/adapter/validate.cjs`
- Test: `tests/unit/validate.test.cjs`

**Interfaces:**
- Produces:
  - `isStrictBase64(s) → boolean` (the four-part rule in architecture §5.3)
  - `validate(op, obj) → { ok: true, req } | { ok: false, reason: string }`. `req` per op:
    - `setup`: `{ owners: Map, contents: Map, disabled: Set }`, built from `Object.entries` (own keys); `key_material` is dropped and never copied
    - `read`: `{ actor, asset, request_id }`
    - `revoke`: `{ actor }`
    - `audit`: `{ request_id }`
    - `protected_read`: `{ actor, asset, challenge, publicKey: Buffer(1184), request_id: string|null }`
  - `OPS = new Set(['setup','read','revoke','audit','protected_read'])`
  - `hostileIds(req) → string[]` (IDs for which `ids.isHostile` is true)

- [ ] **Step 1: Write failing tests:**
  - `setup accepts proto keys`: `JSON.parse('{"owners":{"__proto__":"maya","constructor":"bob"},"contents":{"__proto__":"x","constructor":"y"},"disabled":[]}')` → `req.owners.get('__proto__') === 'maya'` and `req.owners.size === 2`
  - `setup rejects non-string owner value`, `setup rejects disabled not array`
  - `key_material not in req` (JSON.stringify of `req` with Maps converted contains no marker)
  - `read rejects missing request_id`, `rejects number actor`, `rejects 8193-char id`
  - `base64 strict`: accepts a valid 1580-char key; rejects the same with `-_` substituted, with an inserted space, with a trailing newline, 1183 and 1185 decoded bytes, and `''`
  - `challenge over 4096 rejected`
  - `optional request_id on protected_read`
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): strict request validation`.

### Task 1.7: Access policy

**Files:**
- Create: `src/core/policy.cjs`
- Test: `tests/unit/policy.test.cjs`

**Interfaces:**
- Consumes: the adapter schema, `ids`.
- Produces `authorizeOwnerRead(db, actor, asset) → { decision: 'allow'|'deny', rule: 'actor_revoked'|'unknown_asset'|'not_owner'|'owner_allowed', body?: string }`. The checks run in exactly this order: revoked → asset missing or owner/body NULL → owner mismatch → allow. `body` is present only on allow, and decoded.

- [ ] **Step 1: Write failing tests:**
  - `revoked owner denied even though owner` (rule `actor_revoked`)
  - `unknown asset`
  - `asset with owner but no contents` → `unknown_asset`
  - `not owner`
  - `allow returns exact body`
  - `deny has no body key`
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(core): owner read policy`.

### Task 1.8: `setup`

**Files:**
- Create: `src/adapter/ops.cjs` (initially exports `setup`)
- Test: `tests/unit/op-setup.test.cjs`

**Interfaces:**
- Consumes: `openDb`, `tx`, `quarantine`, `schema-adapter`, `audit.append`, `validate` (the req shape).
- Produces `async setup(ctx: {stateDir}, req) → {ready:true}`, which throws only when state can't be persisted. Behaviour per architecture §5.5:
  - `mkdirSync(<stateDir>/kig, {recursive:true, mode:0o700})`;
  - corrupt or schema mismatch → `quarantine`, then create fresh;
  - in one `tx`: `current_gen += 1`; clear `assets` and `revoked_actors`; insert the union of asset IDs (owner/body may be NULL); insert `disabled` with `source='setup_disabled'` and `epoch = epoch + 1`;
  - append `{kind:'setup', gen, detail:{assets:n, disabled:m}}`;
  - if a quarantine happened, also append `{kind:'alert', rule:'A-STATE-FAULT', detail:{reason:'quarantined'}}`.

- [ ] **Step 1: Write failing tests:**
  - `fresh setup ready`
  - `second setup replaces data`: setup A then setup B with different owners/contents → only B's rows; `current_gen === 2`; audit has both setup events and the chain verifies
  - `disabled actors stored as revoked`
  - `corrupt db quarantined and replaced` (the quarantine file exists; `ready:true`)
  - `marker never persisted`: setup with `key_material:'MARKER-'+random`, then a byte search of every file under the state dir finds no marker
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): setup with generations`.

### Task 1.9: `read`

**Files:**
- Modify: `src/adapter/ops.cjs` (add `read`)
- Test: `tests/unit/op-read.test.cjs`

**Interfaces:**
- Produces `async read(ctx, req) → {decision:'allow', body} | {decision:'deny'}`:
  - opens with `create:false`; `missing` or `current_gen = 0` → deny without a write;
  - in one `tx`: `authorizeOwnerRead`, `audit.append({kind:'access', op:'read', …})`, alerts via `alerts.evaluate` (Task 1.13 wires that in; until then it's a no-op).

- [ ] **Step 1: Write failing tests:**
  - `owner allowed exact body`
  - `unicode body`: body `'ünïcode ✓ 🙂'` and body `'a\ud800b'` round-trip exactly
  - `wrong owner denied`
  - `deny response has exactly one key`: `Object.keys(res)` equals `['decision']`
  - `read before setup denies and creates no file`
  - `every read appends one access event with rule`
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): read`.

### Task 1.10: `revoke`

**Files:**
- Modify: `src/adapter/ops.cjs` (add `revoke`)
- Test: `tests/unit/op-revoke.test.cjs`

**Interfaces:**
- Produces `async revoke(ctx, req) → {}`, which throws if the change can't be persisted:
  - opens with `create:true` (a revoke before setup creates the store, gen 0);
  - in one `tx`: `epoch += 1`; `INSERT … ON CONFLICT DO NOTHING` with `source='revoke'`; append `{kind:'revoke'}`.

- [ ] **Step 1: Write failing tests:**
  - `revoked owner then denied`
  - `peer unaffected`
  - `idempotent` (twice → one row; epoch increments twice; two audit events)
  - `unknown actor accepted`
  - `revoke before setup persists`: revoke X on an empty dir → the row exists in gen 0; **then** setup (without X in `disabled`) → X is not revoked in gen 1 (D-01 replace semantics, pinned)
  - `revoke after setup survives process restart` (reopen the DB)
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): revoke`.

### Task 1.11: `audit`

**Files:**
- Modify: `src/adapter/ops.cjs` (add `audit`)
- Test: `tests/unit/op-audit.test.cjs`

**Interfaces:**
- Produces `async audit(ctx, req) → {request_id, decision}`:
  - opens with `create:false`; missing → `{request_id, decision:'deny'}` with no write;
  - in one `tx`: `latestAccessDecision(gen=current)`; append `{kind:'audit_query', request_id, rule: found ? 'hit' : 'audit_lookup_miss'}`.

- [ ] **Step 1: Write failing tests:**
  - `matches denied read`
  - `latest of reused id` (allow then deny with the same ID → `deny`)
  - `unknown id deny`
  - `previous generation id is unknown` (read r1 in gen 1, then setup → `audit r1` gives `deny`)
  - `exactly two keys`
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): audit lookup`.

### Task 1.12: `protected_read`

**Files:**
- Modify: `src/adapter/ops.cjs` (add `protectedRead`)
- Test: `tests/unit/op-protected-read.test.cjs`

**Interfaces:**
- Consumes: `provider.kemEncapsulateRaw`, `provider.hmacHex`.
- Produces `async protectedRead(ctx, req) → {ciphertext: string, proof: string} | {decision:'deny'}`. Order per architecture §5.5:
  - authorize first;
  - on allow, encapsulate. `InvalidKeyError` → deny with rule `invalid_public_key`;
  - `proof = hmacHex(sharedKey, Buffer.from(challenge + body, 'utf8'))`;
  - `ciphertext = base64(ct)`;
  - `sharedKey.fill(0)`;
  - append `{kind:'access', op:'protected_read', request_id: req.request_id, …}`.

  Keep the async encapsulation **outside** the SQLite transaction: authorize and read the body in `tx` #1, encapsulate, then append the audit in `tx` #2. If `tx` #2 fails, return deny and discard the ciphertext. Never return an allow that wasn't recorded.

- [ ] **Step 1: Write failing tests:**
  - `owner gets verifiable proof`: generate a key with `provider.kemGenerate`, call, decapsulate, recompute the HMAC → equal; `ciphertext` decodes to 1088 bytes
  - `revoked actor gets deny with one key`
  - `invalid 0xFF key → deny + audit rule invalid_public_key`
  - `unicode challenge and body` verify
  - `shared secret not in response or db` (byte search for the secret in the state dir and the JSON)
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(adapter): protected_read`.

### Task 1.13: Adapter alerts (P0-10)

**Files:**
- Create: `src/core/alerts.cjs`
- Modify: `src/adapter/ops.cjs` (call `evaluate` in each op's `tx`)
- Test: `tests/unit/alerts.test.cjs`

**Interfaces:**
- Produces `evaluate(db, gen, c) → Array<{rule, severity, reason}>`, where `c = { op, actor?, asset?, decision?, rule?, invalidInput?: boolean, invalidKey?: boolean, hostile: string[] }`. Rules (architecture §5.7):

  | Rule | Fires when | Severity |
  |---|---|---|
  | `A-REVOKED-RETRY` | `rule==='actor_revoked'` and op ∈ {read, protected_read} | medium |
  | `A-CROSS-OWNER` | `rule==='not_owner'` | low |
  | `A-INVALID-INPUT` | `invalidInput` | low |
  | `A-INVALID-KEY` | `invalidKey` | medium |
  | `A-HOSTILE-ID` | `hostile.length > 0` | info |
  | `A-BURST` | `countRecentDenies(db, gen, actor, now − BURST_WINDOW_MS) === BURST_N`, counted **after** this event is appended | high |

- `appendAlerts(db, gen, base, alerts)` writes one `kind:'alert'` event per alert. `detail = { severity, reason }`; the request's raw values are never copied into `detail` beyond the encoded actor/asset fields.

- [ ] **Step 1: Write failing tests:**
  - one test per rule firing
  - `happy path no alerts`: a validator-style scenario of owner read and peer read produces 0 alert events
  - `burst fires once at the fifth deny`
  - `responses identical with alerts on`: same inputs, response JSON equal with and without `evaluate` stubbed
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS).
- [ ] **Step 5:** Commit `feat(core): adapter self-monitoring alerts`.

### Task 1.14: Entry point, routing and error policy

**Files:**
- Create: `src/adapter/index.cjs`, `tests/helpers/run-adapter.cjs`
- Replace: `track4_service.cjs`, `team_app.cjs`
- Test: `tests/adapter/contract.test.cjs`

**Interfaces:**
- Produces:
  - `index.handleRaw(buf: Buffer, env) → Promise<{ response: object|null, exitCode: 0|1 }>`, implementing architecture §5.2 steps 3–9 and the §5.6 table:
    - fatal `TextDecoder`, `JSON.parse`, plain-object check;
    - unknown op → `unsupported_operation`;
    - validation failure → the per-op invalid response (§5.3), with `A-INVALID-INPUT` appended when a store exists (best effort; a failure here is swallowed);
    - `StateError` and unexpected errors → per-op fail-closed shape, except `revoke`/`setup` → `{response:null, exitCode:1}`;
    - `stateDir = env.TRACK4_STATE_DIR || os.tmpdir()`.
  - `team_app.cjs`: `exports.handleRaw = (buf) => require('./src/adapter/index.cjs').handleRaw(buf, process.env)`.
  - `track4_service.cjs`:
    1. `process.removeAllListeners('warning')`;
    2. read fd 0 with `fs.readSync` in 64 KiB chunks until EOF, retrying on `EAGAIN`, stopping past `MAX_STDIN_BYTES` → `{"error":"invalid_request"}`;
    3. call `handleRaw`;
    4. write `JSON.stringify(response)+'\n'` or the fixed stderr line;
    5. set `process.exitCode`;
    6. last-resort `catch` → fixed stderr line, exit 1.
  - `run-adapter.cjs`: `runAdapter(stateDir, input: object|Buffer, {timeoutMs=8000}) → Promise<{code, stdout: string, stderr: string, json: object|null}>`. Spawns `process.execPath track4_service.cjs` with cwd = repo root, and env `TRACK4_STATE_DIR`/`TMPDIR`/`TEMP`/`TMP` = `stateDir` (like `validate.py`).

- [ ] **Step 1: Write failing tests** (all through `runAdapter`, a new process each call):
  - `validator scenario`: the exact sequence from `validate.py`, with all expectations
  - `stderr empty on success`
  - `stdout is one line of JSON`
  - `unknown op → unsupported_operation exit 0`
  - `non-object → invalid_request exit 0`
  - `invalid utf-8 bytes → invalid_request exit 0`
  - `oversize stdin (4 MiB + 1) → invalid_request exit 0`
  - `revoke on unwritable state dir → exit 1, empty stdout, fixed stderr line` (`chmod 0500` dir; skip as root)
  - `read on corrupt db → deny exit 0`
  - `no lingering handles` (process exits within 2 s)
- [ ] **Step 2–4:** Run (FAIL) → implement → run (PASS). Then `sh scripts/validate.sh` → `Local scenario passed.`
- [ ] **Step 5:** Commit `feat(adapter): entry point and error policy`.

### Task 1.15: Hardening suites

**Files:**
- Create: `tests/negative/negative.test.cjs`, `tests/adapter/concurrency.test.cjs`, `tests/crash/adapter-kill.test.cjs`

**Interfaces:**
- Consumes: `runAdapter`.

- [ ] **Step 1: `negative.test.cjs`.** Every ID from the Task 1.1 list, used as actor, asset and request_id, through `setup` → `read` → `revoke` → `audit`: correct decisions, exact body round trip, exit 0. Also:
  - `prototype keys in setup maps`: owners `{"__proto__":"a","constructor":"b"}` with contents → `a` reads `__proto__`'s body; `b` reads `constructor`'s body; `a` is denied on `constructor`
  - wrong types for every field; missing fields; arrays instead of objects; `null` request; duplicate JSON keys
  - nested-leak check: on every deny, the JSON contains no seeded body or marker anywhere (mirror `validate.py`'s `contains_protected_value`)
  - **marker scan** after the full scenario: stdout, stderr and every file under the state dir (including `-wal`) contain no marker bytes
- [ ] **Step 2: `concurrency.test.cjs`:**
  - `warm`: after setup, 8 parallel processes doing mixed read/revoke/audit, ×20 rounds
  - `cold`: an empty dir with 8 parallel `revoke`s of distinct actors, ×20 rounds
  - Expected each round: all exit 0, every revoke row present, `verifyChain` ok.
- [ ] **Step 3: `adapter-kill.test.cjs`.** Start a child holding an open transaction mid-`revoke` (test hook env `KIG_TEST_HANG_IN_TX=1`, read only inside `ops.revoke` and only when `NODE_ENV==='test'`), `SIGKILL` it, then: no partial row, chain valid, the next `read` works.
- [ ] **Step 4:** Run `npm test`. Expected: all PASS. Run `sh scripts/judge.sh npm test`. Expected: PASS on arm64.
- [ ] **Step 5:** Commit `test(adapter): negative, concurrency and crash suites`.

### Task 1.16: `pqcrypto` interop

**Files:**
- Create: `tests/interop/protected_read_interop.py`, `tests/interop/interop.test.cjs`

- [ ] **Step 1:** The Python script (stdlib + `pqcrypto.kem.ml_kem_768`), run 25 times:
  - generate a keypair;
  - make a temp state dir;
  - run the adapter for `setup` (UTF-8 body `ünïcode ✓ <i>`), then `protected_read`;
  - decapsulate and recompute the HMAC with `hmac.compare_digest`.

  It prints `interop N/25` and exits 0 only on 25/25.
- [ ] **Step 2:** `interop.test.cjs` runs the script with `python3`. It **skips with a visible message** if `python3 -c "import pqcrypto"` fails.
- [ ] **Step 3:** Run with the venv active. Expected: `interop 25/25`.
- [ ] **Step 4:** Commit `test(interop): pqcrypto decapsulates protected_read`.

### Task 1.17: Round 1 evidence and README

**Files:**
- Modify: `README.md` (Requirements, Round 1 adapter, Testing)
- Create: `evidence/round1.md`

- [ ] **Step 1:** README: clean-machine steps (install Node 24.11.1; `git clone`; `node track4_service.cjs < request.json`; `npm test`; how to run the validator). State "no dependencies to install".
- [ ] **Step 2:** In `evidence/round1.md`, link the validator output, the `npm test` summary from the judge container, interop output, and the CI run URL. List the limits: actor is a trusted input (P0-05), D-14, D-15.
- [ ] **Step 3:** Run Gate 1 (all four items). Expected: all pass.
- [ ] **Step 4:** Commit `docs: round 1 evidence`, open the PR, merge, tag `round1-ready`.

---

# Phase 2: Audit verification and CLI skeleton

**Spec:** P1-08, P0-10 (operator view); architecture §14, §17.1.
**Gate 2:** `kig verify-log` detects edit, delete, reorder and truncation-after-checkpoint on an adapter DB, and reports OK on an untouched one. `kig alerts --adapter` lists Phase 1 alerts.

| Task | Files | Interfaces produced | Acceptance tests |
|---|---|---|---|
| **2.1 CLI router** | `src/cli/main.cjs`, `kig.cjs` (modify) | `main(argv) → Promise<exitCode>`; each command module exports `{ name, describe, options (util.parseArgs config), run(values) → Promise<number> }`; `kig help` lists commands | `unknown command exits 2 with help`; `compat still works` |
| **2.2 verify-log** | `src/core/audit.cjs` (extend), `src/cli/verify-log.cjs` | `verifyChain(db, {anchor?}) → {ok, count, head} \| {ok:false, seq, reason: 'content_edit'\|'missing_or_reordered'\|'invalid_checkpoint'\|'truncated'}`; CLI `kig verify-log --db <file> [--anchor <file>]` prints `OK <count> <headhex>` or `BROKEN seq=<n> <reason>`, exit 0/1 | each tamper class on a copy of an adapter DB (triggers dropped on the copy); injection actor stays one event |
| **2.3 checkpoints and anchor** | `src/core/checkpoint.cjs`, `src/cli/checkpoint.cjs`, `src/cli/keys.cjs` | `kig keys init --out <dir>` creates an operator audit ML-DSA key; `signCheckpoint(db, priv, storeId) → {store_id, seq, head_hash, checkpoint_id, prev_checkpoint_id, sig}` (ctx `kig/v1/checkpoint`); `kig checkpoint --adapter <stateDir> --key <file> --anchor <file>` writes or appends the anchor JSON | `truncated after anchored checkpoint detected`; `forged checkpoint sig rejected`; `anchor outside db` |
| **2.4 alerts view** | `src/cli/alerts.cjs` | `kig alerts --adapter <stateDir> [--json]` prints alerts newest first: time, rule, severity, actor (decoded and escaped for the terminal), reason | lists each P0-10 rule from a scripted scenario; output escapes control characters (no terminal injection) |

Each task follows the same TDD loop: failing test → implement → pass → commit.

---

# Phase 3: Control plane, nodes, devices, files, revocation

**Spec:** P1-01, P1-02, P1-03 (revocation half), P1-05, P1-17; architecture §6–§11.
**Gate 3:** `kig up` starts the CP plus 3 nodes; enrolled devices read a shared file through each node; `kig revoke --device` → every node denies it while the peer is still allowed; `kig bench revocation --n 100` prints p50/p95/max per node; a partitioned node fails closed at lease expiry; all of this in `scripts/judge.sh`.

| Task | Files | Interfaces produced | Acceptance tests |
|---|---|---|---|
| **3.1 HTTP plumbing** | `src/core/http.cjs` | `serve(port, routes: Map<'METHOD /path', async (body, req) → {status, json}>) → server`, bound to `127.0.0.1`, 1 MiB body cap, JSON only; `call(url, method, json, {timeoutMs}) → {status, json}`; Buffers carried as base64 fields | `body cap 413`; `non-json 400`; `binds loopback only` |
| **3.2 Stores and `kig init`** | `src/store/schema-cp.cjs`, `schema-node.cjs`, `schema-device.cjs`, `src/cp/keys.cjs`, `src/cli/init.cjs` | `KIG_HOME` layout from architecture §6.1; `kig init` creates the CP keys (§7 table), operator recovery KEM key in `operator/`, and the anchor with public keys; key files mode 0600 | `init twice refuses without --force`; `files and modes`; `anchor has public keys only` |
| **3.3 Process supervisor** | `src/cli/supervisor.cjs`, `src/cp/server.cjs`, `src/node/server.cjs` | `kig up` / `kig down` / `kig status`; pid files in `KIG_HOME/run/`; nodes A/B/C on 7401–7403, CP on 7400; `/v1/health` on each | `up then status shows 4 healthy`; `down leaves no process`; `up twice is a no-op` |
| **3.4 Policy snapshots** | `src/cp/snapshot.cjs`, `src/node/policy.cjs`, `src/node/lease.cjs` | `buildSnapshot(cpDb) → object`; `signSnapshot(obj, priv) → {snapshot, sig}` (ctx `kig/v1/revocation`); node `applySnapshot(db, signed, cpPub) → {applied: boolean, reason}` (§10.2); push (`POST /v1/policy`) + pull (`GET /v1/policy/head?nonce=`, signed fresh) every 250 ms; `leaseValid(db) → boolean` | `stale epoch rejected`; `bad sig rejected`; `replayed head (old nonce) rejected`; `lease expiry denies`; `node converges via pull after missed push` |
| **3.5 Accounts and devices** | `src/cp/registry.cjs`, `src/device/keystore.cjs`, `src/cli/device.cjs` | `kig account add <a>`; `kig device enrol <dev> --account <a>` (keys generated in `devices/<dev>/`, enrol request signed by the new key); `kig device approve <dev> --by <device>\|--operator --approval-id <id>`; first device of an account needs the operator | `unapproved device pending`; `approval by other active device works`; `approval by a revoked device refused`; `proof-of-possession sig required` |
| **3.6 Request authentication** | `src/node/auth.cjs`, `src/device/client.cjs` | `GET /v1/challenge` (32 B nonce, 30 s, single use); `authenticate(db, req) → {ok, device, rule}` (§8.2 checks in order: lease, device active, nonce fresh and unused (marked used in the same tx), signature ctx `kig/v1/request` over `encode` transcript, key-version rule); `client.request(node, op, fields)` | one test per rejection rule in §8.2 (altered field, replayed nonce, expired, unknown device, wrong ctx, revoked, stale lease) |
| **3.7 Files and envelopes** | `src/cp/files.cjs`, `src/node/files.cjs`, `src/device/files.cjs`, `src/cli/file.cjs` | `kemWrap(pub, dek, ctxFields)` / `kemUnwrap(priv, wrap, ctxFields)` in `src/core/wrap.cjs` (§7 pattern); `kig file publish <file> --as <dev>`; `kig file read <file> --device <dev> --node <A\|B\|C>`; `kig share <file> --with <account>` | `no plaintext in any db` (byte scan); `envelope for A fails as B`; `tampered ct/tag/nonce/aad fail`; `peer reads after share` |
| **3.8 Device revocation and measurement** | `src/cp/revoke.cjs`, `src/cli/revoke.cjs`, `src/cli/bench-revocation.cjs` | `kig revoke --device <dev>`: CP tx + audit + snapshot push; `kig bench revocation --n 100 --seed <s>` (§10.4) writes `evidence/revocation-<ts>.json` | `all three nodes deny after revoke`; `peer still allowed`; `bench reproducible from seed` |
| **3.9 Partition and self-monitoring** | `src/cli/node.cjs`, `src/node/alerts.cjs`, `src/cp/alerts.cjs` | `kig node partition <id>` / `heal <id>` (the node stops polling and ignores pushes, via a test-only control endpoint on loopback); P1-17 alerts on CP and nodes in their audit chains; `kig alerts` merges all stores | `partitioned node denies at lease expiry and reports the bound`; `revoked device retry raises an alert on the node` |

---

# Phase 4: Rotation, lost-device re-key, crash recovery, backups

**Spec:** P1-03 (re-key half), P1-04, P1-06, P1-07; architecture §11–§13.
**Gate 4:** the §17.2 demo steps 4–8 pass as scripted tests; `kig crash-test` passes at all 5 crash points.

| Task | Files | Interfaces produced | Acceptance tests |
|---|---|---|---|
| **4.1 Rotation and cutoff** | `src/cp/rotate.cjs`, `src/node/transfers.cjs`, `src/cli/rotate.cjs` | state machine and journal from §12.1/§12.3; chunked transfer API on nodes: `POST /v1/transfer/start` → `transfer_id` bound to a version; `GET /v1/transfer/<id>/chunk/<n>`; cutoff and grace enforcement (§12.2) with `process.hrtime.bigint()` | `in-flight transfer completes within grace`; `new old-version request rejected on every node after cutoff`; `transfer terminated after 30 s`; `missing node ack aborts before commit` |
| **4.2 Lost-device re-key** | `src/cp/lostdevice.cjs`, `src/cli/lost.cjs` | `kig lost --device <dev>` = revoke + automatic rotation of every file the device could read; re-enrol through 3.5 approval | `old envelope cannot open new version`; `peer and replacement read`; `re-enrol without approval refused` |
| **4.3 Crash injection and recovery** | `src/cp/recover.cjs`, `src/cli/crash-test.cjs` | `KIG_CRASH_AT ∈ {after_prepare, after_stage, before_commit, after_commit, during_distribute}` (honoured only when `NODE_ENV=test` or under `kig crash-test`); `recover(cpDb) → {action: 'abort'\|'roll_forward'\|'none'}` | per crash point: one consistent active version; revoked stays revoked; committed data decrypts; epoch never decreases |
| **4.4 Backup and restore** | `src/cp/backup.cjs`, `src/cli/backup.cjs` | `kig backup --out <dir>`; `kig restore <dir> --recovery-key <file> --anchor <file>`, with the checks and failure categories in §13.2 | valid restore; flipped bit → `digest_mismatch`; truncation → `digest_mismatch`; bad sig → `bad_signature`; unsupported schema; older epoch → `stale_backup`; live state byte-identical after any failure |
| **4.5 Node anti-rollback** | `src/node/policy.cjs` (extend) | node records its highest applied epoch; refuses older snapshots after restart | restoring an old node DB does not re-enable a revoked device once the current snapshot is pulled |

---

# Phase 5: Detector and benchmark (parallel track)

**Spec:** P1-09, P1-10, P1-11, P1-18; architecture §15. **Depends only on Phase 0** (provider not even needed). Inputs are read from `$TOOLKIT_DIR/practice` in tests (not copied into the repo).
**Gate 5:** practice-set regression passes exactly as below; `kig bench detect --seeds <tuning> --holdout <seeds>` prints precision, recall, F1, median TTA and false alerts per 1,000 benign events for the held-out seeds.

| Task | Files | Interfaces produced | Acceptance tests |
|---|---|---|---|
| **5.1 Ingest and clock** | `src/detect/ingest.cjs`, `src/detect/clock.cjs`, `src/detect/reorder.cjs` | `parseCsv(text) → {events, rejects}` (RFC 4180 subset: quoted fields, commas, CRLF); event `{id, raw, receivedMs, offsetMs, correctedMs, ingestIdx, actor, src, dst, action, roleBefore, roleAfter, outcome, approvalId, session, correlation}`; `correct(e, {maxOffsetMs:5000, uncertaintyMs:250})`; `ReorderBuffer({lateness:5000})` with `push(e) → released[]`, `flush()` | `evt-015 corrected 09:06:01.000Z, delay 200 ms`; `evt-013/014 released in event order, ingest order kept`; `offset 6000 → clock_unsupported`; `order_uncertain when intervals overlap` |
| **5.2 Approvals and role tracking** | `src/detect/approvals.cjs`, `src/detect/roles.cjs`, `src/detect/rules-priv.cjs` | `loadApprovals(json)`; `RoleTracker` handling `grant_role` (scope + `[from, until)`) and `revoke_role` (`effective_at`); `PRIV-1`, `PRIV-2` | `evt-003..005 approved`; `evt-008 alert links evt-009`; `evt-016 matches change-101`; `role decrease never high` |
| **5.3 Baseline and lateral rules** | `src/detect/baseline.cjs`, `src/detect/rules-lm.cjs` | `Baseline.fromDocumented(edges)` + `addCorpus(events)`; `LM-1`, `LM-2`, `LM-3` (N=3), revocation-context exclusion (§15.2) | `evt-010..012 one LM-1 sequence`; `evt-007..009 no LM alert`; `evt-017/018 expected enforcement`; `evt-020 no alert`; `same result for window 30–120 s` |
| **5.4 Alerts and `kig detect`** | `src/detect/index.cjs`, `src/cli/detect.cjs` | `detect(events, approvals, baseline, cfg) → {alerts, timeline}`; alert fields per §15.2; `kig detect --events <csv> --approvals <json> [--baseline <json>] [--json]` | practice regression snapshot (expected alert set, not labels) |
| **5.5 Generator and benchmark** | `src/detect/generator.cjs`, `src/detect/bench.cjs`, `src/cli/bench-detect.cjs` | `generate(seed, cfg) → {events, labels}`, using a seeded PRNG (mulberry32, simulation only); scenario mix per §15.3; `score(alerts, labels) → metrics`; the detector never imports labels (enforced by a test that greps `src/detect/index.cjs` and its imports) | `deterministic per seed`; `held-out seeds disjoint from tuning`; metrics written to `evidence/detect-<ts>.json` with seeds, thresholds and definitions |

---

# Phase 6: Secure messaging

**Spec:** P1-12 to P1-16; architecture §16. **Depends on** 3.5 (device keystore and registry).
**Gate 6:** `kig msg demo` passes every scenario in §17.2 step 11.

| Task | Files | Interfaces produced | Acceptance tests |
|---|---|---|---|
| **6.1 Handshake** | `src/messaging/handshake.cjs` | `initiate(self, peerId) → {state, m1}`; `respond(self, m1) → {session, m2}`; `finish(state, m2) → {session, m3}`; `confirm(session, m3)`. Session holds directional keys, `session_id`, peer, epoch (§16.1). Ephemeral keys wiped on finish. | `tampered m1/m2 field fails`; `revoked or unregistered peer refused`; `wrong key-confirmation MAC fails`; `forward secrecy: leak long-term key after close, transcript undecryptable` |
| **6.2 Record layer and replay** | `src/messaging/record.cjs`, `src/messaging/replay.cjs` | `seal(session, msg) → record`; `open(session, record) → plaintext` (checks recipient first); replay window (64-bit bitmap + msg_id set), persisted in `device.db` | `wrong recipient fails`; `altered AAD field fails`; `duplicate delivered once`; `replay after receiver restart rejected`; `old session id after close rejected` (resumption not supported) |
| **6.3 Chunking and delivery** *(first to cut)* | `src/messaging/chunk.cjs`, `src/messaging/transport-sim.cjs` | `split(msg, 16 KiB)`, `Reassembler(limits)` returning `{delivered\|failed, reason}`; `TransportSim(seed, {drop, dup, reorder, delay})`; three outcomes reported separately | `recoverable loss delivered`; `duplicates not double-delivered`; `count-rewrite truncation rejected`; `expired message discarded with reason`; `limits enforced` |
| **6.4 `kig msg demo`** | `src/cli/msg.cjs` | runs the scenarios above with fixed seeds, PASS/FAIL per line | demo exits 0 |

---

# Phase 7: Evidence, demo and submission

**Spec:** P1-19 to P1-21, deliverables in `ps.md`; architecture §17–§19.
**Gate 7 (submission ready):** a fresh clone inside `scripts/judge.sh` passes `npm test` and `validate.sh`; `kig demo` passes end to end; every evidence-sheet row has an honest status; the brief PDF is ≤ 2 pages with a working video link.

| Task | Deliverable | Acceptance |
|---|---|---|
| **7.1 Performance** | `src/cli/bench.cjs`: p50/p95 for each adapter op (whole process) and in-process ops per P1-20; sizes; DB growth. Runs in ARM CI and writes `evidence/bench-arm64-<commit>.json` | numbers come from native ARM, never emulation; runtime, host and seed recorded |
| **7.2 `kig demo`** | `src/cli/demo.cjs`: the 12 steps in architecture §17.2, narrated, PASS/FAIL per step, seeded | runs from a clean `KIG_HOME` in < 3 minutes; a stranger can run it from the README |
| **7.3 Evidence sheet** | `evidence/evidence-sheet.md` from the toolkit template: one row per goal, statuses `measured`/`partial`/`not tested`/`not supported`, linked artifacts, expected results written before the runs | Goal 12 = `not supported`; nothing marked `measured` without an artifact |
| **7.4 README (final)** | clean-machine setup on Linux/macOS/WSL, Round 1 and Round 2 usage, the dependency statement, test commands, limits | a teammate follows it on a fresh machine with no help |
| **7.5 Threat model and brief** | `docs/brief/brief.md` → PDF (pandoc/Typst): page 1 USP + architecture + video link; page 2 the threat model from architecture §19 | ≤ 2 pages, ≈ 350 words per page, honesty items from features §6 present |
| **7.6 Video** | 5-minute recording of `kig demo` plus the adapter validator run; unlisted YouTube | link opens without permission requests (checked from a logged-out browser) |
| **7.7 Final rehearsal** | fresh clone → judge container → `npm test`, `validate.sh`, `kig demo`; tag `submission` | all green; tag pushed; public repo URL and PDF submitted |

---

## Self-review record

- **Spec coverage:**

  | Features | Covered by |
  |---|---|
  | P0-01..P0-10 | Phase 1 tasks 1.1–1.17 (P0-09 by 1.17 plus not shipping `threat-model.json`) |
  | P1-01..P1-21 | Phases 2–7 (P1-16 by the 6.2 negative test) |
  | D-01..D-17 | Pinned in the Phase 1 tests (D-01 in 1.8/1.10, D-02/03 in 1.11, D-04 in 1.1, D-13 in 1.14, D-16 in the "exactly N keys" tests) |
  | Architecture §20 checks | V1 → 0.3 on ARM; V2 → 0.2; V4 → 0.3; V5/V6 → 1.14 and 1.15 under `judge.sh`; V7 → 7.1 |

- **Type consistency:** `handleRaw`, `runAdapter`, `openDb`/`tx`/`StateError`, `audit.append`/`verifyChain`/`latestAccessDecision`/`countRecentDenies`, `authorizeOwnerRead`, `evaluate`/`appendAlerts` and `kemEncapsulateRaw` have the same names wherever they are consumed.
- **Proportion:** Phases 0–1 are detailed to the step, because they ship first and are frozen at Gate 1. Phases 2–7 are pinned to files, interfaces and acceptance tests. **Before starting each of them, expand it into its own step-level plan** (`docs/plans/phase-N.md`) using the same format as Phase 1.
