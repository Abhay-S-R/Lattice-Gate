# Phase 7 step-level plan: evidence, demo and submission

**Spec:** features P1-19 (CLI and demo), P1-20 (performance), P1-21 (evidence and submission), features §6 (honesty constraints); architecture §17 (CLI, demo script), §18 (testing and evidence), §19 (threat model); `docs/ps.md` §3 (deliverables) and §5 (scoring).
**Plan row:** `docs/implementation-plan.md` Phase 7 (tasks 7.1–7.7). If this file and the spec disagree, the spec wins.
**Branch:** `phase-7-submission`. **Target:** linux x86-64 (amd64) judging replica, Node 24.11.1.
**Builds on:** `main` at `7ed493d`. Phases 0–6 are merged and verified on x86-64 (`testinglogs/x64-verify-phases-0-1-2-5-f7a9e02.txt`, `x64-verify-phase4-3e19b3e.txt`, `x64-verify-phase6-ebf253f.txt`).
**Toolkit templates used:** `../Track-4-Toolkit/templates/evidence-sheet.md`, `../Track-4-Toolkit/templates/two-page-brief.md`.

---

## 0. Where we are

| Item | State |
|---|---|
| Round 1 adapter | Frozen since Gate 1. `validate.py`: `Local scenario passed.` |
| Round 2 CLI | 23 commands registered: `compat`, `verify-log`, `keys`, `checkpoint`, `alerts`, `detect`, `bench detect`, `bench revocation`, `init`, `account`, `device`, `file`, `share`, `up`, `down`, `status`, `revoke`, `node`, `rotate`, `lost`, `backup`, `restore`, `crash-test`, `msg` |
| Tests | 414/414 pass in the x86-64 replica (about 125 s) |
| Missing for submission | `kig bench perf`, `kig demo`, the evidence sheet, the final README, the 2-page brief PDF, the video, the final rehearsal and tag |
| Gaps found while planning | (a) Goals 9–12 are covered only by `kig msg demo`. No test in `npm test` runs it. (b) Every command that writes a report inside the judge replica fails with `ENOENT … not writable` because the root is read-only, so evidence has to be captured from stdout on the host. (c) `evidence/` mixes current and superseded (ARM) files. |

---

## 1. Gate 7 (submission ready)

All of these must pass on a **fresh clone**, inside `node scripts/judge.cjs …` (linux/amd64, read-only root, offline, non-root):

- [ ] `npm test`: all pass, 0 fail, 0 skipped (`pqcrypto` interop 25/25 included).
- [ ] `node scripts/validate.cjs`: `Local scenario passed.`
- [ ] `node kig.cjs compat`: all PASS.
- [ ] `node kig.cjs demo`: 12/12 steps PASS, from a clean `KIG_HOME`, in under 3 minutes.
- [ ] `node kig.cjs bench perf --json`: the report is captured to `evidence/final-<commit>/bench-perf.json`.
- [ ] `evidence/evidence-sheet.md`: one row per goal. Statuses are only `measured`, `partial`, `not tested` or `not supported`. Every `measured` row links to a file captured at the final commit. Goal 12 is `not supported`.
- [ ] `README.md`: a teammate who has not read the code follows it on a clean machine with no help.
- [ ] `docs/brief/brief.pdf`: at most 2 pages, about 350 words per page. The video link opens from a logged-out browser.
- [ ] Tag `submission` pushed. The public repo URL and the PDF are submitted.

---

## 2. Decisions taken here (not fixed by the spec)

| # | Decision | Why |
|---|---|---|
| P7-D1 | **Evidence is collected on the host by one Node script**, `scripts/collect-evidence.cjs`. It runs each check through `scripts/judge.cjs`, saves stdout+stderr per check to `evidence/final-<commit>/<check>.txt`, and writes `evidence/final-<commit>/SUMMARY.md` (check, command, exit code, duration, PASS/FAIL). | The replica's root is read-only, so in-container report writes fail (`ENOENT … not writable here`). One script replaces the hand-written PowerShell loops we used for Phases 1–6, works the same on Windows, WSL and Linux, and makes the final rehearsal a single command. |
| P7-D2 | **Commands that produce reports also support `--json` to stdout.** `bench perf` prints its whole report as JSON with `--json`. `bench detect`, `bench revocation` and `crash-test` already do. | Lets the collector save machine-readable results from inside the read-only replica. |
| P7-D3 | **`kig bench perf` is registered as a `bench` subcommand** next to `detect` and `revocation` (`src/cli/main.cjs` routes `bench perf` to `src/cli/bench-perf.cjs`). | Keeps one `bench` family. `src/cli/bench.cjs` from the plan row becomes `bench-perf.cjs`; the plan row is updated. |
| P7-D4 | **Performance numbers come from the native x86-64 replica only.** The report records `process.version`, `process.arch`, OpenSSL and SQLite versions, `os.cpus()[0].model`, CPU count, total memory, whether we are inside the replica (`/app` and `/toolkit` exist), sample count and seed. | ps.md §5 scores performance. Emulated or Windows-native numbers are not representative of judging. |
| P7-D5 | **`kig demo` runs in its own temporary `KIG_HOME` on a free port base by default**, and always tears down (`kig down`, delete the home) unless `--keep` is given. Options: `--home <dir>`, `--keep`, `--fast`, `--json`, `--practice <dir>`, `--seed <n>`. | A demo must never clobber an operator's real home, and must survive being run twice in a row in front of judges. |
| P7-D6 | **`kig demo` stops at the first failing step** and prints `FAIL step N: <reason>`, followed by a summary of every step (PASS, FAIL or NOT RUN). Exit 1 on any failure. | Steps 4–8 depend on earlier state. Continuing after a failure would print misleading PASS lines. |
| P7-D7 | **The real 30 s grace window is shown, not faked.** By default step 4 waits for the old transfer to end with `grace_expired`. `--fast` skips only that wait and prints `grace expiry not waited (--fast)`, so the line can never be mistaken for a PASS on that check. | Features §6 honesty. The 3-minute budget fits the 30 s wait (Gate 4 e2e: 34–38 s for steps 4–8). |
| P7-D8 | **Step 7 (CP crash) reuses the crash-test harness**: `src/cli/crash-test.cjs` exports `crashCpAt(home, env, point)`, and the demo calls it with `before_commit` on the demo cluster. | Crash injection is honoured only under `NODE_ENV=test` or the crash harness (Phase 4). The demo must not add a second way to enable it. |
| P7-D9 | **Step 9 (log tamper) tampers a copy, never the live store**: `VACUUM INTO` a temp file, drop the append-only triggers on the copy, edit one row, then run `verify-log --db <copy>` and expect `BROKEN seq=<n> content_edit`. The live registry must still verify `OK` afterwards. | The demo must leave a working system behind. It also mirrors what an attacker with file access would do. |
| P7-D10 | **Step 10 needs the toolkit practice files.** It looks in `--practice <dir>`, then `$TOOLKIT_DIR/practice`, then `/toolkit/practice`, then `../Track-4-Toolkit/practice`. If none exist, the step prints `SKIPPED (practice data not found)`, the demo exits 1, and the summary says so. Practice data is never copied into the repo. | Same rule as Phase 5. Showing PASS without the data would be dishonest. |
| P7-D11 | **Add `tests/e2e/msg-demo.test.cjs`**, which runs `kig msg demo` with seeds 2026 and 42 and expects every PASS line plus `Session resumption: NOT SUPPORTED (D-05)`. | Goals 9–12 then have regression coverage in `npm test` and a captured artifact for the evidence sheet. |
| P7-D12 | **Add `tests/e2e/demo.test.cjs`**, which runs `kig demo --fast --json` and expects 12 PASS. The real-grace run is captured by the collector. | Keeps `npm test` about 40 s longer, not 70 s. The full-grace run is still evidence, in `evidence/final-<commit>/demo.txt`. |
| P7-D13 | **Superseded evidence moves to `evidence/superseded/`** (the ARM files and the Phase 4 runs before `83f2294`). `evidence/README.md` explains what each folder holds. `testinglogs/` stays as the team's verification history. | Judges reading the repo should find current evidence first. Nothing is deleted. |
| P7-D14 | **No `threat-model.json` is shipped** (P0-09, open question Q3). The brief and README say why. | The toolkit's example `boundary: identity-check` does not describe an adapter whose `actor` is a trusted input. |
| P7-D15 | **The brief is written in Markdown and exported to PDF** with pandoc + a LaTeX engine or Typst if installed. Fallback: pandoc → standalone HTML → headless Chrome `--print-to-pdf`. Page count is checked from the PDF, not the Markdown. | The template says Markdown viewers do not enforce page counts. |

---

## 3. File map (Phase 7 additions)

```
scripts/collect-evidence.cjs          host-side runner → evidence/final-<commit>/          (7.0)
tests/e2e/msg-demo.test.cjs           Goals 9–12 regression via kig msg demo               (7.0)
src/cli/bench-perf.cjs                kig bench perf                                       (7.1)
src/cli/main.cjs                      route 'bench perf'                                    (7.1, modify)
src/cli/demo.cjs                      kig demo (12 narrated steps)                          (7.2)
src/cli/crash-test.cjs                export crashCpAt(home, env, point)                    (7.2, modify)
tests/unit/bench-perf.test.cjs                                                              (7.1)
tests/e2e/demo.test.cjs               kig demo --fast --json → 12 PASS                      (7.2)
evidence/README.md                    what each evidence folder holds                       (7.3)
evidence/superseded/                  ARM-era and pre-83f2294 artifacts (moved)             (7.3)
evidence/evidence-sheet.md            toolkit template, filled                              (7.3)
evidence/final-<commit>/              collector output at the submission commit             (7.3, 7.7)
README.md                             final                                                 (7.4)
docs/brief/brief.md                   2-page brief source                                   (7.5)
docs/brief/architecture.svg|png       diagram used on page 1                                (7.5)
docs/brief/brief.pdf                  submitted PDF                                         (7.5)
docs/brief/video-script.md            5-minute narration and shot list                      (7.6)
```

---

## 4. Tasks

### Task 7.0: Evidence collector and messaging regression test

**Files:** create `scripts/collect-evidence.cjs`, `tests/e2e/msg-demo.test.cjs`.

**Interfaces:**
- `node scripts/collect-evidence.cjs [--only <check,…>] [--out <dir>] [--no-judge]`
  - Default output: `evidence/final-<short commit>/`. It refuses to run if `git status --porcelain` shows tracked changes, unless `--allow-dirty` is given, because evidence must match a commit.
  - Checks, in order:

    | Check id | Command run through `scripts/judge.cjs` |
    |---|---|
    | `compat` | `node kig.cjs compat` |
    | `validate` | `node scripts/validate.cjs` |
    | `test` | `npm test` |
    | `adapter-walkthrough` | the Round 1 + checkpoint/verify-log/alerts walkthrough as a small script file (`scripts/walkthrough-adapter.cjs`), not an inline `node -e` string, so npm and PowerShell quoting cannot break it |
    | `demo` | `node kig.cjs demo --json` (real grace) |
    | `bench-perf` | `node kig.cjs bench perf --json` |
    | `bench-revocation` | `node kig.cjs bench revocation --n 100 --seed 2026 --json` |
    | `crash-test` | `node kig.cjs crash-test --json` |
    | `detect-practice` | `node kig.cjs detect --events /toolkit/practice/events.csv --approvals /toolkit/practice/approvals.json --json` |
    | `bench-detect` | `node kig.cjs bench detect --seeds 101,102,103 --holdout 201-205 --json` |
    | `msg-demo` | `node kig.cjs msg demo --seed 2026` |

  - It writes one `<check>.txt` (or `.json` when the command printed JSON) per check, and `SUMMARY.md` with environment, commit, UTC time, and a table of check, command, exit code, duration and status.
  - Exit code = number of failed checks.
  - `--no-judge` runs the same commands natively, for quick local use. `SUMMARY.md` then says `native, not the judging replica`.
- `tests/e2e/msg-demo.test.cjs`: spawns `node kig.cjs msg demo --seed <s>` for 2026 and 42. It asserts exit 0, 12 `PASS` lines, no `FAIL`, and the line `Session resumption: NOT SUPPORTED (D-05)`.

- [ ] **Step 1:** Write `tests/e2e/msg-demo.test.cjs`. Run it. Expected: PASS (the demo already exists).
- [ ] **Step 2:** Write `scripts/walkthrough-adapter.cjs` (setup → read allow → revoke → read deny → audit → `keys init` → `checkpoint` → `verify-log` → `alerts`, all inside `os.tmpdir()`).
- [ ] **Step 3:** Write `scripts/collect-evidence.cjs`. Run it with `--only compat,validate`. Expected: two files plus `SUMMARY.md`, exit 0.
- [ ] **Step 4:** Commit `test(e2e): kig msg demo regression; build: host-side evidence collector`.

---

### Task 7.1: Performance benchmark (`kig bench perf`)

**Spec:** P1-20; architecture §5.8, §18; ps.md §5 (Performance & Overhead, 10 points).
**Files:** create `src/cli/bench-perf.cjs`, `tests/unit/bench-perf.test.cjs`; modify `src/cli/main.cjs`.

**Interfaces:**
- `node kig.cjs bench perf [--runs <n>] [--seed <n>] [--no-cluster] [--json] [--out <file>]`. Defaults: `--runs 40` for whole-process measurements and 200 for in-process measurements, `--seed 2026`.
- The report contains `environment` (P7-D4), `config`, `results` and `limits`. Every timing has `{ n, p50_ms, p95_ms, max_ms, mean_ms }`, computed with the nearest-rank method already used by `bench revocation`.

**What is measured:**

| Group | Measurement | How |
|---|---|---|
| Process baseline | empty `node -e ""` process | spawn N times |
| Round 1 adapter (whole process, as the worker sees it) | `setup` (2 assets), `read` allow, `read` deny, `revoke`, `audit` hit, `audit` miss, `protected_read` allow, `protected_read` invalid key | spawn `track4_service.cjs` N times each in a fresh `TRACK4_STATE_DIR` seeded once |
| Round 1 large input | `setup` with a 1 MiB body and with 4 MiB − 1 KiB (just under the stdin cap) | spawn 5 times each (architecture §20 V7) |
| Crypto (in-process) | ML-KEM-768 keygen, encapsulate, decapsulate; ML-DSA-65 keygen, sign, verify; AES-256-GCM seal and open at 1 KiB, 64 KiB and 256 KiB; HKDF; HMAC; `kemWrap`/`kemUnwrap` | `process.hrtime.bigint()` loops |
| Storage (in-process) | audit append (one event in one `tx`); `verifyChain` over 1 000 and 10 000 events; DB bytes per audit event (file size including WAL ÷ events) | temp SQLite file |
| Round 2 (cluster, skipped with `--no-cluster`) | challenge + signed `file.read` round trip through node A; `kig rotate` end to end; `kig revoke` to last-node denial (summary from the revocation bench helper, 20 samples) | temporary home, free port base, torn down at the end |
| Detector | events per second on 10 000 generated events (seed fixed); `detect` on the 22 practice events | in-process |
| Messaging | handshake (M1–M3) duration; `seal`/`open` per 16 KiB chunk | in-process with two temporary identities |
| Sizes (bytes, constant) | ML-KEM pk/ct/ss, ML-DSA pk/sig, AES-GCM nonce/tag; envelope size per device; one policy snapshot with 3 devices; one backup for a 3-device, 1-file home | measured from real objects, never hard-coded |

- `limits` states, in the report itself: one host; loopback HTTP; numbers vary with CPU; whole-process numbers include Node start-up; the replica is a stand-in for the organizer container.
- Without `--json` it prints a readable table. With `--out` it writes JSON there, and on a read-only filesystem it prints a notice and still exits 0 (same behaviour as `bench detect`).

- [ ] **Step 1: Write failing tests** (`tests/unit/bench-perf.test.cjs`):
  - `percentiles use nearest rank` (fixed inputs → known p50/p95)
  - `report shape`: `--runs 3 --no-cluster --json` gives valid JSON with `environment.node === process.version`, every timing has the five fields, and every size is a positive integer
  - `sizes are measured`: ML-KEM ct = 1088, ML-DSA sig = 3309, pk = 1184 / 1952
  - `read-only --out still exits 0 and prints`
  - `bad --runs exits 2`
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement. Reuse the percentile helper from `src/cli/bench-revocation.cjs` (export it if needed) rather than writing a second one.
- [ ] **Step 4:** Run the tests (PASS), then `node scripts/judge.cjs node kig.cjs bench perf` and check the numbers look sane (adapter p50 should be about 50–150 ms; ML-DSA verify under 1 ms).
- [ ] **Step 5:** Commit `feat(cli): kig bench perf (latency, sizes, storage growth)`.

---

### Task 7.2: Narrated demo (`kig demo`)

**Spec:** P1-19; architecture §17.2 (12 steps).
**Files:** create `src/cli/demo.cjs`, `tests/e2e/demo.test.cjs`; modify `src/cli/crash-test.cjs` (export `crashCpAt`) and `src/cli/main.cjs` (register `demo`).

**Interfaces:**
- `node kig.cjs demo [--home <dir>] [--keep] [--fast] [--json] [--practice <dir>] [--seed <n>]`.
- Human output per step:

  ```
  [5/12] Lost device (Goal 2)
         alice-phone reported lost → revoked; brief re-keyed 2 → 3
         node A denied after 31 ms, B 33 ms, C 35 ms (signed acks)
         PASS step 5
  ```

  The summary at the end lists all 12 steps, the total time and `RESULT: 12/12 PASS` (or the first failure).
- `--json` prints `{ commit, started_utc, duration_ms, steps: [{ n, title, goal, status, details, duration_ms }] }`.
- Implementation follows `tests/e2e/phase4-demo.test.cjs`, which already does steps 1–8 against a live cluster. It moves that sequence into `src/cli/demo.cjs` so the test and the demo share the behaviour, using the device client (`src/device/client.cjs`, `src/device/files.cjs`) for in-flight transfers.

**The 12 steps (each must print what it checked, not just PASS):**

| # | Step | Goal | Checks that make it PASS |
|---|---|---|---|
| 1 | `init`, `up`: CP and nodes A/B/C start; snapshot epoch ≥ 1 on all nodes | – | `status` shows 4 healthy; same epoch on A, B, C |
| 2 | Enrol alice-phone (operator approval), alice-laptop (approved by alice-phone), bob-laptop (operator) | 2 | 3 active devices in the signed snapshot on every node |
| 3 | Alice publishes `brief` (about 20 KB, so 3 transfer chunks), shares with Bob; Bob reads via A, B and C | – | plaintext equal on all 3 nodes; no plaintext in any `.db` (byte scan of the home) |
| 4 | Rotate `brief` while Bob's transfer is in flight | 1 | the old transfer finishes with rule `grace`; a new v1 request is refused `old_key_version` on A, B and C; v2 reads succeed; every snapshot has `cutoff {old_version:1, grace_ms:30000}`; after 30 s the old transfer ends with `grace_expired` (skipped with `--fast`, per P7-D7) |
| 5 | `kig lost --device alice-phone` | 2 | revoked; per-node signed-ack latency printed; `device_revoked` on A, B and C; `brief` re-keyed |
| 6 | alice-phone-2 enrols; approval by the lost phone is refused; approval by alice-laptop works | 2 | pending device gets `unknown_device` everywhere; `approver_not_active`; Bob and alice-phone-2 read the new version on A, B and C; the lost phone's old key cannot open the new ciphertext |
| 7 | Crash the CP at `before_commit` during another rotation, then restart | 3 | the CP was killed with no answer; recovery `abort`; the old version is still active on the CP and every node; alice-phone still denied; Bob reads; epoch not lower |
| 8 | Backup; flip a byte → `digest_mismatch`; truncate → `digest_mismatch`; an older backup (taken in step 3) → `stale_backup`; the good backup restores | 4 | registry byte-identical after each refusal; after the restore and `up`, Bob reads and `verify-log` is OK |
| 9 | `verify-log` on the CP and the three node stores; tamper a **copy** (P7-D9); injection actor | 5 | live stores `OK`; copy gives `BROKEN seq=<n> content_edit`; an actor named `x\n{"actor":"admin"}` is one event with that exact actor |
| 10 | `detect` on the practice data; `bench detect` with small seeds | 6, 7, 8 | exactly 2 alerts (`PRIV-1` user-blair, evt-008/009; `LM-1` svc-report-worker, evt-010..012, all denied); evt-015 corrected to 09:06:01.000Z; evt-013 before evt-014; evt-017/018 `expected_enforcement`; evt-020 no alert; held-out metrics printed (seeds 201, 202) |
| 11 | `msg demo` (seed from `--seed`, default 2026) | 9, 10, 11, 12 | all 12 PASS lines; `Session resumption: NOT SUPPORTED (D-05)` printed as **not supported**, not as a pass |
| 12 | `alerts` across CP, nodes and a small Round 1 adapter run | self-monitoring | at least: node revoked-device retry, `A-REVOKED-RETRY` on the adapter, the restore refusals; identifiers escaped |

- [ ] **Step 1:** Export `crashCpAt(home, env, point)` from `src/cli/crash-test.cjs`, with no change in behaviour. Run `tests/crash/rotation-crash.test.cjs`. Expected: PASS.
- [ ] **Step 2:** Write `tests/e2e/demo.test.cjs` (`kig demo --fast --json` → 12 steps, all `PASS` except that the step-4 grace-expiry sub-check is reported as skipped). Run it. Expected: FAIL (no command).
- [ ] **Step 3:** Implement `src/cli/demo.cjs` step by step, re-running the test after each step is added.
- [ ] **Step 4:** Run `node scripts/judge.cjs node kig.cjs demo` (real grace). Expected: 12/12 PASS in under 3 minutes. Run it twice in a row to prove there are no leftovers (ports, homes, processes).
- [ ] **Step 5:** Run `node scripts/judge.cjs npm test`. Expected: all pass.
- [ ] **Step 6:** Commit `feat(cli): kig demo, 12 narrated steps (architecture §17.2)`.

---

### Task 7.3: Evidence sheet and evidence tidy-up

**Spec:** P1-21; toolkit `templates/evidence-sheet.md`; features §6, §7.
**Files:** create `evidence/evidence-sheet.md`, `evidence/README.md`; move superseded files to `evidence/superseded/` (`git mv`).

- [ ] **Step 1:** `git mv` the ARM-era files (`superseded-arm64-*`) and the pre-`83f2294` Phase 4 runs (`*-6984769.txt`, `*-cca2fa5.txt`) into `evidence/superseded/`. Fix any links in `evidence/phase4.md`, `evidence/phase5.md` and `README.md`.
- [ ] **Step 2:** Write `evidence/README.md`: what is in `final-<commit>/` (the submission evidence), the per-phase reports (`round1.md`, `phase3.md`, `phase4.md`, `phase5.md`), `superseded/`, and `../testinglogs/`.
- [ ] **Step 3:** Run `node scripts/collect-evidence.cjs` on the Task 7.2 commit to get current artifacts.
- [ ] **Step 4:** Write **expected results first** (ps rule: "Expected behavior you define before run"), then fill the actual results from `evidence/final-<commit>/`. Header: team, commit, collector run ID (the folder name), UTC time, environment (linux/amd64 replica, Node 24.11.1, OpenSSL 3.5.4, SQLite 3.50.4, 1 host, 1 CP + 3 nodes, CPU model from `bench-perf.json`).

**Row plan (status is decided by what the run shows, not by this table):**

| Goal | Expected (written before the run) | Evidence to link | Status if the evidence holds |
|---|---|---|---|
| 1. Key rotation | Versions `ACTIVE → RETIRED`; cutoff by epoch; 30 s node-local grace for transfers already authenticated; new old-version requests refused on every node | `demo` step 4, `test` (rotation tests), `phase4.md` | measured |
| 2. Revocation across nodes | Every node denies after applying the signed snapshot; latency from CP commit to last-node denial; peer unaffected; re-enrol needs a second factor | `bench-revocation.json`, `demo` steps 5–6 | measured |
| 3. Crash recovery | No durable COMMIT → abort; durable COMMIT → roll forward; revocations never undone; data readable | `crash-test.json` (5/5), `demo` step 7 | measured |
| 4. Backup integrity | Each tamper class refused with its category; live state unchanged; restore only from verified material | `demo` step 8, `test` (backup tests) | measured |
| 5. Log integrity | Edit, delete, reorder → detected; truncation and rewrite detected **with** an external anchor only; injection stays one event | `adapter-walkthrough`, `demo` step 9, `test` (verify-log, checkpoint) | measured |
| 6. Routine vs suspicious | Practice set: 2 alerts, 0 false alerts; held-out F1, median TTA, false alerts per 1 000 benign | `detect-practice.json`, `bench-detect.json`, `phase5.md` | measured, on synthetic data only (stated) |
| 7. Lateral movement | evt-010..012 one LM-1 alert with path, rule and denied outcomes; evt-020 no alert | `detect-practice.json` | measured |
| 8. Clock differences | ±5 s supported; evt-015 corrected with 200 ms delay; evt-013/014 reordered; out-of-range flagged | `detect-practice.json`, `test` | measured |
| 9. Replay and recipient binding | Wrong recipient, altered AAD and duplicates rejected; replay rejected after receiver restart | `msg-demo.txt`, `test` (msg-demo e2e) | measured |
| 10. Forward secrecy | Exact claim: later exposure of a long-term ML-DSA key alone does not reveal a completed session; assumptions listed | `msg-demo.txt` | measured (claim limited as stated) |
| 11. Delivery under loss/reordering | Receipt, reassembly and delivery reported separately; incomplete messages discarded with a reason; authenticated chunk count | `msg-demo.txt` | measured |
| 12. Session resumption | Not supported (D-05); an old session ID or key is rejected after close or revocation | `msg-demo.txt` | **not supported** |

- [ ] **Step 5:** Add one **Measurement record** (template block) each for: revocation propagation latency, crash recovery, held-out detection metrics, Round 1 adapter latency. Each lists claim, setup and seed, procedure, expected, observed (counts, units, sample size), evidence path, limits.
- [ ] **Step 6:** Review against features §6 (all 14 honesty items) and confirm nothing is marked `measured` without a linked file.
- [ ] **Step 7:** Commit `docs(evidence): evidence sheet, evidence index, superseded files moved`.

---

### Task 7.4: Final README

**Spec:** ps.md §3 ("README.md with clean-machine setup steps"), §5 (Usability & Documentation, 10 points).
**Files:** modify `README.md`.

The README is already detailed (127 lines). The final version adds or changes the following:

- [ ] **Step 1: Top of the file.** Add the security claim, a 5-line "what this is", and a **Quick start** that works on a clean machine:
  1. Install Node.js 24.11.1 (links for Windows, macOS and Linux; `nvm install` reads `.nvmrc`).
  2. `git clone https://github.com/Abhay-S-R/devforge && cd devforge`.
  3. `node --version` → `v24.11.1`; `npm run compat` → all PASS.
  4. `node kig.cjs demo` → 12/12 PASS (about 2 minutes).
  5. Optional: clone the toolkit next to the repo, then `npm test` and `npm run validate`.
- [ ] **Step 2: Dependency statement.** Runtime: **none**, Node 24.11.1 built-ins only, no `npm install`. Dev and test only: Python 3.12 + `pqcrypto==0.4.0` (interop test, skipped with a notice if absent), Docker Desktop (judge replica), the organizer toolkit (validator and practice data).
- [ ] **Step 3: Results table.** One line per goal with its status and a link to `evidence/evidence-sheet.md`. Key numbers from `evidence/final-<commit>/` (revocation p50/p95, adapter p50, held-out F1, crash-test 5/5).
- [ ] **Step 4: Usage.** Keep the Round 1 and Round 2 sections. Add `demo` and `bench perf` to the command table. Add a "Reproduce all evidence" section: `node scripts/collect-evidence.cjs`.
- [ ] **Step 5: Limitations.** Merge in the Round 2 limits from the brief's threat model (CP is the key custodian; single host; synthetic detection data; no session resumption; no hybrid KEM; best-effort memory wiping; no `threat-model.json`, with the reason).
- [ ] **Step 6: Clean-machine check.** A teammate who did not write the code follows the README on a machine (or a fresh WSL distro, or a `node:24.11.1` container with the repo copied in) with nothing else installed. Record every stumble and fix the README until a run goes through with no help.
- [ ] **Step 7:** Commit `docs: final README (quick start, results, reproduce evidence)`.

---

### Task 7.5: Two-page brief and threat model

**Spec:** ps.md §3 (2-page PDF: USP, architecture, one-page threat model, video link); toolkit `templates/two-page-brief.md`; architecture §19; features §6.
**Files:** create `docs/brief/brief.md`, `docs/brief/architecture.svg` (or `.png`), `docs/brief/brief.pdf`.

**Page 1 (about 350 words):** USP, architecture, video.
- Header: project, team names, repo URL and commit, demo entry point (`node kig.cjs demo`).
- **USP (at most 4 sentences):** for a team sharing sensitive files, KIG keeps post-quantum protection and access decisions correct while devices are lost, keys rotate and permissions change. Every decision lands in a hash-chained, ML-DSA-signed log the operator verifies offline, and an explainable detector flags unapproved privilege changes and lateral movement. It uses zero runtime dependencies, Node 24.11.1 built-ins only, and every claim comes with a command that reproduces it.
- **Architecture:** a small diagram (control plane, nodes A/B/C, devices, operator/anchor, Round 1 adapter beside it) plus 5–6 lines: ML-KEM-768 (FIPS 203) envelopes + AES-256-GCM + HKDF-SHA-256; ML-DSA-65 (FIPS 204) device signatures, signed epoch snapshots, checkpoints and backups; SQLite with WAL; signed snapshots + 5 s lease (fail closed); rotation journal; detector rules PRIV-1/2, LM-1/2/3. Mark working vs not built (session resumption and hybrid X-Wing are not built).
- **Video:** link, duration 5:00, "access checked on <date> from a logged-out browser".
- **Observed outcome:** one paragraph with 4–5 numbers from `evidence/final-<commit>/` (414+ tests pass; validator pass; revocation last-node p50/p95; crash-test 5/5; held-out F1 and false alerts per 1 000).

**Page 2 (about 350 words):** threat model, built from architecture §19.
- **Assets:** file plaintext and DEKs (confidentiality); device identities (authenticity); signed policy and revocation state (integrity, freshness); audit logs (integrity, completeness relative to the anchor); backups (integrity, confidentiality); Round 1 allow/deny correctness.
- **Adversaries:** Round 1: anyone controlling stdin JSON. Round 2: a lost or stolen device; a revoked device retrying; a network attacker on messaging (drop, replay, reorder, alter); someone who tampers with backup or log files; an insider with valid credentials moving between services.
- **Trust boundaries:** worker → adapter (stdin); device → node (signed request + fresh nonce); CP → node (signed snapshot); operator → CP (approvals, restore); where identity and permission are checked.
- **Assumptions:** the CP and its keys are trusted (KMS model); the operator keeps the recovery key and anchor safe; one host and one monotonic clock; the adapter's `actor` is a trusted input.
- **Defenses → evidence:** one line per main threat, pointing at the evidence-sheet row.
- **Exclusions and remaining risks:** CP compromise exposes files; copied plaintext cannot be recalled; JS cannot guarantee memory wiping; latency excludes real networks; at-rest envelopes are not forward-secret; no post-compromise security; no session resumption; detection metrics are from synthetic data; state directory out of scope in Round 1 (D-15); stored adapter bodies are plaintext (D-14). **Largest remaining risk:** the CP is a single trusted custodian.

**Export:**
- [ ] **Step 1:** Write `docs/brief/brief.md` from the template (keep its headings so reviewers find each item).
- [ ] **Step 2:** Make the diagram. Mermaid → SVG with `npx @mermaid-js/mermaid-cli` (dev machine only, never a repo dependency), or draw it by hand.
- [ ] **Step 3:** Export. Pick one:
  - `pandoc docs/brief/brief.md -o docs/brief/brief.pdf --pdf-engine=typst` (or `xelatex`), with margins and font size set so each page fits; or
  - `pandoc docs/brief/brief.md -s -o docs/brief/brief.html`, then `chrome --headless --print-to-pdf=docs/brief/brief.pdf docs/brief/brief.html`.
- [ ] **Step 4:** Check from the PDF: exactly 2 pages (open it, or `python -c "import pypdf;print(len(pypdf.PdfReader('docs/brief/brief.pdf').pages))"`); the link is clickable; nothing is cut off.
- [ ] **Step 5:** Two teammates review it for the honesty items (features §6) and for any claim without evidence.
- [ ] **Step 6:** Commit `docs(brief): two-page brief and threat model`. The final PDF is rebuilt after 7.6 adds the video link.

---

### Task 7.6: Five-minute video

**Files:** create `docs/brief/video-script.md`.

**Shot list (terminal on the left with `node kig.cjs demo`; browser or second terminal on the right):**

| Time | Scene | On screen |
|---|---|---|
| 0:00–0:20 | Hook and claim | Title card with the security claim; `node kig.cjs compat` all PASS |
| 0:20–0:50 | Round 1 | `node scripts/validate.cjs` → `Local scenario passed.` (mention: the adapter is the automated stage) |
| 0:50–1:20 | Demo steps 1–3 | Cluster up, devices enrolled, Bob reads via A, B, C |
| 1:20–2:10 | Step 4, rotation with grace | In-flight transfer finishes; old version refused on every node; narrate during the 30 s wait |
| 2:10–2:50 | Steps 5–6, lost device | Per-node latency; replacement approval; Bob never loses access |
| 2:50–3:30 | Steps 7–8, crash and backup | Abort recovery; tamper categories; restore |
| 3:30–4:10 | Steps 9–10, log and detector | `content_edit` on the copy; PRIV-1 and LM-1 alerts with reasons; held-out metrics |
| 4:10–4:40 | Steps 11–12, messaging and alerts | Replay and recipient checks; resumption not supported; alert list |
| 4:40–5:00 | Close | 12/12 PASS summary; one honest limit (CP is the custodian); repo URL |

- [ ] **Step 1:** Write `video-script.md` with the narration word for word (about 130 words per minute, so about 650 words).
- [ ] **Step 2:** Rehearse with a stopwatch. If it runs over 5:00, cut words, not checks.
- [ ] **Step 3:** Record with OBS at 1080p, terminal font at least 16 pt, and a dark theme with high contrast.
- [ ] **Step 4:** Upload as **unlisted** to YouTube (or Drive set to "anyone with the link"). Open the link in a private window while logged out. Record the date in the brief.
- [ ] **Step 5:** Put the link in `docs/brief/brief.md`, rebuild the PDF, and re-check that it is still 2 pages.
- [ ] **Step 6:** Commit `docs(brief): video link and script`.

---

### Task 7.7: Final rehearsal, tag and submission

- [ ] **Step 1: Freeze.** No feature changes after this point; bug fixes only, each with a regression test.
- [ ] **Step 2: Fresh clone in a new folder** (not the working copy):

  ```powershell
  git clone https://github.com/Abhay-S-R/devforge $env:TEMP\kig-final
  cd $env:TEMP\kig-final
  node scripts/collect-evidence.cjs
  ```

  Expected: every check PASS; `evidence/final-<commit>/SUMMARY.md` written. Also confirm `docker images` shows the replica was rebuilt from this clone.
- [ ] **Step 3:** Copy `evidence/final-<commit>/` back to the working copy if the commit matches, link it from the evidence sheet, README and brief, and rebuild the PDF if any number changed. If anything changed, repeat Step 2 on the new commit.
- [ ] **Step 4:** Check that the repository is public and that the README renders on GitHub with working links (relative paths, no `file:///`).
- [ ] **Step 5:** Tag and push:

  ```powershell
  git tag -a submission -m "DevForge Track 4 submission"
  git push origin main --tags
  ```

- [ ] **Step 6:** Submit the public repo URL and `docs/brief/brief.pdf`. Open the submitted PDF once more and click the video link.

---

## 5. Order, ownership and time

```
7.0 collector + msg test ──┬──► 7.1 bench perf ──┐
                           └──► 7.2 kig demo ─────┼──► 7.3 evidence sheet ──► 7.4 README ──┐
7.5 brief draft (from now) ─────────────────────── ┘                                         ├──► 7.6 video ──► 7.7 rehearsal + tag
                                                                                              │
                                     7.5 brief final (numbers from 7.3) ───────────────────── ┘
```

| Person | Tasks | Notes |
|---|---|---|
| A (code) | 7.0, 7.1, 7.2 | 7.2 is the longest. Start it first if two people can code. |
| B (evidence and docs) | 7.3, 7.4 | Can start the tidy-up (7.3 steps 1–2) and README structure right away |
| C (brief and video) | 7.5, 7.6 | Draft the brief now with placeholders for numbers; record once `kig demo` passes |
| All | 7.7 | Done together; everyone checks the submitted PDF and link |

**Rough effort:** 7.0 ≈ 1.5 h · 7.1 ≈ 2–3 h · 7.2 ≈ 4–6 h · 7.3 ≈ 2 h · 7.4 ≈ 1.5 h · 7.5 ≈ 3 h · 7.6 ≈ 2–3 h · 7.7 ≈ 1 h.

---

## 6. Cut order if time runs short

1. Drop `bench perf` cluster measurements (`--no-cluster` becomes the default). Keep adapter, crypto and size numbers.
2. Drop step 12's adapter sub-run in `kig demo`.
3. Use `--fast` in the video and say the grace wait is shown in the captured evidence.
4. Simplify the brief diagram to a text block.

**Never cut:** Gate 7 items for `npm test`, the validator and the evidence sheet; the threat-model exclusions; Goal 12 shown as `not supported`; the fresh-clone rehearsal.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| `kig demo` is flaky (ports, timing) in front of judges | Free port base, `until()` polling like the e2e tests, run twice back to back in Step 7.2.4, and the video as fallback |
| Numbers in the brief, README and evidence sheet drift apart | All three quote `evidence/final-<commit>/` only; 7.7 Step 3 re-checks after the last commit |
| Brief runs over 2 pages | Check page count from the PDF; cut words, keep the threat-model exclusions |
| Video link not public | Logged-out check, recorded in the brief |
| Late bug fix invalidates evidence | 7.7 Step 3: any new commit means re-running the collector on a fresh clone |
| A judge runs `npm test` without the toolkit or Python | README says which tests skip and why; the skip prints a visible notice (already true for interop) |
