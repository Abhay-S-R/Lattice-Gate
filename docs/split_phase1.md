# Phase 1 Work Split: Developer A and Developer B

This splits **Phase 1 (Round 1 adapter)** of `docs/implementation-plan.md` between two developers. Task details, interfaces and tests are in the plan, so this file does not repeat them. It covers **who does what, in what order, and where the two meet**. If this file and the plan disagree, the plan wins (and the spec wins over the plan).

**Precondition:** Gate 0 has passed. `src/crypto/provider.cjs`, `kig compat`, `scripts/judge.cjs`, `scripts/validate.cjs` and CI are all on `main`.

---

## 1. Team setup (both developers)

- **Node 24.11.1 exactly.** `.nvmrc` pins it.
- Clone the toolkit **next to** this repo as `../Track-4-Toolkit`. `scripts/validate.sh` expects it there.
- Commands, which work the same from Windows, WSL and Linux:

  | Command | What it does |
  |---|---|
  | `npm test` | All `*.test.cjs` suites |
  | `npm run compat` | `kig compat` crypto/runtime checks |
  | `npm run validate` | Toolkit `validate.py` against the root adapter |
  | `npm run judge -- <command>` | Runs `<command>` inside the x86-64 judging replica, for example `npm run judge -- npm test` |

- **A judge run is native on x86-64 machines** (the judging platform), so it is about as fast as a normal run. Still run it **before merging**. For the inner loop, use `node --test <file>`.

---

## 2. Branching and merging

- Integration branch: `phase-1-adapter`, cut from `main`. Nothing goes to `main` until Gate 1 passes (Task 1.17).
- Each developer works on short task branches off `phase-1-adapter`, such as `p1/a-ids-encoder` or `p1/b-validate`, and merges it **into `phase-1-adapter`** once reviewed.
- Commit once per task, using the plan's message (for example `feat(core): opaque identifier encoding and limits`).
- Every merge needs: its task tests green locally, `npm run judge -- npm test` green, and a review from the other developer.
- **The other developer reviews each change before it merges.** That way both people know both halves before the joint stage.

---

## 3. Stage 1: Foundations (in parallel)

### Developer A: tasks 1.1 → 1.5 (the shared core)

| Order | Task | Files | Unblocks |
|---|---|---|---|
| 1 | **1.1** Limits and opaque identifiers | `src/core/limits.cjs`, `src/core/ids.cjs` | B's 1.6 (`isHostile`, limits), every later task |
| 2 | **1.2** Length-prefixed encoder | `src/core/encoding.cjs` | 1.5 |
| 3 | **1.3** SQLite helper | `src/store/db.cjs` | 1.4, all ops |
| 4 | **1.4** Adapter schema | `src/store/schema-adapter.cjs` | B's 1.7 tests against the real schema, all ops |
| 5 | **1.5** Audit chain | `src/core/audit.cjs` | all ops, 1.13 |

**Merge 1.1 on its own and early (hours, not days).** It is small, and B's validator depends on `ids.isHostile` and `limits`.

Watch for:
- 1.3 `parallel create` must pass **20/20**. This is the cold-start race (features R9), and the bug most likely to fail hidden tests. Do not merge it at 19/20.
- 1.3: check `fs.existsSync` **before** constructing `DatabaseSync`, because the constructor silently creates a missing file.
- 1.4 must match the DDL in architecture §5.4 exactly. B writes policy queries against those table and column names.

### Developer B: tasks 1.6 and 1.7 (request side)

| Order | Task | Files | Depends on |
|---|---|---|---|
| 1 | **1.6** Request validation | `src/adapter/validate.cjs` | `limits`, `ids.isHostile` (A's 1.1) |
| 2 | **1.7** Access policy | `src/core/policy.cjs` | adapter table layout (architecture §5.4) |

Dependencies, and how to avoid waiting:
- **1.6 depends on 1.1.** Start with `isStrictBase64` and the per-op shape checks, which need nothing from A. Wire in `ids.isHostile` / `MAX_ID_LEN` once A's 1.1 merges, which should be the same day.
- **1.7 reads the adapter tables** (`assets`, `revoked_actors`). It does not need `openDb`, `tx` or the audit chain. Until 1.4 merges, test against an in-memory `DatabaseSync(':memory:')` built from the §5.4 DDL. After 1.4 merges, switch the test fixture to `schema-adapter.init` and delete the copied DDL. **Do not merge 1.7 until it runs against the real `init`.**
- Remember that IDs are stored with `ids.enc` (D-04). Policy must compare **encoded** values and return a **decoded** body.

Watch for:
- 1.6: `setup` maps are built from `Object.entries` into a `Map`, never into a plain object. `__proto__` and `constructor` must survive as ordinary keys.
- 1.6: `key_material` is dropped at validation and never copied into `req`.
- 1.7: the check order is fixed: revoked → unknown asset (including owner/body NULL) → not owner → allow. A deny has **no** `body` key.

### Sync point S1: "foundations merged"

Stage 2 starts once **1.1–1.7 are all merged into `phase-1-adapter`** and `npm run judge -- npm test` is green on that branch. Hold a 15-minute walkthrough: A presents the `db`/`audit` interfaces and B presents `validate`/`policy`.

If B finishes before A, B can start drafting `tests/helpers/run-adapter.cjs` (part of 1.14), which only spawns a process and has no dependency on A's work.

---

## 4. Stage 2: Joint work (1.8–1.17)

The split follows ownership. A takes the ops that are mostly **state and persistence**. B takes the ops that are mostly **policy, crypto and request handling**.

| Task | Owner | Why this person |
|---|---|---|
| **1.8** `setup` | **A** | Generations, quarantine and `tx`, all built on A's 1.3–1.5 |
| **1.9** `read` | **B** | Thin wrapper around B's `authorizeOwnerRead` |
| **1.10** `revoke` | **A** | Persistence, epochs, exit-1 path |
| **1.11** `audit` | **A** | `latestAccessDecision` from A's 1.5 |
| **1.12** `protected_read` | **B** | Builds on B's strict Base64 and policy; crypto provider |
| **1.13** Alerts (P0-10) | **B** | Touches every op, so it is done after 1.8–1.12; uses A's `countRecentDenies` |
| **1.14** Entry point, routing, error policy | **B** | Driven by `validate` and the §5.6 error table |
| **1.15** Hardening: `negative.test.cjs` | **B** | Hostile IDs and input shapes (Review focus 1, 4, 5) |
| **1.15** Hardening: `concurrency.test.cjs`, `adapter-kill.test.cjs` | **A** | Busy retry, cold start, crash (Review focus 2, 3) |
| **1.16** `pqcrypto` interop | **B** | Verifies 1.12 |
| **1.17** Evidence, README, Gate 1 | **Both** | A runs Gate 1 items 2 and 4; B runs items 1 and 3; both review README |

### Order inside Stage 2

```
        A                                B
  1.8 setup  ─────────────┐
                          ├──► 1.9 read  (needs setup to seed tests)
  1.10 revoke             │    1.12 protected_read
  1.11 audit              │
        └────────┬────────┘
                 ▼
          S2: ops 1.8–1.12 merged
                 │
                 ├──► B: 1.13 alerts   ──┐
                 │                       ├──► B: 1.14 entry point
  A: start concurrency/crash test drafts │
                 ▼                       ▼
          S3: 1.14 merged (validate.sh → "Local scenario passed.")
                 │
     A: 1.15 concurrency + crash     B: 1.15 negative, 1.16 interop
                 ▼
          1.17 together → Gate 1 → merge to main → tag round1-ready
```

1. **A does 1.8 first.** Every other op's tests need `setup` to seed state. B can write 1.9 and 1.12 tests in the meantime and run them once 1.8 merges.
2. A then does 1.10 and 1.11 while B finishes 1.9 and 1.12.
3. **S2:** all five ops merged. B adds 1.13 alerts (every op's `tx` gets an `evaluate` call), then 1.14.
4. **S3:** 1.14 merged and `npm run validate` prints `Local scenario passed.`. The hardening suites run against the real process from here on.
5. 1.15 and 1.16 in parallel, then 1.17 together.

### Avoiding conflicts in `src/adapter/ops.cjs`

Both developers edit this one file during 1.8–1.13. To keep merges clean:
- A creates the file in 1.8 with one exported function per op, **in this order**: `setup`, `read`, `revoke`, `audit`, `protectedRead`. The ones not yet built are stubs that throw `new Error('not implemented')`. Shared helpers (for example opening the DB for the state dir) go at the top.
- Each person edits only the body of the functions they own. Do not reorder, reformat or "tidy" the other person's functions.
- Rebase on `phase-1-adapter` before each merge.
- In 1.13, B adds the `evaluate`/`appendAlerts` calls to **A's** ops too. A reviews that change specifically for transaction boundaries.

### Hand-offs that need a second look

- **`revoke` and `setup` exit 1** (A, 1.8 and 1.10) is turned into the fixed stderr line by B's 1.14. Agree on the error that the ops throw: plain `StateError`, not a custom wrapper.
- **The test hook `KIG_TEST_HANG_IN_TX`** (A's crash test) lives inside `ops.revoke`. A owns it, and it may only be read when `NODE_ENV==='test'`.
- **`protected_read` two-transaction rule** (B, 1.12): authorize in tx #1, encapsulate outside, audit in tx #2. If tx #2 fails, return deny. A reviews this.

---

## 5. Gate 1 checklist (Task 1.17)

All run inside `npm run judge -- …` (x86-64 replica), plus green CI:

- [ ] `npm run judge -- sh scripts/validate.sh` → `Local scenario passed.`, exit 0, output saved to `evidence/` (**B**)
- [ ] `npm run judge -- npm test` → all suites pass, including cold start ×20 and crash (**A**)
- [ ] Interop `25/25` (Task 1.16) (**B**)
- [ ] Marker scan: `key_material` absent from stdout, stderr and every byte under the state dir, including `-wal` (**A**)
- [ ] `README.md` and `evidence/round1.md` written and reviewed by both
- [ ] `phase-1-adapter` approved by both, merged into `main`, tagged `round1-ready`

**After Gate 1 the adapter is frozen.** Changes are only for bugs, and each one comes with a regression test.

---

## 6. Summary of ownership

| | Developer A | Developer B |
|---|---|---|
| Stage 1 | 1.1, 1.2, 1.3, 1.4, 1.5 | 1.6, 1.7 |
| Stage 2 | 1.8, 1.10, 1.11, 1.15 (concurrency + crash) | 1.9, 1.12, 1.13, 1.14, 1.15 (negative), 1.16 |
| Together | 1.17 and Gate 1 | 1.17 and Gate 1 |
| Files owned | `src/core/{limits,ids,encoding,audit}.cjs`, `src/store/*`, `ops.setup/revoke/audit` | `src/adapter/{validate,index}.cjs`, `src/core/{policy,alerts}.cjs`, `ops.read/protectedRead`, `track4_service.cjs`, `team_app.cjs`, `tests/helpers/run-adapter.cjs`, `tests/interop/*` |
