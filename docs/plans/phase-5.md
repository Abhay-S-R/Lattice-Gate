# Phase 5 Implementation Plan: Detector and Benchmark

> **For agentic workers:** Follow the TDD loop for every task: write failing tests → run and verify FAIL → implement → run and verify PASS → commit. Steps use checkbox (`- [ ]`) syntax for tracking.

**Phase:** 5 of 7 (parallel track — depends only on Phase 0)
**Branch:** `phase-5-detector` (cut from `main`, merged by PR after Gate 5)
**Goal:** Build KIG's deterministic, explainable anomaly detector (privilege escalation, lateral movement, clock-skew & reordering handling) and its seeded synthetic benchmark, with CLI commands `kig detect` and `kig bench detect`.
**Spec:**
- `docs/features.md` v0.4: **P1-09** (Goal 6), **P1-10** (Goal 7), **P1-11** (Goal 8), **P1-18** (Goal 6 metrics), **D-09**
- `docs/architecture.md` v1.0: **§15** (Detector pipeline, stages, benchmark) and **§17.1** (CLI commands)
- `docs/implementation-plan.md`: **Phase 5** (lines 742–754)
- Ground-truth practice fixture: `$TOOLKIT_DIR/practice/{events.csv, approvals.json, labels.csv, examples.md, README.md}` (read from `$TOOLKIT_DIR/practice` at test time — **never copied into the repo**)

If this plan and `docs/features.md` or `docs/architecture.md` disagree, the spec wins; fix this plan.

---

## 1. Scope, Constraints, and Non-Negotiable Rules

1. **Zero npm dependencies, zero AI/ML.** Node.js 24.11.1 built-ins only (`node:fs`, `node:path`, `node:os`, `node:util`, `node:test`, `node:assert`). CommonJS (`.cjs`) only.
2. **Crypto boundary preserved.** Phase 5 must **never** `require('node:crypto')` (verified by `tests/unit/crypto-boundary.test.cjs`). The synthetic generator uses a pure-JS seeded PRNG (`mulberry32`), explicitly marked simulation-only.
3. **Strict label isolation.** The detector (`src/detect/index.cjs` and everything it imports) must **never** read `labels.csv` or depend on label fields. Only `src/detect/bench.cjs` (the scorer) reads labels. Enforced by an automated static-analysis test in Task 5.5.
4. **Preserve raw evidence.** `event_time_utc`, `received_time_utc`, `source_clock_offset_ms`, and `ingestIdx` are never overwritten. Sorting or correcting times creates derived fields; original source strings remain intact in the timeline report.
5. **No over-claiming.**
   - Denied lateral-movement attempts are classified as `candidate_lateral_movement`, **never** `compromise` or `successful_access`.
   - Role changes alone never assert malicious intent — alerts explain the exact missing or mismatched approval condition.
   - Evasive attacks missed by threshold rules (e.g., low-and-slow) are **reported honestly** in benchmark output, never hidden or tuned away on held-out seeds.
   - Time-to-alert (TTA) includes the watermark wait (up to 5 s) and is reported honestly on collector monotonic time.
6. **Read-only container compatibility.** All tests run cleanly inside `npm run judge -- npm test` (`--read-only` root, `--network none`, `/toolkit` read-only, `/tmp` writable). Any test output goes under `os.tmpdir()`.
7. **Phase 2 CLI forward-compatibility.** Because Phase 5 runs in parallel with Phase 2 (`src/cli/main.cjs`), every CLI command module in Phase 5 exports `{ name, describe, options, run(values) → Promise<number> }` (matching Phase 2 Task 2.1) AND is wired cleanly into `kig.cjs` with minimal entries in the `COMMANDS` map.

---

## 2. Data Contracts and Defaults

### 2.1 Input Schema: `events.csv` (from `$TOOLKIT_DIR/practice/events.csv`)

Exact 14 CSV columns (also accepted as JSONL objects with the same keys):

```text
event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id
```

Normalized internal `Event` object (produced by `ingest.cjs`, enriched by `clock.cjs` and `reorder.cjs`):

```js
/**
 * @typedef {object} DetectEvent
 * @property {string} id                      // event_id
 * @property {string} rawEventTimeUtc         // original event_time_utc (never mutated)
 * @property {string} rawReceivedTimeUtc      // original received_time_utc (never mutated)
 * @property {number} eventTimeMs             // parsed UTC ms from event_time_utc
 * @property {number} receivedMs              // parsed UTC ms from received_time_utc
 * @property {number} offsetMs                // integer source_clock_offset_ms
 * @property {number|null} correctedMs        // eventTimeMs - offsetMs (null if invalid; set by clock.cjs)
 * @property {number|null} deliveryDelayMs    // receivedMs - correctedMs
 * @property {boolean} clockUnsupported       // true if |offsetMs| > maxOffsetMs (kept, never clamped)
 * @property {number} uncertaintyMs           // configured ±uncertainty half-width (default 250)
 * @property {number} ingestIdx               // 0-based arrival index (never mutated)
 * @property {boolean} late                   // true if arrived below watermark (set by reorder.cjs)
 * @property {boolean} orderUncertain         // true if uncertainty intervals overlap another event in same actor+session
 * @property {string} actor
 * @property {string} src                     // source_service
 * @property {string} dst                     // target_service
 * @property {string} action                  // sign_in | sign_out | read | approve_role_change | role_change | revoke_role | list_roles | ...
 * @property {string} roleBefore              // role_before
 * @property {string} roleAfter               // role_after
 * @property {string} outcome                 // allow | deny | success | ...
 * @property {string|null} approvalId         // approval_id or null when empty
 * @property {string} session                 // session_id
 * @property {string} correlation             // correlation_id
 */
```

### 2.2 Input Schema: `approvals.json` (from `$TOOLKIT_DIR/practice/approvals.json`)

Top-level `{ synthetic?: boolean, changes: Approval[] }` with **two distinct approval shapes** (features P1-09 [v0.3]):

1. **`grant_role`**:
   ```json
   {
     "approval_id": "change-100",
     "approved_by": "user-admin",
     "subject": "user-alex",
     "operation": "grant_role",
     "role": "report-reader",
     "scope": ["reports", "reports-node-a", "reports-node-b"],
     "valid_from_utc": "2026-01-15T09:01:00Z",
     "valid_until_utc": "2026-01-15T09:07:00Z"
   }
   ```
   Validity rule: `valid_from_ms <= correctedMs && correctedMs < valid_until_ms` (**`valid_until_utc` is strictly exclusive**).

2. **`revoke_role`**:
   ```json
   {
     "approval_id": "change-101",
     "approved_by": "user-admin",
     "subject": "user-alex",
     "operation": "revoke_role",
     "role": "report-reader",
     "effective_at_utc": "2026-01-15T09:07:00Z"
   }
   ```
   Validity rule: `correctedMs >= effective_at_ms`. **Important:** in `events.csv` (`evt-016`), `actor` is the operator (`user-admin`), while the affected subject (`user-alex`) and revoked role (`report-reader`) come from `approvals.json`!

### 2.3 Output Schema: `Alert` (architecture §15.2)

```js
/**
 * @typedef {object} Alert
 * @property {string} alert_id                // deterministic per run: "alert-001", "alert-002", ...
 * @property {'PRIV-1'|'PRIV-2'|'LM-1'|'LM-2'|'LM-3'} rule_id
 * @property {'low'|'medium'|'high'} severity
 * @property {'unexpected_privilege_change'|'access_after_unexpected_privilege'|'candidate_lateral_movement'|'novel_sensitive_access'|'unseen_deny_burst'} classification
 * @property {string} identity                // actor
 * @property {string[]} services              // ordered distinct services touched
 * @property {string[]} path                  // ordered directed edges e.g. ["reports->billing","billing->archive","archive->identity"]
 * @property {string[]} event_ids             // supporting event IDs in event-time order
 * @property {Array<{event_id: string, outcome: string, src: string, dst: string}>} outcomes
 * @property {string} reason                  // human-readable explanation naming rule and missing/mismatched conditions
 * @property {boolean} order_uncertain        // true if any supporting event has orderUncertain === true
 * @property {{ start_utc: string, end_utc: string, window_ms: number }} window
 * @property {number} last_evidence_received_ms
 * @property {number} emitted_at_mono_ns      // process.hrtime.bigint() delta / timestamp for TTA
 */
```

### 2.4 Default Configuration (`DEFAULT_CONFIG`)

All thresholds are configurable and included verbatim in benchmark reports:

| Parameter | Default | Spec reference |
|---|---|---|
| `maxOffsetMs` | `5000` (±5 s) | P1-11, architecture §15.2 |
| `latenessMs` | `5000` (5 s reorder watermark) | P1-11, architecture §15.2 |
| `uncertaintyMs` | `250` (±250 ms overlap margin) | architecture §15.2 |
| `lmWindowMs` | `60000` (60 s; practice set invariant across 30–120 s) | P1-10, architecture §15.2 |
| `lm1EdgeThreshold` | `3` (≥ 3 unseen directed edges) | P1-10, D-09 |
| `lm3DenyThreshold` | `3` (≥ 3 denies across ≥ 2 unseen targets; N=2 false-alerts on `evt-017/018`) | P1-10 [v0.3] |
| `lm3TargetThreshold` | `2` (distinct unseen target services) | P1-10 |
| `sensitiveServices` | `['identity', 'billing', 'archive']` | P1-10, architecture §15.2 |
| `revocationContextWindowMs` | `300000` (5 min post-revocation expected-enforcement window) | P1-10 [v0.3] |
| `roleRanks` | `Map { viewer: 1, 'service-reader': 2, 'report-reader': 3, operator: 4, admin: 5 }` | P1-09 |
| `documentedEdges` | `[['portal','identity'], ['admin-console','identity'], ['portal','catalog'], ['portal','reports'], ['portal','reports-node-a'], ['portal','reports-node-b'], ['reports','catalog']]` | P1-10 [v0.3], `practice/README.md` |

### 2.5 Worked Ground-Truth Trace on the 22 Practice Events

Every rule is verified against all 22 rows of `$TOOLKIT_DIR/practice/events.csv`:

| Events | What happens in the pipeline | Expected result |
|---|---|---|
| `evt-001`, `evt-002` | `user-alex` sign-in (`portal→identity`) and catalog read (`portal→catalog`); both in baseline | Routine, **0 alerts** |
| `evt-003` | `user-admin` `approve_role_change` (`change-100`); recorded in approval cross-reference | Approved admin, **0 alerts** |
| `evt-004` | `user-alex` `role_change` `viewer→report-reader` with `change-100`; matches subject=`user-alex`, role=`report-reader`, `09:01:05Z ∈ [09:01:00Z, 09:07:00Z)`; actor ≠ approver allowed | Approved change, **0 alerts**; Alex expected role → `report-reader` (scope `reports`, `reports-node-a`, `reports-node-b`) |
| `evt-005` | `user-alex` reads `reports` during valid window (`portal→reports` in baseline) | Routine, **0 alerts** |
| `evt-006` | `svc-report-worker` `reports→catalog` (in baseline) | Routine, **0 alerts** |
| `evt-007` | `user-blair` sign-in (`portal→identity`, in baseline) | Routine, **0 alerts** |
| `evt-008` | `user-blair` `role_change` `viewer→operator`, `approval_id=null` | **Alert #1 (`PRIV-1`, high)**: unapproved role increase `viewer→operator` |
| `evt-009` | `user-blair` allowed read `portal→reports` in `sess-blair`/`flow-004` following `evt-008`; edge is in global baseline so **no LM alert** | **Linked via `PRIV-2`** to `evt-008` (both `evt-008` and `evt-009` cited; **0 LM alerts**) |
| `evt-010`..`evt-012` | `svc-report-worker` denied on 3 unseen edges (`reports→billing`, `billing→archive`, `archive→identity`) in 3 s (`sess-worker`/`flow-005`) | **Alert #2 (`LM-1`, medium, `candidate_lateral_movement`)**: single grouped alert listing all 3 events, path `reports→billing→archive→identity`, all outcomes `deny` (LM-3 deduplicated so no duplicate alert for the same sequence) |
| `evt-014`, `evt-013` | `evt-014` (`09:05:02Z`) arrives before `evt-013` (`09:05:01Z`, received `09:05:04.2Z`); 1 s apart, inside 5 s watermark → released in event order `evt-013` then `evt-014`, `ingestIdx` preserved | Routine delayed delivery, **0 alerts** |
| `evt-015` | Raw `09:06:03.000Z`, offset `+2000 ms` → corrected `09:06:01.000Z`, receipt `09:06:01.200Z` → `deliveryDelayMs = 200` | Routine clock offset, **0 alerts** |
| `evt-016` | `user-admin` `revoke_role` with `change-101` at `09:07:00Z >= effective_at_utc`; updates `user-alex` expected role back to `viewer` and records revocation context for `['reports','reports-node-a','reports-node-b']` | Approved revocation, **0 alerts** |
| `evt-017`, `evt-018` | `user-alex` denied on `reports-node-a` / `reports-node-b` at `09:07:02Z`/`09:07:03Z` with `change-101` | Classified `expected_enforcement` (revocation context), **0 LM alerts** |
| `evt-019`, `evt-020` | `user-casey` sign-in, then 1 isolated `deny` on unseen edge `portal→billing` | Isolated denial, **0 alerts** |
| `evt-021`, `evt-022` | `user-alex` reads `catalog` (`viewer`), `user-admin` signs out | Routine, **0 alerts** |

**Exact practice-set alert count: 2 incidents** (`PRIV-1`/`PRIV-2` covering `evt-008` + `evt-009`, and `LM-1` covering `evt-010` + `evt-011` + `evt-012`), invariant across `lmWindowMs ∈ [30000, 120000]`.

---

## 3. Review Focus (High-Risk Edge Cases)

Every one of these must be pinned by a dedicated unit test:

1. **`actor ≠ approved_by` on `role_change` (`evt-004`).** Never require `event.actor === approval.approved_by`; match `event.actor === approval.subject` and cross-reference `approval.approved_by` against prior `approve_role_change` events when present.
2. **Operator-acted `revoke_role` (`evt-016`).** The event's `actor` is `user-admin`, NOT `user-alex`. Look up the affected subject (`user-alex`) and revoked role (`report-reader`) from `approvals.json`, and link that role back to the prior `grant_role`'s `scope` so `evt-017`/`evt-018` are recognized as expected enforcement.
3. **Exclusive `valid_until_utc`.** A `role_change` or scoped access at `correctedMs === valid_until_ms` (e.g., `09:07:00.000Z` for `change-100`) is **expired**, NOT approved.
4. **No cold-start baseline trap.** Never build the lateral-movement baseline from the evaluation stream itself (simulated in features R12: per-actor cold start falsely flags `evt-007..009`). Always seed from `Baseline.fromDocumented(edges)` + optional separate warm-up corpus.
5. **No plain-object indexing by untrusted strings.** Actor names, session IDs, service names, and approval IDs live in `Map` / `Set`, never plain objects (consistent with P0-05 / `__proto__` hygiene).
6. **Honest TTA & zero label leakage.** TTA measures collector/monotonic time from receipt of the final evidence event to alert emission (including reorder-buffer wait). Static test proves no detector module touches `labels`.

---

## 4. File Map

```text
src/detect/
├── config.cjs           # DEFAULT_CONFIG, role ranks, documented baseline edges        (5.1)
├── ingest.cjs           # parseCsv (RFC 4180 subset), parseJsonl, validate rows        (5.1)
├── clock.cjs            # correct(), clock_unsupported flag, deliveryDelayMs           (5.1)
├── reorder.cjs          # ReorderBuffer (watermark, late flag, order_uncertain)        (5.1)
├── approvals.cjs        # loadApprovals(), matchGrant(), matchRevoke()                 (5.2)
├── roles.cjs            # RoleTracker (expected role + revocation context per actor)   (5.2)
├── rules-priv.cjs       # PRIV-1 (unapproved increase), PRIV-2 (post-elevation link)   (5.2)
├── baseline.cjs         # Baseline (documented edges + warm-up corpus, summary)        (5.3)
├── rules-lm.cjs         # LM-1, LM-2, LM-3, revocation-context filter, dedup           (5.3)
├── index.cjs            # detect(events, approvals, baseline, cfg) → {alerts,timeline} (5.4)
├── generator.cjs        # mulberry32 PRNG + seeded synthetic scenario generator        (5.5)
└── bench.cjs            # score(alerts, labels) + runBenchmark({tuning, holdout})      (5.5)

src/cli/
├── detect.cjs           # `kig detect --events ... --approvals ... [--baseline ...] [--json]` (5.4)
└── bench-detect.cjs     # `kig bench detect --seeds ... --holdout ... [--out ...] [--json]`   (5.5)

kig.cjs                  # register `detect` and `bench` commands                       (5.4, 5.5)

tests/unit/detect/
├── ingest-clock-reorder.test.cjs   (5.1)
├── approvals-priv.test.cjs         (5.2)
├── baseline-lm.test.cjs            (5.3)
├── pipeline-practice.test.cjs      (5.4)
├── generator-bench.test.cjs        (5.5)
└── no-label-leak.test.cjs          (5.5)

evidence/
└── phase5.md            # Gate 5 report: practice regression + held-out benchmark      (5.6)
```

---

## 5. Gate 5 Checklist

All commands must pass locally **and** inside `npm run judge -- ...` (ARM64, read-only root, offline):

- [ ] `npm run judge -- node --disable-warning=ExperimentalWarning --test "tests/unit/detect/*.test.cjs"` → all PASS, exit 0
- [ ] `npm run judge -- node --disable-warning=ExperimentalWarning --test tests/unit/crypto-boundary.test.cjs` → PASS (Phase 5 introduces zero `node:crypto` imports)
- [ ] Practice-set regression passes against `/toolkit/practice/events.csv` and `/toolkit/practice/approvals.json`:
  - `evt-003`..`evt-005` approved; `evt-016` approved (`change-101`)
  - `evt-008` triggers `PRIV-1` linking `evt-009` (`PRIV-2`)
  - `evt-010`..`evt-012` grouped as **one** `LM-1` candidate lateral-movement alert (`reports→billing→archive→identity`, all `deny`)
  - `evt-007`..`evt-009` produce **0** lateral-movement alerts
  - `evt-017`/`evt-018` classified `expected_enforcement`, **0** lateral-movement alerts
  - `evt-020` produces **0** alerts
  - `evt-013`/`evt-014` ordered by event time with raw receipt order preserved; `evt-015` corrected to `09:06:01.000Z` (delay `200 ms`)
  - Same alert set for `lmWindowMs` = `30000`, `60000`, `120000`
- [ ] `kig bench detect --seeds 101,102,103 --holdout 201,202,203,204,205` prints precision, recall, F1, median TTA (including watermark wait), false alerts per 1,000 benign events, and missed-evasion breakdown for the **held-out** seeds, and saves `evidence/detect-<ts>.json` (or prints cleanly on read-only FS)
- [ ] Label-isolation static test passes (no detector module reads or imports `labels`)
- [ ] `evidence/phase5.md` written and reviewed; PR `phase-5-detector` → `main` green in ARM CI

---

## 6. Step-by-Step Tasks

### Task 5.1: Config, Ingest, Clock Correction, and Reorder Buffer

**Spec:** P1-11 (Goal 8); architecture §15.2.
**Files:**
- Create: `src/detect/config.cjs`, `src/detect/ingest.cjs`, `src/detect/clock.cjs`, `src/detect/reorder.cjs`
- Test: `tests/unit/detect/ingest-clock-reorder.test.cjs`

**Interfaces:**
- `config.cjs`: exports `DEFAULT_CONFIG`, `DOCUMENTED_PRACTICE_EDGES`, `DEFAULT_ROLE_RANKS`, `mergeConfig(overrides) → config`.
- `ingest.cjs`:
  - `parseCsv(text) → { events: DetectEvent[], rejects: Array<{ line: number, reason: string, raw: string }> }`
    - RFC 4180 subset: handles CRLF and LF, quoted fields containing commas and escaped `""`, empty trailing lines.
    - Validates required header columns (all 14 names from §2.1); missing header column throws `Error`.
    - Validates per row: exact column count, non-empty `event_id`/`actor`/`source_service`/`target_service`/`action`/`outcome`, ISO-8601 UTC parseable `event_time_utc` and `received_time_utc`, finite integer `source_clock_offset_ms`. Malformed rows go into `rejects[]` (never silently coerced or guessed).
    - Preserves `rawEventTimeUtc`, `rawReceivedTimeUtc`, `offsetMs`, and 0-based `ingestIdx`.
  - `parseJsonl(text) → { events, rejects }` (same normalized `DetectEvent` shape and row validation).
  - `loadEventsFile(filePath) → { events, rejects }` (dispatches by `.jsonl`/`.ndjson` vs `.csv`).
- `clock.cjs`:
  - `correct(ev, { maxOffsetMs = 5000, uncertaintyMs = 250 } = {}) → DetectEvent` (returns a new object; never mutates raw strings):
    - `correctedMs = ev.eventTimeMs - ev.offsetMs`
    - `deliveryDelayMs = ev.receivedMs - correctedMs`
    - `clockUnsupported = Math.abs(ev.offsetMs) > maxOffsetMs` (if true, keep `correctedMs` computed for diagnostics, flag `clockUnsupported: true`, and mark `orderUncertain: true` — **never clamp the offset**).
- `reorder.cjs`:
  - `class ReorderBuffer`:
    - `constructor({ latenessMs = 5000, uncertaintyMs = 250 } = {})`
    - `push(ev) → DetectEvent[]`:
      - Tracks `watermarkMs = maxCorrectedMs - latenessMs` across events with `!ev.clockUnsupported`.
      - Events with `ev.clockUnsupported === true` bypass event-time ordering and are ordered by `receivedMs` / `ingestIdx` with `orderUncertain: true`.
      - If `!ev.clockUnsupported && maxCorrectedMs !== -Infinity && ev.correctedMs < watermarkMs`: mark `late: true` and emit immediately (or keep flagged in released set) so late arrivals are never silently dropped.
      - Releases all buffered events with `correctedMs <= watermarkMs` sorted by `(correctedMs, ingestIdx)`.
      - Before returning released events, checks every pair sharing `(actor, session)` against recently released events in that `(actor, session)` (within `2 * uncertaintyMs`): if `Math.abs(a.correctedMs - b.correctedMs) <= a.uncertaintyMs + b.uncertaintyMs`, sets `orderUncertain = true` on both.
    - `flush() → DetectEvent[]`: releases remaining buffered events in `(correctedMs, ingestIdx)` order with the same overlap check.

- [ ] **Step 1: Write failing tests** in `tests/unit/detect/ingest-clock-reorder.test.cjs`:
  - `parseCsv parses quoted fields, embedded commas, escaped quotes, and CRLF`
  - `parseCsv quarantines malformed rows into rejects without throwing` (bad timestamp, non-integer offset, wrong column count)
  - `parseJsonl produces identical normalized events to parseCsv`
  - `clock evt-015`: `event_time_utc='2026-01-15T09:06:03.000Z'`, `received_time_utc='2026-01-15T09:06:01.200Z'`, `offsetMs=2000` → `correctedMs === Date.parse('2026-01-15T09:06:01.000Z')`, `deliveryDelayMs === 200`, `clockUnsupported === false`, raw strings unchanged
  - `clock offset +6000 and -5001 flagged clockUnsupported and NOT clamped` (`offsetMs` still `6000`, `orderUncertain === true`)
  - `reorder evt-014 then evt-013`: released in event-time order `[evt-013, evt-014]` while `evt-014.ingestIdx < evt-013.ingestIdx`
  - `reorder late event past 5 s watermark marked late=true and still emitted`
  - `reorder overlapping uncertainty intervals`: two events for same actor+session `300 ms` apart with `uncertaintyMs=250` → both have `orderUncertain === true`; two events `600 ms` apart → both `false`
- [ ] **Step 2:** Run `node --test tests/unit/detect/ingest-clock-reorder.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement `config.cjs`, `ingest.cjs`, `clock.cjs`, `reorder.cjs`.
- [ ] **Step 4:** Run `node --test tests/unit/detect/ingest-clock-reorder.test.cjs`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(detect): ingest, clock correction and reorder buffer`.

---

### Task 5.2: Approvals, Role Tracking, and Privilege-Change Rules (`PRIV-1`, `PRIV-2`)

**Spec:** P1-09 (Goal 6); architecture §15.2.
**Files:**
- Create: `src/detect/approvals.cjs`, `src/detect/roles.cjs`, `src/detect/rules-priv.cjs`
- Test: `tests/unit/detect/approvals-priv.test.cjs`

**Interfaces:**
- `approvals.cjs`:
  - `loadApprovals(obj) → ApprovalStore` (uses a `Map<string, Approval>` keyed by `approval_id`; validates both `grant_role` and `revoke_role` shapes; parses UTC timestamps to ms; also indexes prior grants by `subject + '\0' + role` so revocations know which service scope was revoked).
  - `loadApprovalsFile(filePath) → ApprovalStore`
  - `matchGrant(store, ev, approvedEventsById) → { matched: true, approval } | { matched: false, reason: string }`:
    - Checks in order: `approvalId` present → exists in store → `operation === 'grant_role'` → `subject === ev.actor` → `role === ev.roleAfter` → `validFromMs <= ev.correctedMs && ev.correctedMs < validUntilMs` (**exclusive `valid_until_utc`**).
    - If an `approve_role_change` event with the same `approvalId` was seen, verifies its actor matches `approval.approvedBy` (mismatch → `approver_mismatch`). Does **not** require `ev.actor === approval.approvedBy`.
  - `matchRevoke(store, ev) → { matched: true, approval, revokedScope: string[] } | { matched: false, reason: string }`:
    - Checks: `approvalId` present → exists in store → `operation === 'revoke_role'` → `ev.correctedMs >= approval.effectiveAtMs` → if `ev.action === 'revoke_role'`, checks `ev.actor === approval.approvedBy`; if `ev.action === 'role_change'` decreasing role, checks `ev.actor === approval.subject && ev.roleBefore === approval.role`.
    - Returns `revokedScope` from the matching `grant_role` approval for `(approval.subject, approval.role)` (or `[]` if none).
- `roles.cjs`:
  - `class RoleTracker`:
    - `constructor(approvals, cfg)`
    - `rankOf(role) → number` (uses `cfg.roleRanks` `Map`; unknown roles default to `0` and are flagged as unknown).
    - `isRoleIncrease(before, after) → boolean` (`rankOf(after) > rankOf(before)`).
    - `process(ev) → { kind: 'none'|'approved_admin'|'approved_grant'|'approved_revoke'|'unapproved_increase'|'unapproved_decrease'|'follow_up_access', approval?, reason?, revocationRecord?, linkedEscalation? }`:
      - Tracks `approvedEventsById` (`Map`) on `approve_role_change`.
      - Tracks `expectedRoleByActor` (`Map<string, string>`).
      - Tracks `recentRevocationsByActor` (`Map<string, Array<{ atMs, role, scope: Set<string>, approvalId }>>`).
      - Tracks `activeEscalationsBySession` (`Map<string, { priv1Event, alertId, escalatedRole, atMs }>` keyed by `actor + '\0' + session`).
      - Exposes `isExpectedEnforcementDenial(ev) → { matched: boolean, revocation? }`: true when `ev.outcome === 'deny'` AND actor has a revocation within `revocationContextWindowMs` (`ev.correctedMs >= rev.atMs && ev.correctedMs - rev.atMs <= cfg.revocationContextWindowMs`) AND (`rev.scope.has(ev.dst)` OR (`ev.approvalId && ev.approvalId === rev.approvalId`)).
- `rules-priv.cjs`:
  - `evaluatePrivilege(events, approvals, cfg) → { alerts: Alert[], tracker: RoleTracker, eventMeta: Map<string, object> }`:
    - **`PRIV-1`**: fires on `unapproved_increase` (`severity: 'high'`, `classification: 'unexpected_privilege_change'`). Reason explicitly states missing/mismatched condition (never infers intent).
    - **`PRIV-2`**: when an allowed access occurs in the same `(actor, session)` (or `correlation_id`) after a `PRIV-1`, links it to that escalation: updates/associates `evt-009` with `evt-008` (so the operator sees both `evt-008` and `evt-009` in the escalation alert's `event_ids`, `services`, `outcomes`, and `reason`, plus records the follow-up rule tag `PRIV-2`).
    - Role decreases (`unapproved_decrease`): never high severity; at most an informational/low notice (`unrecorded_role_decrease`) — never classified as privilege escalation.

- [ ] **Step 1: Write failing tests** in `tests/unit/detect/approvals-priv.test.cjs`:
  - `evt-003..005 approved`: `change-100` matches `evt-004` (`actor=user-alex`, `approved_by=user-admin`), `evt-005` allowed, 0 alerts
  - `valid_until_utc is exclusive`: `role_change` at exact `2026-01-15T09:07:00.000Z` fails `change-100` with reason `outside_validity_window` and triggers `PRIV-1`
  - `evt-008 unapproved escalation links evt-009`: 1 high alert (`PRIV-1`) citing both `evt-008` and `evt-009`, naming missing approval and `viewer -> operator`
  - `evt-016 revoke_role matches change-101`: `actor=user-admin` updates `user-alex` expected role back to `viewer`, records revocation context covering `reports`, `reports-node-a`, `reports-node-b`, 0 alerts
  - `isExpectedEnforcementDenial true for evt-017 and evt-018, false for unrelated target billing`
  - `role decrease without approval never raises high alert`
  - `subject mismatch and role mismatch rejected with explicit reason`
  - `prototype-key actor/approval_id (__proto__, constructor) handled safely via Map`
- [ ] **Step 2:** Run `node --test tests/unit/detect/approvals-priv.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement `approvals.cjs`, `roles.cjs`, `rules-priv.cjs`.
- [ ] **Step 4:** Run `node --test tests/unit/detect/approvals-priv.test.cjs`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(detect): approvals, role tracking and privilege rules`.

---

### Task 5.3: Baseline and Lateral-Movement Rules (`LM-1`, `LM-2`, `LM-3`)

**Spec:** P1-10 (Goal 7), D-09; architecture §15.2.
**Files:**
- Create: `src/detect/baseline.cjs`, `src/detect/rules-lm.cjs`
- Test: `tests/unit/detect/baseline-lm.test.cjs`

**Interfaces:**
- `baseline.cjs`:
  - `edgeKey(src, dst) → string` (safe delimiter encoding via `JSON.stringify([src, dst])` so service names with `->` or `|` cannot collide).
  - `class Baseline`:
    - `static fromDocumented(edges = DOCUMENTED_PRACTICE_EDGES, meta = { source: 'documented' }) → Baseline`
    - `static fromFile(filePath) → Baseline` (loads `{ edges: [[src, dst], ...], source?, seed? }` JSON)
    - `addEdge(src, dst)`
    - `addCorpus(events, { seed } = {})` (adds edges from a **benign warm-up corpus**, keeping `source` and `seed` metadata)
    - `has(src, dst) → boolean`
    - `summary() → { source: string, edgeCount: number, seed: number|null }`
- `rules-lm.cjs`:
  - `evaluateLateralMovement(events, baseline, roleTracker, cfg) → { alerts: Alert[], eventMeta: Map<string, object> }`:
    - Evaluates events in event-time order.
    - Skips events where `baseline.has(ev.src, ev.dst)` is true (known routine edges).
    - Checks `roleTracker.isExpectedEnforcementDenial(ev)`: if matched, tags event in `eventMeta` as `{ classification: 'expected_enforcement', revocation }` and **excludes it from `LM-1` and `LM-3`**.
    - Maintains per-`(actor, session, correlation)` (and per-`(actor, session)` for `LM-3`) sliding windows of unseen events within `cfg.lmWindowMs`:
      - **`LM-1` (sequence):** when a sliding window contains `>= cfg.lm1EdgeThreshold` (default `3`) distinct unseen directed edges for the same `(actor, session, correlation)` (falling back to `(actor, session)` when `correlation` is empty):
        - Groups the entire contiguous unseen sequence in that window into **one** alert (`classification: 'candidate_lateral_movement'`, `severity: anyAllowed ? 'high' : 'medium'`).
        - Ordered `path`: e.g. `['reports->billing', 'billing->archive', 'archive->identity']`; `services`: `['reports', 'billing', 'archive', 'identity']`.
        - Explicitly states whether each request was `allow` or `deny` in `outcomes` and `reason` (never calls denied probes "compromise").
      - **`LM-2` (novel allowed edge to sensitive service):** when `ev.outcome === 'allow'` (or `'success'`) over an unseen edge where `sensitiveSet.has(ev.dst)` → `severity: 'medium'`, `classification: 'novel_sensitive_access'` (unless already covered by an `LM-1` alert for the same event).
      - **`LM-3` (deny burst):** when a sliding window for `(actor, session)` contains `>= cfg.lm3DenyThreshold` (default `3`) denied unseen requests across `>= cfg.lm3TargetThreshold` (default `2`) distinct unseen target services — emits `severity: 'low'` (`classification: 'unseen_deny_burst'`) **only if those events were not already grouped into an `LM-1` alert** (prevents duplicate alerts on `evt-010..012`, while catching 3 denies across 2 repeated targets where distinct edges < 3!).
    - Single isolated denial (`evt-020`) triggers none of `LM-1`, `LM-2`, `LM-3`.

- [ ] **Step 1: Write failing tests** in `tests/unit/detect/baseline-lm.test.cjs`:
  - `evt-010..012 grouped as ONE LM-1 candidate lateral-movement alert`: path `reports->billing->archive->identity`, all outcomes `deny`, reason does NOT claim compromise
  - `evt-007..009 produce ZERO LM alerts` (all edges in documented baseline)
  - `evt-017 and evt-018 classified expected_enforcement, ZERO LM alerts` (even if `portal->reports-node-a/b` were absent from baseline, revocation context still excludes them!)
  - `evt-020 single isolated denial produces ZERO alerts`
  - `LM-2 fires on single allowed unseen edge to billing/archive/identity` (catches 1-edge and 2-edge successful attacks that LM-1 misses)
  - `LM-3 fires on 3 denials across 2 distinct unseen targets` (e.g. `portal->billing`, `portal->archive`, `portal->billing` — only 2 distinct edges so LM-1 doesn't fire, LM-3 catches it)
  - `LM-3 does NOT fire on 2 denials` (proves default N=3 avoids the N=2 trap)
  - `window invariance`: `evt-010..012` produces identical alert for `lmWindowMs` = `30000`, `60000`, `120000`
  - `order_uncertain propagates from supporting events to alert`
- [ ] **Step 2:** Run `node --test tests/unit/detect/baseline-lm.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement `baseline.cjs`, `rules-lm.cjs`.
- [ ] **Step 4:** Run `node --test tests/unit/detect/baseline-lm.test.cjs`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(detect): service-edge baseline and lateral-movement rules`.

---

### Task 5.4: Full Detector Pipeline and `kig detect` CLI

**Spec:** P1-09, P1-10, P1-11; architecture §15.1–§15.2, §17.1.
**Files:**
- Create: `src/detect/index.cjs`, `src/cli/detect.cjs`
- Modify: `kig.cjs` (register `detect` command)
- Test: `tests/unit/detect/pipeline-practice.test.cjs`

**Interfaces:**
- `src/detect/index.cjs`:
  - `detect(rawEvents, approvals, baseline, cfgOverrides = {}) → { alerts: Alert[], timeline: TimelineEntry[], stats: object, config: object, baseline: object }`:
    1. Merges `DEFAULT_CONFIG` with `cfgOverrides`.
    2. Defaults `baseline` to `Baseline.fromDocumented()` if omitted.
    3. Runs `clock.correct` on every event, feeds into `ReorderBuffer`, collects released events + `flush()`.
    4. Records collector receipt/emission timestamps (`process.hrtime.bigint()`) and simulates honest watermark release delay so TTA is measurable both in live streams and offline replay.
    5. Runs `evaluatePrivilege` → produces `PRIV-1`/`PRIV-2` alerts + `RoleTracker`.
    6. Runs `evaluateLateralMovement` → produces `LM-1`/`LM-2`/`LM-3` alerts + `expected_enforcement` classifications.
    7. Assigns deterministic `alert_id`s (`alert-001`, …) ordered by earliest supporting event time.
    8. Builds `timeline`: every event in event-time order with raw timestamps, corrected timestamp, `deliveryDelayMs`, `ingestIdx`, `late`, `clockUnsupported`, `orderUncertain`, and classification (`routine`, `approved_change`, `expected_enforcement`, `alert:<alert_id>`).
- `src/cli/detect.cjs`:
  - Exports `{ name: 'detect', describe, options, run(values) → Promise<number>, main(argv) → Promise<number> }`.
  - Options (via `util.parseArgs`): `--events <path>` (required), `--approvals <path>` (optional), `--baseline <path>` (optional), `--window-ms <n>`, `--max-offset-ms <n>`, `--json`.
  - Human output escapes terminal control characters (no terminal injection from untrusted IDs).
  - Exits `0` on success, `2` on invalid CLI args / unreadable file.

- [ ] **Step 1: Write failing tests** in `tests/unit/detect/pipeline-practice.test.cjs`:
  - Resolves toolkit practice dir via `process.env.TOOLKIT_DIR || (fs.existsSync('/toolkit/practice') ? '/toolkit/practice' : path.resolve(__dirname, '../../../../Track-4-Toolkit/practice'))` (fails loudly in CI/judge if missing; never copies practice files into repo).
  - `full 22-event practice regression`:
    - `rejects.length === 0`, `timeline.length === 22`
    - Exactly 2 alerts:
      1. `PRIV-1` (`high`, `identity: 'user-blair'`, `event_ids: ['evt-008', 'evt-009']`)
      2. `LM-1` (`medium`, `identity: 'svc-report-worker'`, `event_ids: ['evt-010', 'evt-011', 'evt-012']`, `path: ['reports->billing','billing->archive','archive->identity']`, all outcomes `deny`)
    - `evt-013` appears before `evt-014` in `timeline`, with `evt-014.ingestIdx < evt-013.ingestIdx`
    - `evt-015` has `correctedMs === Date.parse('2026-01-15T09:06:01.000Z')` and `deliveryDelayMs === 200`
    - `evt-017`, `evt-018` classified `expected_enforcement`
    - `evt-020` has no alert
  - `window invariance 30 s / 60 s / 120 s` produces identical alert IDs and event sets
  - `CLI node kig.cjs detect --events ... --approvals ... --json` exits 0 and outputs parseable JSON matching the API result
  - `CLI control-character escaping`: event with `\x1b[31mFAKE` actor does not write raw ESC byte to stdout
- [ ] **Step 2:** Run `node --test tests/unit/detect/pipeline-practice.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement `src/detect/index.cjs`, `src/cli/detect.cjs`, wire `detect` in `kig.cjs`.
- [ ] **Step 4:** Run `node --test tests/unit/detect/pipeline-practice.test.cjs`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(detect): detector pipeline and kig detect CLI`.

---

### Task 5.5: Seeded Synthetic Generator, Benchmark Scorer, and `kig bench detect`

**Spec:** P1-18 (Goal 6 metrics); architecture §15.3.
**Files:**
- Create: `src/detect/generator.cjs`, `src/detect/bench.cjs`, `src/cli/bench-detect.cjs`
- Modify: `kig.cjs` (register `bench` command, routing `bench detect` cleanly for Phase 7's `bench` subcommands too)
- Test: `tests/unit/detect/generator-bench.test.cjs`, `tests/unit/detect/no-label-leak.test.cjs`

**Interfaces:**
- `src/detect/generator.cjs`:
  - `mulberry32(seed)` (pure-JS 32-bit deterministic PRNG; comment explicitly notes *simulation only, never cryptographic*).
  - `generateWarmupCorpus(seed, { count = 500 } = {}) → DetectEvent[]`: generates purely benign routine traffic over normal service edges (separate seed from all evaluation sets).
  - `generateDataset(seed, cfg = {}) → { seed, events: DetectEvent[], approvals: Approval[], incidents: LabelledIncident[], eventLabels: Map<string, string>, summary: object }`:
    - Default size per seed: ~1,200 events (~1,150+ benign events + ~18–25 labelled malicious incidents) so false alerts per 1,000 benign events is statistically meaningful (never derived from 22 events!).
    - Required scenario mix (features P1-18, architecture §15.3):
      - **Benign routine:** viewer reads, report-worker reads, normal sign-ins/sign-outs
      - **Benign approved admin:** `grant_role` + in-window reads + `revoke_role` + post-revocation expected denials
      - **Benign clock & delivery stress:** out-of-order arrivals (1–4 s delay), source clock skew within ±4.5 s, occasional out-of-range skew (±6.5 s)
      - **Hard benign cases:** approved off-hours admin, new hire's first accesses over normal baseline edges, single isolated denials (`evt-020`-style), legitimate approved role decreases
      - **Detectable attacks:**
        - Unapproved privilege escalation + follow-up read (`PRIV-1`/`PRIV-2`)
        - Expired-approval role change (`correctedMs >= valid_until_utc`)
        - 3-edge denied lateral-movement chain (`LM-1`)
        - 1-edge and 2-edge **allowed** unseen access into sensitive services (`LM-2`)
        - 3-deny burst across 2 unseen targets (`LM-3`)
      - **Evasive attacks (honestly labelled, expected to test recall limits):**
        - Low-and-slow lateral probe (3 unseen denied edges spaced 90 s apart, exceeding the 60 s window)
        - 2-edge denied probe across 2 targets (below `LM-3` N=3 threshold)
    - Shuffles receipt order realistically according to simulated delivery delays while recording ground-truth `incidents[]` (`{ incident_id, kind, event_ids, last_event_received_ms, evasive: boolean }`).
- `src/detect/bench.cjs`:
  - `score(alerts, dataset, { latenessMs = 5000 } = {}) → ScoreReport`:
    - **Incident-level matching (primary unit, per P1-18):** an alert matches a labelled incident iff their `event_ids` intersect (1-to-1 greedy match by highest overlap).
      - Computes `tp`, `fp`, `fn`, `precision`, `recall`, `f1`.
      - Computes `false_alerts_per_1000_benign = (fp / benignEventCount) * 1000`.
      - Computes `median_tta_ms` across matched TP alerts: `simulatedEmitMs - incident.last_event_received_ms`, where `simulatedEmitMs` includes the watermark wait (up to `latenessMs`) plus actual detector processing time (`emitted_at_mono_ns`). Reported honestly!
      - Breaks down misses into `missed_detectable` vs `missed_evasive` so limitations are transparent.
    - **Event-level metrics (reported separately, never mixed with incident metrics):** precision, recall, F1 over event IDs covered by alerts vs event IDs belonging to malicious incidents.
  - `runBenchmark({ tuningSeeds = [101, 102, 103], holdoutSeeds = [201, 202, 203, 204, 205], warmupSeed = 1, cfg = {} }) → BenchReport`:
    - **Enforces disjointness:** throws if `tuningSeeds` and `holdoutSeeds` overlap, or if `warmupSeed` appears in either!
    - Builds baseline from `Baseline.fromDocumented()` + `generateWarmupCorpus(warmupSeed)`.
    - Evaluates tuning seeds and held-out seeds separately; aggregates totals and medians for each split.
    - Includes full provenance: runtime version, platform/arch, seeds, baseline summary, config thresholds, dataset sizes, class distributions, and metric definitions.
- `src/cli/bench-detect.cjs`:
  - `node kig.cjs bench detect --seeds 101,102,103 --holdout 201,202,203,204,205 [--warmup-seed 1] [--out <file>] [--json]`
  - Writes JSON report to `--out` or `evidence/detect-<timestamp>.json` (silently skips file write with a clear stderr/stdout notice if running on a read-only filesystem).

- [ ] **Step 1: Write failing tests:**
  - `tests/unit/detect/generator-bench.test.cjs`:
    - `deterministic per seed`: `generateDataset(201)` twice yields byte-identical JSON
    - `different seeds produce different datasets`
    - `disjoint seed enforcement`: overlapping tuning & holdout seeds throws
    - `held-out benchmark quality gate`: on `holdoutSeeds = [201, 202, 203, 204, 205]` (≥ 5,000 benign events total):
      - `f1 >= 0.85` on all incidents (and `recall >= 0.95` on non-evasive detectable incidents)
      - `false_alerts_per_1000_benign <= 2.0`
      - `median_tta_ms` is finite, positive, and honestly reflects watermark wait (`> 0`)
      - `missed_evasive` is explicitly reported (proving evasions are not hidden)
    - `CLI node kig.cjs bench detect --seeds 101,102 --holdout 201,202 --out <tmp> --json` exits 0 and writes valid JSON
  - `tests/unit/detect/no-label-leak.test.cjs`:
    - Walks every `.cjs` file in `src/detect/` except `generator.cjs` and `bench.cjs`, plus `src/cli/detect.cjs`.
    - Asserts **none** of them reference `labels.csv`, `eventLabels`, `incidents`, `bench.cjs`, `generator.cjs`, `node:crypto`, or any external package.
- [ ] **Step 2:** Run `node --test tests/unit/detect/generator-bench.test.cjs tests/unit/detect/no-label-leak.test.cjs`. Expected: FAIL.
- [ ] **Step 3:** Implement `generator.cjs`, `bench.cjs`, `src/cli/bench-detect.cjs`, and wire `bench` in `kig.cjs`.
- [ ] **Step 4:** Run `node --test tests/unit/detect/*.test.cjs tests/unit/crypto-boundary.test.cjs`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(detect): seeded generator, benchmark scorer and kig bench detect`.

---

### Task 5.6: Phase 5 Evidence and Gate 5 Verification

**Files:**
- Create: `evidence/phase5.md` (and benchmark JSON artifact under `evidence/`)

- [ ] **Step 1:** Run the full detector suite and crypto-boundary check inside the ARM64 judge replica:
  ```powershell
  npm run judge -- node --disable-warning=ExperimentalWarning --test "tests/unit/detect/*.test.cjs" tests/unit/crypto-boundary.test.cjs
  ```
- [ ] **Step 2:** Run `kig detect` on `$TOOLKIT_DIR/practice` and `kig bench detect --seeds 101,102,103 --holdout 201,202,203,204,205` (saving output to `evidence/detect-<commit>.json`).
- [ ] **Step 3:** Write `evidence/phase5.md` recording:
  - Exact commands run, runtime version, host/arch, and seeds
  - Practice-set regression output (all 22 events, 2 alerts, window invariance 30–120 s)
  - Held-out benchmark table: precision, recall, F1 (incident-level and event-level separately), median TTA (including watermark wait), false alerts per 1,000 benign events, dataset size, and class distribution
  - Honest limitations: synthetic benchmark origin (not production traffic), evasive low-and-slow misses, ±5 s clock-offset range, watermark latency trade-off
- [ ] **Step 4:** Run full `npm test` (and confirm ARM CI green on PR `phase-5-detector` → `main`).
- [ ] **Step 5:** Commit `docs(evidence): phase 5 detector regression and benchmark evidence`.

---

## 7. Implementation Notes (where the build differs from the text above)

Recorded during implementation. Where the spec and this plan disagreed, the spec won, as §0 requires.

1. **Watermark also advances with the collector clock.** §6 Task 5.1 defines `watermark = maxCorrectedMs − latenessMs` only. With that alone, an event waits until a newer event arrives; on the practice set, `evt-008` would wait for `evt-010`, 55 s later. Architecture §15.3 says TTA includes the watermark wait "up to 5 s", so the buffer also behaves like a lateness timer: effective watermark = `max(maxCorrected, latest receipt) − lateness`. Ordering is unchanged; an arrival older than `receipt − lateness` is `late`. Each released event carries `releasedAtMs`, its simulated collector release time.
2. **Time-to-alert is per alert.** §6 Task 5.5 measures from `incident.last_event_received_ms`. For a PRIV incident that includes the follow-up reads, which arrive after the alert, so TTA would go negative. The spec says "from the receipt of the last needed event", so TTA = alert emission (simulated collector clock) − receipt of the last evidence event *that alert* needed, plus measured processing time per event. `last_event_received_ms` is still recorded on each incident.
3. **PRIV-2 is a link, not a separate alert.** As the §2.5 trace and Task 5.4 test require ("exactly 2 alerts", PRIV-1 citing `evt-008` and `evt-009`), the follow-up access is added to the PRIV-1 alert's `event_ids` and `linked`, with `related_rules: ['PRIV-2']`.
4. **Notices are not alerts.** An unapproved role decrease produces a low-severity `unrecorded_role_decrease` notice in `notices`, so it can never be counted as an alert or a false alert.
5. **Unknown roles.** `rankOf` returns 0 for an unranked role, as specified, but a change *into* an unranked role is treated as an increase (and the alert says so). A change to an unknown role cannot be shown to be a decrease, and spec P1-09 requires unapproved increases to alert.
6. **LM-2 groups per actor/session within the window**, like LM-1, so a two-edge allowed path is one alert rather than two (under one-to-one matching the second would otherwise count as a false alert).
7. **Composite keys use `JSON.stringify([...])`, not `'\0'` joins** (§6 Task 5.2), because a `'\0'` join collides when a field itself contains NUL.
8. **The generator returns approvals as `{ synthetic: true, changes }`** (the `approvals.json` shape `loadApprovals` takes), plus `csv`; its events go through `parseCsv`, so the benchmark exercises the real ingest.
9. **Practice-set location.** Tests look in `TOOLKIT_DIR`, `/toolkit` (judge replica), `./toolkit` (CI checkout), `../Track-4-Toolkit` and `../track4-toolkit`, and fail loudly if none has the practice files.
10. **`kig detect` exit codes:** 0 success; 2 for bad arguments or unreadable/invalid input (events, approvals or baseline). JSON output also escapes C1 controls, bidi overrides and line separators, which `JSON.stringify` leaves raw.
11. **Gate commands on Windows:** run `node scripts/judge.cjs …` directly; `npm run judge -- node --test …` loses the `--test` flags to npm in PowerShell.

## 8. Quick Reference: Commit Sequence

1. `feat(detect): ingest, clock correction and reorder buffer`
2. `feat(detect): approvals, role tracking and privilege rules`
3. `feat(detect): service-edge baseline and lateral-movement rules`
4. `feat(detect): detector pipeline and kig detect CLI`
5. `feat(detect): seeded generator, benchmark scorer and kig bench detect`
6. `docs(evidence): phase 5 detector regression and benchmark evidence`
