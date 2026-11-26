# Phase 5 evidence: detector regression and benchmark (Gate 5)

Code under test: commit `7223592` (branch `phase-5-detector`). Every command below ran inside the judging-container replica (`node scripts/judge.cjs …`): linux/arm64 (emulated on an x86-64 host), Node.js v24.11.1, read-only root, no network, toolkit at `/toolkit`. Emulated ARM is correct but slow, so no timing in this file is a performance claim, except the time-to-alert figures, which come from the simulated collector clock and do not depend on host speed.

Specs: features P1-09, P1-10, P1-11, P1-18, D-09; architecture §15; plan `docs/plans/phase-5.md`.

## 1. Test suites

```
node scripts/judge.cjs node --disable-warning=ExperimentalWarning --test "tests/unit/detect/*.test.cjs" tests/unit/crypto-boundary.test.cjs
```

Result: **86 tests, 86 pass, 0 fail, 0 skipped** (arm64). This includes the label-isolation test: the detector's modules never mention ground truth, and its require graph never reaches `generator.cjs` or `bench.cjs`. It also includes the crypto-boundary test: Phase 5 adds no `node:crypto` import.

Full `npm test` on Node 24.11.1 (native x86-64 container, toolkit mounted): 302 tests, 301 pass, 0 fail, 1 skipped. The skip is the `pqcrypto` interop test, which needs Python with `pqcrypto` (present in the judge image, absent in the plain Node image used for this run).

## 2. Practice-set regression (22 events)

```
node scripts/judge.cjs node kig.cjs detect --events /toolkit/practice/events.csv --approvals /toolkit/practice/approvals.json
```

Full output: [`detect-practice-7223592.txt`](detect-practice-7223592.txt). 22 events, 0 rejected, **2 alerts**, 0 notices. Baseline: the 7 documented practice edges.

| Gate item | Result |
|---|---|
| `evt-003`..`evt-005` approved | `evt-003`, `evt-004` → `approved_change` (`change-100`; the actor `user-alex` is the subject, the approver is `user-admin`); `evt-005` routine |
| `evt-016` approved (`change-101`) | `approved_change`; Alex's expected role returns to `viewer`; revocation context covers `reports`, `reports-node-a`, `reports-node-b` |
| `evt-008` → `PRIV-1` linking `evt-009` | `alert-001` PRIV-1 high: "role increase viewer -> operator for user-blair has no matching approval: no approval is referenced by the event"; `evt-009` linked as PRIV-2 |
| `evt-010`..`evt-012` one `LM-1` | `alert-002` LM-1 medium, path `reports->billing, billing->archive, archive->identity`, all three `deny`, "no access succeeded"; the LM-3 deny burst is folded into it (`also: LM-3`), not a second alert |
| `evt-007`..`evt-009` no LM alert | none (all three edges are in the documented baseline) |
| `evt-017`/`evt-018` expected enforcement | both classified `expected_enforcement` (`change-101`), no LM alert |
| `evt-020` no alert | none (one isolated denial) |
| `evt-013`/`evt-014` order | timeline in event-time order `evt-013` then `evt-014`; ingest indexes 13 and 12 kept |
| `evt-015` correction | raw `09:06:03.000Z`, offset +2000 ms → corrected `09:06:01.000Z`, delay 200 ms; raw and received strings preserved |
| Window 30 s / 60 s / 120 s | identical alert set (test `window invariance 30 s / 60 s / 120 s`) |

Time-to-alert on the practice set: 4.8 s (PRIV-1) and 4.9 s (LM-1). Both are the 5 s reorder-buffer wait minus the 100–200 ms delivery delay.

## 3. Held-out benchmark

```
node scripts/judge.cjs node kig.cjs bench detect --seeds 101,102,103 --holdout 201,202,203,204,205
```

Full report: [`detect-7223592.json`](detect-7223592.json) (seeds, thresholds, baseline, per-seed results and metric definitions); console output: [`detect-bench-7223592.txt`](detect-bench-7223592.txt).

**Data origin: synthetic**, from the seeded generator `src/detect/generator.cjs` (mulberry32; simulation only). This is not production traffic. Baseline: the 7 documented edges plus 3 edges from a separate benign warm-up corpus (seed 1), 10 edges in total. Tuning, held-out and warm-up seeds are disjoint (enforced in code). No rule or threshold was changed after looking at the held-out seeds.

| Held-out seeds 201–205 | Value |
|---|---|
| Events | 6,784 (6,516 benign, 268 attack) |
| Labelled incidents | 105 (85 detectable by design, 20 evasive) |
| Incident level: precision / recall / F1 | **1.000 / 0.810 / 0.895** |
| Recall on detectable incidents | 1.000 |
| Event level: precision / recall / F1 (reported separately) | 1.000 / 0.813 / 0.897 |
| Median time-to-alert | **4,810 ms** (max 5,000 ms) |
| False alerts per 1,000 benign events | **0.00** |
| Misses | 0 detectable, **20 evasive** (all of them) |
| Clock and delivery stress | 1,333 events skewed within ±5 s; 216 beyond ±5 s (flagged unsupported, ordered by receipt); 914 delayed 1–4 s; 159 delayed > 5 s (147 processed as late); 228 reordered |

Detection by scenario (held-out):

| Scenario | Detected |
|---|---|
| Unapproved escalation, no approval | 10/10 |
| Unapproved escalation citing another subject's approval | 5/5 |
| Unapproved escalation citing an approval for a different role | 5/5 |
| Role change on an expired approval (`valid_until` exclusive) | 10/10 |
| 3-edge denied chain (LM-1) | 20/20 |
| One allowed edge into a sensitive service (LM-2) | 10/10 |
| Two allowed edges into sensitive services (LM-2) | 10/10 |
| 3 denials across 2 unseen targets (LM-3) | 15/15 |
| **Evasive:** low-and-slow, 3 denied edges 75–120 s apart | **0/10** |
| **Evasive:** two denied edges | **0/10** |

Tuning seeds 101–103 give the same picture: precision 1.000, recall 0.810, F1 0.895, median time-to-alert 4,854 ms, 0 false alerts, 12 of 12 evasive incidents missed.

### Metric definitions

- **Incident match:** an alert matches a labelled incident when their event IDs intersect. Matching is one-to-one and greedy by largest overlap. A second alert on an already-matched incident counts as a false alert.
- **Precision** = matched alerts / all alerts. **Recall** = matched incidents / all incidents, evasive ones included. **F1** = their harmonic mean.
- **False alerts per 1,000 benign events** = unmatched alerts / benign events × 1000.
- **Time-to-alert:** from receipt of the last evidence event an alert needed to its emission, on the simulated collector clock, which includes the reorder-buffer wait (bounded by the 5 s lateness), plus the measured detector processing time per event.
- **Event level:** event IDs covered by alerts vs event IDs belonging to incidents, never mixed with the incident-level figures.

## 4. Limits (read before quoting any number above)

- **Synthetic data only.** The generator's benign traffic stays on baseline edges, and its role changes are cleanly approved or cleanly not. A precision of 1.000 and 0 false alerts describe that mix, not a real estate. Real traffic adds things the generator does not: new services after a deployment, untidy approvals, and shared or service sessions, all of which would cost precision. The 22 practice events demonstrate behaviour; they do not establish accuracy.
- **Known blind spots, measured not hidden.** Probes spread wider than the 60 s window (low-and-slow) and two-edge denied probes fall below the LM-1 and LM-3 thresholds: 0 of 20 detected. LM-2 catches small paths only when a request into a sensitive service succeeds.
- **Clock.** Offsets are trusted as given within ±5 s; beyond that an event is flagged `clock_unsupported`, ordered by receipt and marked order-uncertain, never corrected or clamped. The ±250 ms uncertainty is a configured assumption, not a measurement.
- **Latency trade-off.** The 5 s reorder window buys correct ordering for delays up to 5 s at the cost of about 5 s of time-to-alert. Events delayed longer are still processed, marked `late`.
- **Cold start per subject.** A subject's first observed role becomes its expected role. An identity whose very first event already shows an elevated role is not flagged by PRIV-1.
- **Revocation context** covers approved `revoke_role` changes in the event stream. Device revocations and key cutoffs from Phases 3–4 are not yet fed in.
