# Evidence Index

This directory holds reproducible verification artifacts and gate reports for **Key Identity Guard (DevForge Track 4)**.

## Structure

| Path | Purpose |
|---|---|
| [`evidence-sheet.md`](evidence-sheet.md) | **Primary Track 4 evidence sheet** (filled from the organizer template): all 12 core goals, pre-defined expectations, measured outcomes, artifact links, and 4 detailed measurement records. |
| `final-<commit>/` | **Submission evidence bundle** produced by `node scripts/collect-evidence.cjs` inside the native `linux/amd64` judging replica (`--read-only`, `--network none`, Node 24.11.1, Python 3.12 + `pqcrypto==0.4.0`). Start with `final-<commit>/SUMMARY.md`. |
| [`round1.md`](round1.md) | Gate 1 report for the Round 1 judging adapter (`track4_service.cjs`). |
| [`phase3.md`](phase3.md) | Gate 3 report for multi-node revocation propagation (`kig bench revocation`) and partition fail-closed leases. |
| [`phase4.md`](phase4.md) | Gate 4 report for versioned key rotation, 30 s grace cutoff, lost-device re-keying, 5-point `SIGKILL` crash recovery, backups, and node anti-rollback. |
| [`phase5.md`](phase5.md) | Gate 5 report for the explainable detector, 22-event practice regression, and seeded synthetic benchmark. |
| [`superseded/`](superseded/) | Historical captures from before the organizer platform correction (emulated `linux/arm64`) and intermediate Phase 4 commits (`6984769`, `cca2fa5`). Kept for auditability; not used for final claims. |
| [`../testinglogs/`](../testinglogs/) | Operator terminal verification logs captured across phases on Windows + Docker Desktop (`linux/amd64`). |

## Reproducing Everything

From the repository root (with `../Track-4-Toolkit` cloned alongside and Docker running):

```sh
node scripts/collect-evidence.cjs
```
