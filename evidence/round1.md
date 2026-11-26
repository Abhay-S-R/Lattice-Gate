# Phase 1 / Round 1 Gate Evidence

**Project:** Key Identity Guard  
**Runtime target:** Node.js 24.11.1, Linux **x86-64 (amd64)** judging container  
**Status:** Gate 1 checks passed on x86-64 (2026-11-26)

> **Platform correction (2026-11-26).** The organizers first said the judging container was ARM64, then corrected it to x86-64. The Gate 1 checks were re-run in the x86-64 replica (below). The earlier ARM64 results are kept under "Superseded" as a record of what was run; they are no longer the target.

## Verification results (x86-64, current)

All in the judging replica (`npm run judge -- …`): linux/amd64, Node 24.11.1, Python 3.12.16 with `pqcrypto==0.4.0`, read-only root, no network, non-root user, writable `/tmp` only. Run natively on an x86-64 host; total time 96 s including the image build.

| Check | Result | Evidence |
| --- | --- | --- |
| `kig compat` | **PASS**, all checks; `node v24.11.1 linux-x64`, OpenSSL 3.5.4, SQLite 3.50.4 | `evidence/x64-replica-compat.txt` |
| Test suite (unit, adapter contract, negative incl. marker scan, concurrency warm + cold ×20, crash, interop) | **PASS**: 262 tests, 262 passed, 0 failed, **0 skipped** | `evidence/x64-replica-test.txt` |
| `protected_read` interoperability | **PASS**: `pqcrypto==0.4.0` decapsulates and recomputes the proof, `interop 25/25` (part of the suite above) | `evidence/x64-replica-test.txt` |
| Toolkit lost-device validator | **PASS**: `Local scenario passed.` including "fake key stays out of output" | `evidence/x64-replica-validate.txt` |
| Secret marker scan | **PASS**: unique `key_material` marker absent from stdout, stderr and every file under the state directory (test `marker scan` in `tests/negative/`) | `evidence/x64-replica-test.txt` |
| CI on x86-64 (`x64` and `judging-replica` jobs) | Pending the next push; artifacts `evidence-x64-<sha>` and `evidence-replica-x64-<sha>` | GitHub Actions |

## Scope and limitations

- The Round 1 adapter accepts `actor` as a trusted input; it does not authenticate a real-world identity.
- Adapter state stores protected bodies in plaintext SQLite. No at-rest confidentiality is claimed for the adapter state directory.
- The Round 1 threat scope is hostile JSON input and observable adapter behavior; compromise of the state directory or host is outside that scope.
- The replica reproduces the conditions the organizers described, not their hidden test program or exact machine.
- These checks establish the Phase 1 adapter gate. They do not establish completion or measured performance for later CLI, multi-node, backup, detection, or messaging phases.

## Superseded: ARM64 results (pre-correction, kept for the record)

| Check | Result | Evidence |
| --- | --- | --- |
| Toolkit validator, emulated ARM64 replica | PASS, `Local scenario passed.` | `evidence/superseded-arm64-validate.txt`, `evidence/validate-17f601d.txt` (local) |
| Test suite, emulated ARM64 replica | PASS, 216 passed, 0 failed, 1 skipped (interop; `pqcrypto` not yet in that image), about 16 minutes under emulation | `evidence/superseded-arm64-npm-test-summary.txt` |
| Interop, ARM64 replica | PASS, `interop 25/25` | Command: `npm run judge -- node --test tests/interop/interop.test.cjs` (result confirmed in the project chat) |
| ARM64 GitHub Actions CI | PASS, reported by a teammate; run URL not captured | n/a |

`testinglogs/phase1testlog.txt` records a separate local run: 217 tests, 211 passed, 0 failed, 6 skipped (interop skipped, no `pqcrypto` there).
