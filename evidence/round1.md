# Phase 1 / Round 1 Gate Evidence

**Project:** Key Identity Guard  
**Runtime target:** Node.js 24.11.1, Linux ARM64 replica  
**Status:** Gate 1 checks passed (2026-11-26)

## Verification results

| Check | Result | Evidence |
| --- | --- | --- |
| Toolkit lost-device validator in the ARM64 replica | **PASS** — `Local scenario passed.`; setup, owner and peer reads, denial after revocation, audit correlation, persistence, fresh setup, and fake-key output check passed. | `evidence/validate-17f601d.txt` (local validator capture); ARM64 replica result confirmed in the project chat. |
| Test suite in the ARM64 replica | **PASS** — exit 0; 216 passed, 0 failed, 1 skipped. | ARM64 replica result confirmed in the project chat. The separate local log `testinglogs/phase1testlog.txt` is not this ARM64 run. |
| `protected_read` interoperability in the ARM64 replica | **PASS** — `pqcrypto==0.4.0`, `interop 25/25`; 1 test passed, 0 failed, 0 skipped. | Command: `npm run judge -- node --test tests/interop/interop.test.cjs`. The judge image was updated to provide the pinned Python package. |
| Secret marker scan | **PASS** — unique `key_material` marker absent from stdout, stderr, and files recursively scanned under the temporary state directory. Setup returned `{"ready":true}`. The adapter stores the DB under `<state-dir>/kig/adapter.db`. | Manual scan result confirmed in the project chat. |
| Native ARM64 GitHub Actions CI | **PASS** — user inspected the GitHub repository and confirmed all CI checks passed. | CI run URL/commit was not captured in this evidence file. |

## Local test log note

`testinglogs/phase1testlog.txt` records a separate local run: 217 tests, 211 passed, 0 failed, 6 skipped. It includes the marker-scan test passing, but its interop test skipped because `pqcrypto` was unavailable in that environment. The interop result above is from the later ARM64 replica run and passed 25/25.

## Scope and limitations

- The Round 1 adapter accepts `actor` as a trusted input; it does not authenticate a real-world identity.
- Adapter state stores protected bodies in plaintext SQLite. No at-rest confidentiality is claimed for the adapter state directory.
- The Round 1 threat scope is hostile JSON input and observable adapter behavior; compromise of the state directory or host is outside that scope.
- These checks establish the Phase 1 adapter gate. They do not establish completion or measured performance for later CLI, multi-node, backup, detection, or messaging phases.

## Release checklist

The CI and Phase 1 verification results above are recorded as passed. PR approval/merge, README review, and the `round1-ready` tag are repository/release actions and are not evidenced by the test outputs in this file.

## Captured logs (added in Task 1.17)

- `evidence/arm64-npm-test-summary.txt`: `npm run judge -- npm test` in the emulated linux/arm64 replica. 217 tests, 216 pass, 0 fail, 1 skipped (interop, since this replica run had no `pqcrypto`; interop 25/25 is recorded above). Duration about 16 minutes under emulation.
- `evidence/validate-arm64.txt`: `npm run judge -- node scripts/validate.cjs` in the same replica. `Local scenario passed.`
- CI: the validator step in `.github/workflows/ci.yml` is now blocking (no `continue-on-error`).
