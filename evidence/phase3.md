# Phase 3 M4 evidence

## M4 deliverables

- `kig bench revocation --n 100 --seed 2026` completed against a temporary KIG home. Per-node first-denial and signed-ack percentiles, the last node, and the partition result are in [revocation-2026-11-26T19-57-45-434Z.json](revocation-2026-11-26T19-57-45-434Z.json).
- All 100 revoked devices were denied by nodes A, B, and C. The unaffected observer remained allowed on all three nodes.
- Partitioning node A stopped policy sync. After the 5,000 ms lease expired, its signed probe was denied with `lease_expired`; healing resumed sync.
- The integration test also checked node revoked-device alerts and control-plane duplicate-revocation alerts through the merged `kig alerts --json` output.

## Verification

- WSL2 Ubuntu, Node 24.13.1: `npm test` — 390 passed, 0 failed, 0 skipped.
- Windows Docker Desktop judge: `node scripts/judge.cjs npm test` — 390 passed, 0 failed, 0 skipped. The judge script builds and runs `linux/amd64` (x86-64).
- Final Developer A/B integration recheck (2026-11-27): isolated `linux/amd64` Docker `npm test` — 395 passed, 0 failed, 0 skipped; `npm run validate` — passed. This run includes `verify-log --db` on the CP registry and all three node stores.
- Interop: `node --test tests/interop/interop.test.cjs` — `interop 25/25` in WSL2 and in the Docker judge.
- `git diff --check` — clean.

## Limitations

- Revocation timings use one host monotonic clock and loopback HTTP. They include signed challenge probes and do not represent a multi-host network deployment.
- The partition control is available only over loopback, using the supervisor-managed per-node token (or `NODE_ENV=test`).
- This report records local and judge verification. It does not record a new hosted CI run.
