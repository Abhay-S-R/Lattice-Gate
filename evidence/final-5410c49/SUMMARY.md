# Evidence Summary (`5410c49`)

- **Commit:** `5410c49`
- **Started (UTC):** `2026-11-26T23:20:34.797Z`
- **Completed (UTC):** `2026-11-26T23:24:57.845Z`
- **Environment:** linux/amd64 judging replica (`--read-only`, `--network none`, Node 24.11.1, Python 3.12 + pqcrypto 0.4.0)
- **Checks Passed:** 11 / 11

| Check | Command | Exit | Duration (s) | Artifact | Status |
|---|---|---:|---:|---|---|
| `compat` | `node kig.cjs compat` | 0 | 4.2 | [compat.txt](compat.txt) | **PASS** |
| `validate` | `node scripts/validate.cjs` | 0 | 2.0 | [validate.txt](validate.txt) | **PASS** |
| `test` | `npm test` | 0 | 175.5 | [test.txt](test.txt) | **PASS** |
| `adapter-walkthrough` | `node scripts/walkthrough-adapter.cjs` | 0 | 1.5 | [adapter-walkthrough.txt](adapter-walkthrough.txt) | **PASS** |
| `demo` | `node kig.cjs demo --json` | 0 | 39.6 | [demo.json](demo.json) | **PASS** |
| `bench-perf` | `node kig.cjs bench perf --json` | 0 | 20.8 | [bench-perf.json](bench-perf.json) | **PASS** |
| `bench-revocation` | `node kig.cjs bench revocation --n 100 --seed 2026 --out /tmp/kig-revocation-bench.json --json` | 0 | 10.4 | [bench-revocation.json](bench-revocation.json) | **PASS** |
| `crash-test` | `node kig.cjs crash-test --json` | 0 | 4.7 | [crash-test.json](crash-test.json) | **PASS** |
| `detect-practice` | `node kig.cjs detect --events /toolkit/practice/events.csv --approvals /toolkit/practice/approvals.json --json` | 0 | 0.9 | [detect-practice.json](detect-practice.json) | **PASS** |
| `bench-detect` | `node kig.cjs bench detect --seeds 101,102,103 --holdout 201-205 --out /tmp/kig-detect-bench.json --json` | 0 | 1.0 | [bench-detect.json](bench-detect.json) | **PASS** |
| `msg-demo` | `node kig.cjs msg demo --seed 2026` | 0 | 2.4 | [msg-demo.txt](msg-demo.txt) | **PASS** |
