# Key Identity Guard

Post-quantum protected file access that keeps enforcing decisions as keys, devices and permissions change, with a tamper-evident audit log and an explainable detector. Built for DevForge Track 4, "Trust, but verify".

Design documents: [`docs/features.md`](docs/features.md) (what and why), [`docs/architecture.md`](docs/architecture.md) (how), [`docs/implementation-plan.md`](docs/implementation-plan.md) (build order).

## Requirements

Node.js **24.11.1**. Nothing else: there are no npm dependencies to install.

```sh
git clone <this repo> && cd <repo>
node --version            # must print v24.11.1
npm run compat            # all PASS
npm test                  # optional: Python 3.12 + pqcrypto==0.4.0 enables the interop test
```

## Round 1 adapter

`track4_service.cjs` at the repository root is the organizer entry point. Each run reads **one** JSON object on stdin, writes **one** JSON object plus a newline on stdout, and exits. State persists in SQLite under `$TRACK4_STATE_DIR` (or the OS temp dir) at `kig/adapter.db`. Nothing is installed and no background process is left running.

```sh
export TRACK4_STATE_DIR=$(mktemp -d)        # PowerShell: $env:TRACK4_STATE_DIR = (New-Item -ItemType Directory "$env:TEMP\kig").FullName
echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo note"},"disabled":[],"key_material":"synthetic-only"}' | node track4_service.cjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r01"}' | node track4_service.cjs
echo '{"op":"revoke","actor":"maya"}' | node track4_service.cjs
echo '{"op":"read","actor":"maya","asset":"brief","request_id":"r02"}' | node track4_service.cjs
echo '{"op":"audit","request_id":"r02"}' | node track4_service.cjs
```

| Operation | Response |
|---|---|
| `setup` | `{"ready":true}`, after the new generation is committed |
| `read` | `{"decision":"allow","body":"…"}` or `{"decision":"deny"}` |
| `revoke` | `{}`, after the revocation is persisted |
| `audit` | `{"request_id":"…","decision":"allow"\|"deny"}` (latest attempt; unknown ID → `deny`) |
| `protected_read` | `{"ciphertext":"<base64 ML-KEM-768 ct>","proof":"<hex HMAC-SHA-256>"}` or `{"decision":"deny"}` |
| unknown `op` / malformed input | `{"error":"unsupported_operation"}` / `{"error":"invalid_request"}` |

Exit code is 0 for every answer, denials included. Only a `setup` or `revoke` that could not be persisted exits 1, with empty stdout and one fixed stderr line (features D-13). `key_material` is never stored, logged or used. Suspicious requests (revoked-actor retries, invalid keys, hostile identifiers, denial bursts) are recorded as alert events in the audit chain (features P0-10).

## Round 2 CLI

`node kig.cjs <command> [options]` (`node kig.cjs help` lists commands; `<command> --help` shows usage). Exit codes: 0 ok, 1 failed/broken, 2 usage error.

| Command | Does |
|---|---|
| `compat` | Checks that this runtime supports everything KIG needs (crypto, SQLite concurrency and crash safety) |
| `verify-log (--adapter <stateDir> \| --db <file>) [--anchor <file>]` | Verifies an audit log offline. Prints `OK <count> <head>` or `BROKEN seq=<n> <reason>`, where reason is `content_edit`, `missing_or_reordered`, `truncated`, `checkpoint_mismatch` or `invalid_checkpoint`. |
| `keys init --out <dir> [--force]` | Creates the operator's ML-DSA-65 audit-signing key pair (private key mode 0600) |
| `checkpoint (--adapter <stateDir> \| --db <file>) --key <file> --anchor <file>` | Signs the current log head and appends it to an anchor file kept **outside** the store |
| `alerts (--adapter <stateDir> \| --db <file>) [--json] [--limit N]` | Lists self-monitoring alerts, newest first, with identifiers escaped for safe terminal display |

Operator flow for the adapter's log:

```sh
node kig.cjs keys init --out ~/kig-operator
node kig.cjs checkpoint --adapter "$TRACK4_STATE_DIR" --key ~/kig-operator/audit-signing.key --anchor ~/kig-operator/adapter-anchor.json
node kig.cjs verify-log --adapter "$TRACK4_STATE_DIR" --anchor ~/kig-operator/adapter-anchor.json
node kig.cjs alerts --adapter "$TRACK4_STATE_DIR"
```

Without an anchor, `verify-log` detects edits, deletions and reordering, but not removal of the newest records. The signed checkpoint in the anchor is what makes truncation and recomputed rewrites detectable. Whoever controls the anchor file controls which key is trusted, so keep it with the operator.

## Development

Works the same on Windows (PowerShell, cmd, Git Bash), WSL, Linux and macOS. All helper scripts are Node scripts; there are no shell scripts.

- Install Node.js 24.11.1 (Windows: the official installer or `nvm-windows`; Linux/WSL/macOS: `nvm install` reads `.nvmrc`).
- Clone the organizer toolkit next to this repo: `git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit ../Track-4-Toolkit` (or set `TOOLKIT_DIR`).
- `npm test`: all tests (`node --test`).
- `npm run compat`: runtime self-check.
- `npm run validate`: the toolkit's `validate.py` against the root adapter (needs Python 3.10+; output saved to `evidence/`).
- `npm run judge -- <cmd>`: runs `<cmd>` inside a replica of the judging container (linux/amd64 like judging, Node 24.11.1, Python 3.12, read-only root, no network, non-root, writable `/tmp` only). Needs Docker Desktop. Native and fast on x86-64 machines; on ARM machines (e.g. Apple Silicon) Docker emulates x86, which is correct but slow, so never use its timings. Examples: `npm run judge -- node kig.cjs compat`, `npm run judge -- npm test`, `npm run judge -- node scripts/validate.cjs`.

The judging container is Linux: the replica (and CI, both x86-64) is the source of truth, not a Windows run.

## Testing

`npm test` runs everything with Node's built-in runner (about 1 minute; similar inside the x86-64 replica).

| Layer | Location | Covers |
|---|---|---|
| Unit | `tests/unit/` | crypto provider (RFC 5869 vector, tamper rejection, ML-KEM/ML-DSA), identifiers, encoder, SQLite helper, schema, audit chain, validation, policy, each operation, alerts |
| Adapter contract | `tests/adapter/contract.test.cjs` | spawns `track4_service.cjs` once per request, exactly like the worker |
| Negative | `tests/negative/` | hostile identifiers (`__proto__`, lone surrogates, NUL, newline-JSON, paths), malformed input, strict Base64, leak and `key_material` marker scans |
| Concurrency | `tests/adapter/concurrency.test.cjs` | 8 parallel processes, warm and cold start, ×20 |
| Crash | `tests/crash/` | SIGKILL inside a transaction: no partial state, chain stays valid |
| Interop | `tests/interop/` | Python `pqcrypto==0.4.0` decapsulates our `protected_read` output and recomputes the proof (25 runs). Skipped with a notice if `pqcrypto` is absent. |

Round 1 gate evidence: [`evidence/round1.md`](evidence/round1.md).

## Limitations

Round 1 adapter (full threat model: Task 7.5):

- **The `actor` field is a trusted input.** The adapter enforces policy for the actor it is given; it cannot prove the caller owns that identity (features P0-05). Device authentication is part of the Round 2 system.
- **The state directory is outside the attacker model.** We defend the input channel (stdin, stdout, stderr, exit codes, timing). Someone who can read, modify or roll back `TRACK4_STATE_DIR` is out of scope (D-15).
- **Stored bodies are plaintext in SQLite.** The adapter has no secret outside the state directory, so encryption there would protect nothing (D-14).
- **`protected_read` is a KEM/HMAC interoperability check**, not end-to-end messaging, replay protection or forward secrecy.
- **Memory wiping is best effort.** JavaScript cannot guarantee that secrets are erased from memory.
