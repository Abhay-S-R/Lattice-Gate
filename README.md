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
| `detect --events <events.csv\|.jsonl> [--approvals <approvals.json>] [--baseline <baseline.json>] [--json]` | Runs the explainable detector (privilege changes without approval, lateral-movement candidates, clock-skew and reordering handling) and prints each alert with its reason, plus a timeline with raw, received and corrected times. Example: `node kig.cjs detect --events ../Track-4-Toolkit/practice/events.csv --approvals ../Track-4-Toolkit/practice/approvals.json` |
| `bench detect --seeds 101,102,103 --holdout 201-205` | Seeded synthetic detection benchmark: held-out precision, recall, F1, median time-to-alert and false alerts per 1,000 benign events (results and limits: [`evidence/phase5.md`](evidence/phase5.md)) |
| `init [--home <dir>] [--force]` | Creates the KIG stores, signing and KEM keys, operator recovery key, and public trust anchor |
| `account add <account>` | Creates an account in the control-plane registry |
| `device enrol <device> --account <account>` / `device approve <device> --by <device>\|--operator --approval-id <id>` | Creates a device keystore with proof of possession, then activates it through approval |
| `file publish <file> --as <device> --input <path>` / `file read <file> --device <device> --node <A\|B\|C>` | Encrypts file contents at the control plane and reads them through an authenticated node |
| `share <file> --with <account>` | Grants an account access by adding device-bound encrypted envelopes |
| `up` / `down` / `status` | Starts, stops and checks the control plane (`127.0.0.1:7400`) and nodes A, B, C (`7401`–`7403`); `KIG_PORT_BASE` moves them |
| `revoke --device <device>` | Revokes a device; every node denies it once it applies the signed snapshot |
| `node partition <A|B|C>` / `node heal <A|B|C>` | Cuts a node off from the CP to show it fails closed at lease expiry (5 s) |
| `bench revocation --n 100 --seed <s>` | Revocation propagation p50/p95/max per node and last node, plus the partition bound |
| `rotate --file <file>` | Rotates a file to a new key version: staged on every node with signed acks, then committed with an epoch cutoff. New requests for the old version are refused from the moment each node applies the cutoff; transfers already in flight may finish within 30 s (node-local clock), then end |
| `lost --device <device>` | Lost device: revokes it on every node (prints each node's signed-ack latency), then re-keys every file it could read. A replacement enrols with `device enrol` and needs approval by another active device of the account or the operator; it then receives envelopes for the current versions |
| `backup --out <dir>` | Signed (ML-DSA-65), encrypted backup of the control plane (registry snapshot and CP keys), wrapped to the operator recovery ML-KEM-768 key; pins its epoch in the anchor |
| `restore <dir> --recovery-key <file> --anchor <file>` | Restores only after every check passes, in order: `bad_signature`, `unsupported_schema`, `digest_mismatch`, `stale_backup`, `decrypt_failed`, `incomplete_backup`. A refused restore leaves live state unchanged |
| `crash-test [--point <p>]` | SIGKILLs the control plane at each rotation phase (`after_prepare`, `after_stage`, `before_commit`, `after_commit`, `during_distribute`) on an isolated cluster, restarts it and checks recovery: one active version everywhere, revocations kept, data readable, epochs never lower |
| `msg demo [--seed <uint32>]` | Runs the authenticated messaging, replay protection, forward-secrecy, and seeded delivery demonstration |

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
| Crash | `tests/crash/` | SIGKILL inside an adapter transaction: no partial state, chain stays valid; `kig crash-test` at all five rotation crash points |
| End to end | `tests/e2e/` | Round 2 demo steps 4–8 on a live CP and three nodes, with the real 30 s grace window (Gate 4) |
| Interop | `tests/interop/` | Python `pqcrypto==0.4.0` decapsulates our `protected_read` output and recomputes the proof (25 runs). Skipped with a notice if `pqcrypto` is absent. |

Round 1 gate evidence: [`evidence/round1.md`](evidence/round1.md). Phase 4 (rotation, lost device, crash recovery, backups): [`evidence/phase4.md`](evidence/phase4.md).

## Limitations

Round 1 adapter (full threat model: Task 7.5):

- **The `actor` field is a trusted input.** The adapter enforces policy for the actor it is given; it cannot prove the caller owns that identity (features P0-05). Device authentication is part of the Round 2 system.
- **The state directory is outside the attacker model.** We defend the input channel (stdin, stdout, stderr, exit codes, timing). Someone who can read, modify or roll back `TRACK4_STATE_DIR` is out of scope (D-15).
- **Stored bodies are plaintext in SQLite.** The adapter has no secret outside the state directory, so encryption there would protect nothing (D-14).
- **`protected_read` is a KEM/HMAC interoperability check**, not end-to-end messaging, replay protection or forward secrecy.
- **Memory wiping is best effort.** JavaScript cannot guarantee that secrets are erased from memory.

Round 2 rotation, recovery and backups (Phase 4; details in [`evidence/phase4.md`](evidence/phase4.md)):

- **The control plane is the key custodian** (KMS model): it decrypts during rotation and holds every file key under its master KEM key. Content or keys a lost device copied before the loss cannot be recalled; revocation stops new access only.
- **Single host, one monotonic clock, loopback HTTP.** Cutoff grace (30 s) and leases are node-local monotonic times; latencies exclude real networks.
- **Files are capped at 256 KiB**, so a staged version fits one signed HTTP message.
- **Node anti-rollback protects against restoring an old `node.db`**, not against an attacker who controls a node's whole directory. A rolled-back node fails closed for versions staged after its copy was taken.
- **The recovery private key lives in `KIG_HOME/operator/`** for the demo; in a real deployment the operator keeps it offline.
