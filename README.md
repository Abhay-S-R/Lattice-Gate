# Key Identity Guard

Post-quantum protected file access that keeps enforcing decisions as keys, devices and permissions change, with a tamper-evident audit log and an explainable detector. Built for DevForge Track 4, "Trust, but verify".

Design documents: [`docs/features.md`](docs/features.md) (what and why), [`docs/architecture.md`](docs/architecture.md) (how), [`docs/implementation-plan.md`](docs/implementation-plan.md) (build order).

## Requirements

Node.js **24.11.1**. Nothing else: there are no npm dependencies to install. *(Full clean-machine steps: Task 7.4.)*

## Round 1 adapter

`track4_service.cjs` at the repository root reads one JSON request on stdin and writes one JSON response on stdout. *(Usage: Task 1.17.)*

## Round 2 CLI

`node kig.cjs <command>`. Available now: `node kig.cjs compat` checks that this machine's Node supports everything the project needs. *(Full command list: Phase 2 onward.)*

## Development

- `npm test`: all tests (`node --test`).
- `npm run compat`: runtime self-check.
- `npm run validate`: the organizer toolkit's `validate.py` against the root adapter (expects the toolkit at `../Track-4-Toolkit`, or set `TOOLKIT_DIR`).
- `npm run judge -- <cmd>`: runs `<cmd>` inside a replica of the judging container (ARM64, read-only root, offline, writable `/tmp` only). Needs Docker.

## Testing

*(Test layers and evidence: Task 1.17 and Phase 7.)*

## Limitations

*(Threat-model limits: Task 1.17 and Task 7.5.)*
