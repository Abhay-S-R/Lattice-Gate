# Key Identity Guard

Post-quantum protected file access that keeps enforcing decisions as keys, devices and permissions change, with a tamper-evident audit log and an explainable detector. Built for DevForge Track 4, "Trust, but verify".

Design documents: [`docs/features.md`](docs/features.md) (what and why), [`docs/architecture.md`](docs/architecture.md) (how), [`docs/implementation-plan.md`](docs/implementation-plan.md) (build order).

## Requirements

Node.js **24.11.1**. Nothing else: there are no npm dependencies to install. *(Full clean-machine steps: Task 7.4.)*

## Round 1 adapter

`track4_service.cjs` at the repository root reads one JSON request on stdin and writes one JSON response on stdout. *(Usage: Task 1.17.)*

## Round 2 CLI

`node kig.cjs <command>` (`node kig.cjs help` lists them). Available now:

- `node kig.cjs compat` checks that this machine's Node supports everything the project needs.
- `node kig.cjs detect --events <events.csv|.jsonl> [--approvals <approvals.json>] [--baseline <baseline.json>] [--json]` runs the explainable detector (privilege changes without approval, lateral-movement candidates, clock-skew and reordering handling) and prints each alert with its reason, plus a timeline with raw, received and corrected times. Example: `node kig.cjs detect --events ../Track-4-Toolkit/practice/events.csv --approvals ../Track-4-Toolkit/practice/approvals.json`.
- `node kig.cjs bench detect --seeds 101,102,103 --holdout 201-205` runs the seeded synthetic benchmark and prints held-out precision, recall, F1, median time-to-alert and false alerts per 1,000 benign events (results and limits: [`evidence/phase5.md`](evidence/phase5.md)).

*(Full command list: Phase 2 onward.)*

## Development

Works the same on Windows (PowerShell, cmd, Git Bash), WSL, Linux and macOS. All helper scripts are Node scripts; there are no shell scripts.

- Install Node.js 24.11.1 (Windows: the official installer or `nvm-windows`; Linux/WSL/macOS: `nvm install` reads `.nvmrc`).
- Clone the organizer toolkit next to this repo: `git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit ../Track-4-Toolkit` (or set `TOOLKIT_DIR`).
- `npm test`: all tests (`node --test`).
- `npm run compat`: runtime self-check.
- `npm run validate`: the toolkit's `validate.py` against the root adapter (needs Python 3.10+; output saved to `evidence/`).
- `npm run judge -- <cmd>`: runs `<cmd>` inside a replica of the judging container (linux/arm64, Node 24.11.1, read-only root, no network, writable `/tmp` only). Needs Docker Desktop. On x86 machines ARM is emulated: correct but slow, so never use its timings. Examples: `npm run judge -- node kig.cjs compat`, `npm run judge -- npm test`, `npm run judge -- node scripts/validate.cjs`.

The judging container is Linux: the replica (and CI on native ARM64) is the source of truth, not a Windows run.

## Testing

*(Test layers and evidence: Task 1.17 and Phase 7.)*

## Limitations

*(Threat-model limits: Task 1.17 and Task 7.5.)*
