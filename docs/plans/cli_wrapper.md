# Plan & Prompt: KIG Dashboard CLI Command (`node kig.cjs dashboard`)

**Project:** Key Identity Guard (KIG) — DevForge Track 4 ("Trust, but verify")  
**Target Modules:** `src/cli/dashboard.cjs` + registration in `src/cli/main.cjs` (invoked as `node kig.cjs dashboard`)  
**Status:** Refined specification aligned with KIG's CommonJS `.cjs` CLI architecture, `node:http` conventions, and security boundaries  
**Guardrails:** Do **not** modify `dashboard.html` functionality, `evidence/` files, or Round 1 adapter (`track4_service.cjs`). Do **not** commit or push unless explicitly instructed.

---

## 1. Alignment with KIG's Existing CLI Architecture

Instead of introducing a separate ESM entry point (`kig.mjs`), implement the dashboard server as a first-class subcommand of the existing CommonJS CLI ([kig.cjs](../../kig.cjs) → [src/cli/main.cjs](../../src/cli/main.cjs)):

- **Module format:** CommonJS (`.cjs`) with `'use strict';` and `// @ts-check`, matching every module in `src/cli/`.
- **Zero runtime dependencies:** Use only Node.js `24.11.1` built-in modules (`node:http`, `node:fs`, `node:path`, `node:os`, `node:child_process`, `node:util`).
- **Router contract:** Export `{ name: 'dashboard', describe, usage, options, run({ values, positionals, io }) }` from `src/cli/dashboard.cjs` and register it in `COMMANDS` inside `src/cli/main.cjs`.
- **Exit codes:** Follow `src/cli/main.cjs` conventions — `0` success, `1` operational/runtime failure (`CommandError`), `2` invalid CLI flags/arguments (`UsageError`).
- **Round 1 isolation:** Never `require` `src/cli/dashboard.cjs` from `track4_service.cjs` or `src/adapter/*`.

---

## 2. Supported CLI Interface

```text
node kig.cjs dashboard [options]
```

| Flag | Type | Default | Behavior |
|---|---|---|---|
| *(none)* | — | — | Starts local HTTP server on `127.0.0.1:5410`, verifies evidence dir, writes PID state, opens browser |
| `--port <port>` | `string` | `5410` | Custom TCP port (`1..65535`); invalid values throw `UsageError` (exit `2`) |
| `--no-open` | `boolean` | `false` | Starts server without launching the system browser |
| `--evidence <dir>` | `string` | `evidence/final-5410c49` | Evidence directory exposed read-only at `/evidence/*` |
| `--status` | `boolean` | `false` | Checks PID file & liveness (`process.kill(pid, 0)` + optional `/health` probe); reports running URL/PID or stopped |
| `--stop` | `boolean` | `false` | Sends `SIGTERM` (and cleans stale PID file if already exited) to the running dashboard server |
| `--help` | `boolean` | `false` | Displays KIG-formatted usage and flag reference (handled by `src/cli/main.cjs`) |

Mutually exclusive flags (e.g., `--status` with `--stop`) must throw `UsageError` (exit `2`).

---

## 3. Local HTTP Server & Security Boundaries

### Loopback-Only Binding
- Bind exclusively to `127.0.0.1` (never `0.0.0.0` or `::`).
- Default port: `5410` (referencing commit `5410c49`).

### Strict Route & File Allowlist (Directory Traversal Protection)
Only `GET` and `HEAD` requests are permitted (all other methods return `405 Method Not Allowed`).

1. **`GET /` or `GET /dashboard.html`:**
   - Serves `<repoRoot>/dashboard.html` with `Content-Type: text/html; charset=utf-8` and `Cache-Control: no-store`.
   - If `dashboard.html` is missing, return a clean `404` or exit `1` on startup with an actionable `CommandError`.
2. **`GET /evidence/<filename>`:**
   - Serves read-only files from the configured evidence directory (default `<repoRoot>/evidence/final-5410c49/`).
   - **Traversal & escape protection:**
     - Decode URI component safely (`try { decodeURIComponent(...) } catch -> 400`).
     - Reject null bytes (`\0`), backslashes, and `..` segments.
     - Resolve real/normalized path with `path.resolve(evidenceDir, relPath)` and verify `path.relative(evidenceDir, resolved)` does not start with `..` and is not `path.isAbsolute(...)`.
     - Restrict to safe read-only extensions: `.json` (`application/json; charset=utf-8`), `.txt`/`.md` (`text/plain; charset=utf-8`).
     - Never serve `src/`, `KIG_HOME` keystores, `registry.db`, `.git/`, or arbitrary host paths.
3. **`GET /health`:**
   - Returns `200` JSON: `{ "ok": true, "service": "kig-dashboard", "pid": <pid>, "port": <port>, "evidence_dir": <relPath>, "evidence_present": <boolean> }`.
4. **All other paths:** `404 Not Found` (no directory listings, no stack traces).

---

## 4. Process Lifecycle, PID Tracking & Browser Launch

### PID State File
- Store PID metadata at `path.join(os.tmpdir(), 'kig-dashboard.pid.json')` (or under `KIG_HOME` if explicitly desired, with `os.tmpdir()` as the safe default that never pollutes the repo working tree):
  ```json
  {
    "pid": 12345,
    "host": "127.0.0.1",
    "port": 5410,
    "evidenceDir": "evidence/final-5410c49",
    "startedAt": "2026-11-27T08:00:00.000Z"
  }
  ```
- **Stale PID handling:** Before reporting `running` or refusing startup, check liveness with `process.kill(pid, 0)`. If `ESRCH`, remove the stale PID file and proceed cleanly.
- **Port conflict handling:** On `EADDRINUSE`, print a clear KIG-branded `CommandError` explaining that port `<port>` is already in use and suggesting `--port <other>` or `node kig.cjs dashboard --stop`.

### Graceful Shutdown
- Handle `SIGINT` and `SIGTERM`:
  1. Call `server.close()` (and `server.closeAllConnections()` if available in Node 24 so keep-alive sockets don't hang exit).
  2. Remove the PID file only if it still belongs to `process.pid`.
  3. Print a clean shutdown line and exit `0`.

### Safe Cross-Platform Browser Opening (unless `--no-open`)
Construct the URL solely from validated `127.0.0.1` and numeric `port` (`http://127.0.0.1:${port}/`), and launch detached with `stdio: 'ignore'` + `child.unref()`:
- `win32`: `spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore', windowsHide: true })`
- `darwin`: `spawn('open', [url], { detached: true, stdio: 'ignore' })`
- `linux`: `spawn('xdg-open', [url], { detached: true, stdio: 'ignore' })`

---

## 5. Terminal Output & Evidence Check

- On startup, verify whether `dashboard.html` and `evidence/final-5410c49/` exist:
  - Missing `dashboard.html` → fail fast with `CommandError` (exit `1`).
  - Missing `evidence/final-5410c49/` → print a clear `[WARN]` notice that the dashboard will rely on embedded fallback data or drag-and-drop JSON loading.
- Print concise, KIG-branded status lines:
  ```text
  [KIG] Trust & Verification Console
  [KIG] URL:      http://127.0.0.1:5410
  [KIG] Evidence: evidence/final-5410c49 (verified)
  [KIG] PID:      12345
  [KIG] Press Ctrl+C to stop, or run: node kig.cjs dashboard --stop
  ```

---

## 6. Verification Plan (`tests/unit/cli-dashboard.test.cjs`)

Verify with `node --test`:
1. `node kig.cjs dashboard --help` exits `0` and prints usage.
2. `node kig.cjs dashboard --status` reports stopped cleanly when no server is running.
3. Invalid `--port` (e.g., `abc`, `0`, `70000`) exits `2` (`UsageError`).
4. Server starts on an available port with `--no-open`:
   - `GET /` returns `200` (`text/html`).
   - `GET /health` returns `200` JSON with `ok: true`.
   - `GET /evidence/demo.json` returns `200` (`application/json`) when present.
   - Traversal attempts (`/evidence/../package.json`, `/evidence/%2e%2e/kig.cjs`, `/src/core/policy.cjs`) return `400`/`403`/`404`.
5. `node kig.cjs dashboard --status` reports running PID/URL, and `node kig.cjs dashboard --stop` terminates the server and removes the PID file.
