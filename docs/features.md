# Key Identity Guard — Feature Specification

**Track:** 4 — Trust, but verify
**Document:** features.md
**Status:** Draft v0.5 — judging container corrected to x86-64 (was ARM). v0.4: organizer answers folded in (x86-64 judging container, Round 1 = adapter only with hidden tests/exploits, Round 2 = CLI, Node 24.11.1 confirmed, WAL works); input-channel threat scope (D-15); strict contract response shapes (D-16); adapter self-monitoring moved to P0 (P0-10). v0.3: audit findings folded in.
**Purpose:** Define observable product behaviour before designing the architecture.

**How to read v0.3.** Feature IDs are unchanged from v0.1 so existing cross-references still work. Items changed in v0.2 are tagged **[CHG]**, new in v0.2 **[NEW]**; items changed or added in v0.3 are tagged **[v0.3]**, in v0.4 **[v0.4]**, in v0.5 **[v0.5]**.

**[v0.5] Correction (2026-11-26): the organizers corrected the judging container to x86-64 (amd64), not ARM.** Everything below that said ARM64 now says x86-64; the replica and CI were switched to linux/amd64. No product code changed (pure JavaScript, no native modules). Section 0 is the decision record: what was decided, on what evidence, and what is still unverified. Nothing in Section 0 is a claim about the organizer's container; every measurement was taken in a stand-in environment described in Appendix A. Technology/runtime *details* (which built-in does what, module layout) belong in `architecture.md`; this document keeps only the runtime *decision* and its evidence.

---

## 0. Decision record (v0.2)

### 0.1 Runtime: Node.js 24.11.1, CommonJS, zero npm dependencies — CONFIRMED

v0.1 made Node provisional pending a spike. The spike was run in the exact Node `v24.11.1` binary (OpenSSL 3.5.4, SQLite 3.50.4). Result summary (full table in Appendix A):

| Gate from v0.1 §2.2 | Result in Node 24.11.1 |
|---|---|
| Raw-public ML-KEM-768 import, encapsulate, decapsulate | PASS (pk 1184 B, ct 1088 B, ss 32 B) |
| ML-DSA-65 keygen / sign / verify / tamper rejection | PASS (pk 1952 B, sig 3309 B); context-string domain separation works |
| AES-256-GCM encrypt/decrypt, AAD tamper rejection | PASS |
| HKDF-SHA-256 | PASS (RFC 5869 test case 1 reproduced) |
| HMAC-SHA-256 | PASS |
| SQLite writes across fresh processes | PASS (8 concurrent processes × 25 chained appends → 200 rows, chain valid) |
| **[NEW]** Interop with the toolkit's own `pqcrypto==0.4.0` | PASS both directions (25/25 and 10/10), including the exact `HMAC-SHA-256(shared_secret, challenge ‖ body)` proof construction |
| **[NEW]** Crash atomicity | PASS: `kill -9` mid-transaction left no partial row and a valid chain |

**Why not Python (the alternative argued for in the stack discussion).** Python + `pqcrypto==0.4.0` covers ML-KEM, ML-DSA and SLH-DSA (verified: also Falcon), plus stdlib `hmac`, `hashlib`, `sqlite3`, `fcntl`. It has **no AEAD and no X25519**, and the standard library has neither. AEAD is needed by P1-02 (file encryption, DEK envelopes), P1-07 (backups) and P1-12 to P1-15 (messaging) — roughly half of P1. Every Python workaround has a cost the toolkit does not cover:

| Python workaround | Problem |
|---|---|
| Organizer-approved `cryptography` package | The adapter contract lists only `pqcrypto==0.4.0`. Unconfirmed; cannot be assumed. |
| Vendored `cryptography` wheel in the repo | Binary wheel tied to CPU architecture and ABI of a container we cannot inspect. |
| Pure-Python AEAD | Not constant-time; and "custom cryptographic primitives presented as secure" is a disqualification clause. |
| `ctypes` into the container's `libcrypto` | Our own FFI glue around the most security-critical call; fragile and unreviewable. |

A second, measured difference: given a 1184-byte ML-KEM public key consisting of `0xFF` bytes (coefficients ≥ q, which fails the FIPS 203 §7.2 encapsulation-key check), `pqcrypto` encapsulates without complaint, while Node rejects the key at import with `DataError`. The adapter must validate recipient-supplied keys (P0-07/P0-08), and Node does that check for us.

**[v0.3]** A third, measured difference: `pqcrypto.sign.ml_dsa_65.sign(secret_key, message)` has **no context parameter**, so the context-string domain separation P1-01 relies on would have to be imitated with message prefixes. Node's ML-DSA accepts `context` natively (a context signature fails verification under a different context and under no context). In a stock Python 3.12 + `pqcrypto` environment, `cryptography`, `Crypto` (PyCryptodome) and `nacl` are all absent; only `cffi` is importable (a `pqcrypto` dependency), which still means hand-written FFI. Node 24.11.1 also exposes FIPS 205 SLH-DSA through the KeyObject API (not through WebCrypto); not needed, noted for completeness.

**Where the Python case was right, and what v0.2 keeps from it.** The provided Python starter exists, but a Node starter and demo exist too (`starters/node`, `demo/node`); the adapter is thin transport either way. Process-per-request latency favours Python slightly (measured p50 18.8 ms vs 26.0 ms for a `protected_read`-equivalent, empty-process 8.9 vs 15.6 ms); both are far below the validator's 8-second timeout and the difference is reportable, not decisive. The real cost of Node is team familiarity: keep the codebase small, CommonJS, no build step, `// @ts-check` + JSDoc for editor-level type checking if the team wants it.

**Reversal condition (the only one).** Switch to Python only if organizers confirm that the judging image does not provide Node 24.11.1 with these WebCrypto algorithms, **and** confirm that a vetted AEAD package is present for Python. Absent both, Node is locked.

### 0.2 Residual risks of the Node choice (accepted, with mitigations)

| Risk | Mitigation |
|---|---|
| Web Crypto "Modern Algorithms" (ML-KEM, ML-DSA) are documented as *Stability 1.1 — Active development*; ML-DSA arrived in Node 24.7.0 and ML-KEM in 24.8.0 per the Node changelog | The judging runtime is pinned to 24.11.1. All crypto calls go through one module, `src/crypto/provider.cjs`, so API drift is isolated. `kig compat` (P0-02) re-runs the spike inside the pinned image. |
| `node:sqlite` is *Stability 1.1* in 24.11.1 (it became 1.2 release-candidate in 24.15.0, which we do not run) | Use only `DatabaseSync`, `exec`, `prepare`, `run`, `get`, `all`, and the `timeout` option — all exercised in the spike. |
| `ExperimentalWarning` text printed to stderr | `process.removeAllListeners('warning')` at process start. Verified: stderr is 0 bytes. |
| **[v0.3]** Concurrent first opens of a *new* database: `PRAGMA journal_mode=WAL` threw `database is locked` in 1 of 4 runs (8 processes), not covered by the busy timeout | WAL is set only by `setup`; other operations never change journal mode; bounded retry on busy (P0-03). |
| **[v0.3]** `Buffer.from(s, 'base64')` is lenient (accepts URL-safe alphabet, silently skips junk) | Strict standard-Base64 validator before decoding (P0-07). |
| **[v0.3]** Plain JS objects indexed by client strings misbehave for `__proto__`, `constructor`, … | Client-keyed data lives in `Map`/`Set` or SQLite rows, never plain objects (P0-08). |
| JavaScript cannot guarantee memory zeroisation | Best-effort buffer clearing; stated as a limit in the threat model (already in P1-14). |
| ML-KEM comes from OpenSSL 3.5 in Node but from PQClean in `pqcrypto` | Interop is **verified**, both directions (Appendix A). Re-run in CI. |

### 0.3 Semantic decisions that change v0.1

| ID | Decision | Reason |
|---|---|---|
| D-01 | **`setup` replaces adapter state (new "generation"); it does not refuse or merge.** The audit log, the monotonic epoch counter and key history are append-only across generations. | v0.1 P0-04 said not to overwrite on a second `setup`. The contract says `setup` "initialize[s] from the supplied data", the toolkit's mock says "Setup resets practice state", and the official worker may run several scenarios in one container ("a fresh container starts empty" implies a container can serve more than one call sequence). A refuse-or-ignore `setup` would fail every later scenario. A replace-with-generation rule is safe either way. Flagged as open question Q1. |
| D-02 | **`audit` for a reused `request_id` returns the most recent event for that ID within the current setup generation**; earlier events are never overwritten. **[v0.4]** The response is exactly `{"request_id","decision"}` (D-16); attempt counts and sequence numbers are visible only in the audit log and CLI. **[v0.3]** Events from earlier generations stay in the chain for verification but are not returned by `audit` (an ID unknown in the current generation gets the D-03 response). | Matches what a mock-validated harness expects (last write), while keeping every attempt as a distinct event (v0.1 P0-06). Generation scoping stops a request ID from a previous scenario returning a stale decision in a later one. |
| D-03 | **`audit` for an unknown `request_id` returns `{"request_id":…,"decision":"deny"}`**, never a bare error object. **[v0.4]** No `recorded` field (D-16); the fact that no event existed is written to the audit log as an `audit_lookup_miss` event. | `validate.py` rejects any `audit` response whose `decision` is not `allow`/`deny` as a *format* failure (exit 3). Deny-by-default is also consistent. Organizers left response shapes to us (Q2 answered). |
| D-04 | **All client-supplied strings are stored as their JSON string encoding** (`JSON.stringify(value)`), never as raw SQLite TEXT. | Measured: in `node:sqlite`, a lone-surrogate identifier (`"\ud800"`) is silently stored as U+FFFD and then **collides** with a genuine `"\ufffd"` identifier (primary-key conflict); an identifier with an embedded NUL does not round-trip. `JSON.stringify` is injective for every JS string (escapes lone surrogates and NUL). Eleven edge-case identifiers (lone surrogates, NUL, newline-plus-fake-JSON, path traversal, SQL text, emoji, empty) all stored as distinct rows and round-tripped exactly. This fixes identity confusion without rejecting any "opaque" identifier the worker might send. |
| D-05 | **Session resumption is "not supported"** (status `not supported` in the evidence sheet). P1-16 moves to P2-04. A cheap negative test replaces it: an old session ID or an old session key presented after revocation is rejected. | The brief says "if supported"; the evidence sheet defines `not supported`. A resumption mechanism is a classic critical finding if wrong and every finding costs 1–10 points in a 25-point category. |
| D-06 | **Cutoff is defined by control-plane epoch, not wall-clock time.** The 30-second grace window is node-local, measured on a monotonic clock from the moment that node applies the cutoff entry, and covers only transfers already authenticated before cutoff. | Removes cross-node clock skew from the security boundary. |
| D-07 | **Backups are wrapped to an operator recovery ML-KEM-768 key** (private half held offline, supplied at restore time). | v0.1 required "encrypted key material" in backups but never said under which key. A key stored next to the backup protects nothing. |
| D-08 | **Audit hash input is a fixed-schema, length-prefixed binary encoding**, not RFC 8785 JSON canonicalisation. | Avoids canonical-JSON edge cases (number formatting, Unicode normalisation) for arbitrary identifiers. JSON is used for display and export only. v0.1 allowed either; this fixes the choice. |
| D-09 | **Lateral-movement detection is a small rule set, not a single "≥3 unseen edges" rule** (see P1-10). **[v0.3]** "Unseen" is defined against a warm-up baseline, never a cold start, and denials explained by a recent revocation are context, not movement. | The ≥3 threshold is exactly the shape of the 22-event practice set; it would miss two-edge attacks and any single successful novel edge into a sensitive service. Simulated on the practice data: a per-actor cold-start baseline flags `evt-007`–`evt-009` (routine sign-in included), and a deny-burst threshold of 2 flags the routine post-revocation denials `evt-017`/`evt-018`. |
| D-10 | **AES-GCM nonce policy:** session traffic uses deterministic nonces (direction + counter) from per-direction keys; DEK and envelope encryptions use one fresh random 96-bit nonce per fresh key. No key encrypts more than 2^32 messages with random nonces. | NIST SP 800-38D §8.3 limits random-IV use to 2^32 invocations per key; nonce reuse in GCM breaks confidentiality and integrity. |
| D-11 | **Optional hybrid (P2-02) uses X-Wing as specified, or is not built.** | X-Wing (X25519 + ML-KEM-768, SHA3-256 combiner) is an active CFRG Internet-Draft, not a finished standard, so it stays P2. Node 24.11.1 has X25519 and SHA3-256, so it is buildable if time remains. |
| D-12 | **Scope is sequenced into vertical slices with a hard P0-first gate** (Section 9). | See Section 9 and the objections listed there. |
| D-13 **[v0.3]** | **Exit-code policy is per operation; a denial is never a crash.** `read`/`protected_read` internal error → `{"decision":"deny"}`, exit 0; `audit` → D-03 shape, exit 0; unknown `op` → `{"error":"unsupported_operation"}`, exit 0; `revoke` → non-zero exit, no acknowledgement; `setup` → non-zero unless quarantine and re-initialisation succeeded. **[v0.4]** Invalid *input* is not an internal error: unparseable stdin, invalid UTF-8, oversize or non-object requests, and invalid `setup`/`revoke` fields → `{"error":"invalid_request"}`, exit 0, state untouched; invalid `read`/`protected_read`/`audit` fields → their deny shape, exit 0. Full table: `architecture.md` §5.6. | `validate.py` treats any non-zero exit as a fatal `setup` failure and stops all further checks. Only `revoke` (an unpersisted change must not be acknowledged) and a failed `setup` justify that. |
| D-14 **[v0.3, CHG v0.4]** | **The adapter stores bodies in plaintext SQLite and makes no at-rest confidentiality claim.** The adapter has no secret that does not live in the same `TRACK4_STATE_DIR`, so encrypting bodies there would be theatre; under D-15 the state directory is outside the Round 1 attacker's reach anyway. `key_material` is never used as a key (P0-04). At-rest encryption with keys held outside the service (P1-02) is a demo/CLI capability. | Same reasoning as D-07: a key stored next to the ciphertext protects nothing from someone who can read both. Over-claiming here is a Threat-Model & Honesty deduction. |
| D-15 **[v0.4]** | **Round 1 threat scope is the input channel.** The adapter's attacker controls the JSON on stdin (any value, any size up to the cap, any number of sequential or parallel invocations) and observes stdout, stderr, exit codes and timing. An attacker who can read or write `TRACK4_STATE_DIR` or the repository between invocations is **out of scope for the adapter** and is stated as such in the threat model. Consequences: no adapter at-rest encryption (D-14); no audit-chain verification on every adapter start (`kig verify-log` does it offline); fail-closed handling of a corrupt/missing database stays, because it is also crash safety. | Every hint in the toolkit points to the input channel: the contract's rules are about identifiers, diagnostics and disclosure; `validate.py` and its tests probe only leaks (including nested), marker exposure, error text, exit codes, timeouts and stream limits; the demo README says actor values are trusted inputs. A state-directory attacker cannot be stopped by anything inside the container (read-only root, no external secret), so effort there has a low ceiling. |
| D-16 **[v0.4]** | **Adapter responses use exactly the contract shapes, no extra fields.** `setup` → `{"ready":true}`; `read` → `{"decision":"allow","body":…}` or `{"decision":"deny"}`; `revoke` → `{}`; `audit` → `{"request_id":…,"decision":…}`; `protected_read` → `{"ciphertext":…,"proof":…}` or `{"decision":"deny"}`; unsupported → `{"error":"unsupported_operation"}`. | Hidden tests may compare responses strictly; extra fields add risk and can leak policy structure. Rich detail lives in the audit log and CLI. |
| D-17 **[v0.4]** | **Two rounds, two surfaces.** Round 1 (automated: hidden test cases and exploits) runs only the repository-root adapter on an **x86-64 (amd64)** Linux container with Node 24.11.1 **[v0.5: corrected from ARM]**. Round 2 (judges) is presented through our `kig` CLI. | Organizer answers, 2026-11-26. S1 is the Round 1 deliverable; P1 is primarily Round 2 evidence. |

---

## 1. Product definition

### 1.1 Problem we are solving
Key Identity Guard (KIG) protects a sensitive file shared between a file owner and authorised peers. It must continue to enforce access decisions as devices, identities, keys and permissions change. It also gives an operator a verifiable record of those decisions and explains suspicious access patterns across services.

### 1.2 Main demonstration story
1. An owner enrolls a device and creates a protected file.
2. The file is encrypted and shared with an authorised peer.
3. The owner performs normal reads; the peer retains its own authorised access.
4. The owner's device is reported lost.
5. The lost device is revoked. The revocation reaches all simulated service nodes.
6. The owner enrolls a replacement device. The file's access material is re-keyed for the replacement and remaining authorised peers; peers do not lose access.
7. Requests from the revoked device are denied, including attempts using an old key, an old session ID or an old session key.
8. Every access, denial, key-state change and administrative action is written to a tamper-evident audit log.
9. The operator verifies the log offline and sees explainable alerts for suspicious privilege changes or unusual service access.
10. We deliberately interrupt a key rotation, damage a backup, reorder events and drop/reorder message chunks to demonstrate recovery and failure handling.

### 1.3 Primary security claim
After a device credential is revoked and the revocation has been enforced by every participating node, that device cannot obtain new protected file content or establish a new protected session. Every connection performs a full authenticated handshake; there is no resumption path (D-05). Other authorised devices retain access. The operator can verify the integrity of recorded security events against a trusted ML-DSA checkpoint.

This claim concerns future access. Revocation cannot erase plaintext or keys that a lost device legitimately obtained before it was reported lost. That limitation must appear in the threat model and demo narration.

### 1.4 Product principles
- Use standard, vetted cryptographic implementations; do not implement cryptographic primitives ourselves. Composing vetted primitives (HKDF + AES-GCM + ML-KEM) is our code and is tested with published vectors where they exist.
- Treat identity authentication, authorisation, key establishment, encryption and audit as separate responsibilities.
- Deny by default. A missing, stale, corrupt or unverifiable security state must not produce an allow decision.
- Make state changes durable before acknowledging them. **[CHG]** A decision and the audit event that records it commit in the same transaction.
- Make every important security claim reproducible through an attack test or measured evidence.
- Keep the organizer adapter, the richer demo and the CLI connected to the same core logic; do not create separate implementations of security rules.
- Do not use AI/ML components. Detection is deterministic, explainable and based on rules/statistics/graphs.

---

## 2. Priority definitions and project boundary

| Priority | Meaning | Release objective |
|---|---|---|
| P0 — Gate | Required for the judging adapter and its protected-read check | Clean adapter contract, persistence, correct access decisions, protected-read interoperability, local validator pass |
| P1 — Core track coverage | Implements the twelve security goals and provides evidence for Stage 1/desk review | Working end-to-end story, rotation, revocation, recovery, audit, detection, messaging and metrics |
| P2 — Polish / stretch | Improves operator experience and demo quality after P0/P1 are sound | Dashboard, extra visualisations, optional extensions |

### 2.1 Two execution surfaces, one security core
1. **Judging adapter:** the exact operations and input/output contract required by the Track 4 toolkit. One JSON request per process; no continuously running server.
2. **Demonstration/operator interface:** `kig` CLI commands and a local three-node simulation (three separately identified node processes, each with its own state directory) that exercise capabilities the adapter does not expose.

Both surfaces call the same policy, key-state, audit and detection modules.

### 2.2 Runtime (resolved — see 0.1)
Node.js 24.11.1, CommonJS adapter `track4_service.cjs`, zero npm dependencies. Built-in modules only on the judging path: `node:crypto` (including `crypto.webcrypto`), `node:sqlite`, `node:fs`, `node:path`, `node:os`.

**[v0.4]** Repository layout, tech stack and the complete request flows are defined in `architecture.md` (§2, §3, §5). The root adapter is the toolkit starter **adapted** in three places (warning suppression, bounded fatal-UTF-8 stdin read, `invalid_request` with exit 0 instead of exit 1 for unparseable input, D-13); the transport contract is otherwise unchanged.
Dev/test-only dependency: Python 3.12 + `pqcrypto==0.4.0`, used solely by the cross-implementation interop test. It is not on the judging path and the test skips with a visible notice if absent.

---

## 3. P0 — judging adapter and minimum protected-resource workflow

### P0-01. Exact adapter entry point
- Exactly one supported adapter at the repository root: `track4_service.cjs`.
- Read one UTF-8 JSON object from stdin through EOF, dispatch once, write exactly one JSON object to stdout, exit.
- Keep stdout machine-readable. Diagnostics go to stderr and must never include request secrets, file contents, private keys, shared secrets or raw exception traces.
- Do not leave background child processes running. **[NEW]** The validator treats lingering output streams as a setup failure.
- **[NEW]** `process.removeAllListeners('warning')` first thing, so experimental-feature warnings never reach stderr.
- **[v0.3]** Per-operation failure handling follows D-13: internal errors in `read`/`protected_read`/`audit` produce a deny-shaped JSON response and exit 0; only `revoke` and a failed `setup` exit non-zero. A top-level handler (as in the toolkit starter) remains as the last resort for truly unexpected crashes: generic stderr line, non-zero exit. Exceptions must never turn into an `allow`.
- **[v0.3, CHG v0.4]** A request with an unknown `op` returns `{"error":"unsupported_operation"}` with exit 0 (the toolkit demo's shape); unparseable, non-UTF-8, oversize or non-object input returns `{"error":"invalid_request"}` with exit 0 (D-13).
- Implement `setup`, `read`, `revoke`, `audit`, `protected_read` with the contract's request/response semantics.

Acceptance: `validate.py` can start the root adapter repeatedly; every valid request produces one parseable JSON object; stderr is empty on the success path; **[v0.3]** an injected internal error in `read`, `protected_read` and `audit` yields deny/exit 0, and in `revoke` yields non-zero exit with no state change.

### P0-02. Runtime and dependency compatibility
- Target the exact organizer runtime: Node.js 24.11.1 on offline Linux, **[v0.5] x86-64 (amd64)** (corrected from ARM64). Appendix A measurements were taken on x86-64, the judging architecture; `kig compat` and the brief's performance numbers are re-run in the x86-64 replica and CI.
- **[CHG]** `kig compat` re-runs the Appendix-A spike (ML-KEM raw-public import/encaps/decaps, ML-DSA-65 sign/verify with context, AES-GCM, HKDF with the RFC 5869 vector, HMAC, SQLite writes from separate processes, `kill -9` atomicity) and prints PASS/FAIL without secret material.
- CI runs `kig compat` and the full test suite inside a `node:24.11.1` container, not only on developer machines. **[v0.5]** CI runs on GitHub `ubuntu-24.04` (x86-64), both plain and inside the judging replica (read-only root, offline, non-root).
- Do not assume the organizer installs anything from `package.json`; there is no `package.json` dependency list to install.

Acceptance: compatibility test passes in the pinned container on x86-64.

### P0-03. Persistent state across process invocations
- Use `TRACK4_STATE_DIR` when supplied, otherwise `os.tmpdir()`. The directory is created if missing, by `setup` or **[v0.4]** by a `revoke` that arrives before any `setup` (a revocation must always be persisted before it is acknowledged).
- Durable state in SQLite under that directory. **[CHG]** Connection settings: `timeout` (busy timeout) ≥ 5000 ms; `PRAGMA synchronous=FULL`; `PRAGMA foreign_keys=ON`; `PRAGMA user_version` schema check; `STRICT` tables.
- **[v0.3] Journal mode is set once, by `setup` only:** `PRAGMA journal_mode=WAL` with a check that the returned mode is `wal`, falling back to `DELETE` if not (shared-memory files are not guaranteed on every filesystem). The mode persists in the database file; all other operations only *read* it and never change it. Reason (measured): when several processes open a new database concurrently, the journal-mode switch itself can throw `database is locked` despite the busy timeout (1 of 4 runs, one of eight processes lost).
- **[v0.3] Bounded retry on busy:** opening the database and the first statement are retried on `SQLITE_BUSY`/`database is locked` (3 attempts, small random jitter). If still locked: `read`/`protected_read`/`audit` fail closed per D-13 (deny, exit 0); `revoke` exits non-zero without acknowledgement.
- **[CHG]** Every mutation runs in `BEGIN IMMEDIATE … COMMIT`. This is what serialises concurrent processes and keeps the audit hash chain linear (measured: 8 processes × 25 appends, 200 rows, chain valid).
- A corrupt, missing or incompatible existing state fails closed. **[CHG]** Measured: a corrupted database file makes `node:sqlite` throw at first use; the adapter must catch this and respond per operation (D-13): `read`/`protected_read` → `{"decision":"deny"}`; `audit` → D-03 shape; `revoke` → non-zero exit and **no acknowledgement** (it could not be persisted); `setup` → quarantine the corrupt file (rename, never delete) and initialise a new generation.
- Keep the database and SQLite sidecar files in the writable state directory, never in the read-only repository root.

Acceptance: setup/read/revoke/audit work across separately started processes; an interrupted transaction exposes no partial state; a fresh directory initialises independently; concurrent-process test passes **both** on a database already in WAL mode **and [v0.3] on a cold start** (8 processes issuing their first operation against a just-set-up database, repeated ≥ 20 times, zero non-zero exits on read/audit, zero lost revocations).

### P0-04. `setup` **[CHG]**
- Initialise the synthetic assets, owner mapping and `disabled` list exactly as supplied. Per D-01, this **replaces** adapter-visible state with a new generation. The audit log, the global epoch counter and any key history are append-only across generations and are never reset. Record a `setup` audit event for each generation.
- Generate required deployment keys with the CSPRNG (`crypto.randomBytes` / WebCrypto `generateKey`); never hard-code keys.
- `key_material` is a synthetic sensitive marker. Do not print, log, persist or use it as a root key or KDF input. It is not a trusted source of entropy. **[NEW]** Test: scan stdout, stderr, the whole state directory (including WAL/journal files) and any export for the marker after a full scenario; it must not appear.
- Return `{"ready":true}` only after the new generation is committed.
- A `setup` that follows an unusable state (D-01, P0-03) quarantines it and proceeds.

Acceptance: `{"ready":true}` only after commit; two consecutive `setup` calls with *different* owners/contents in the same state directory both result in the second dataset being served correctly; the marker is absent from every output and every persisted byte.

### P0-05. `read` and `revoke`
- `read` is deny-by-default. Check the supplied actor's disabled/revoked state before checking ownership.
- Allowed read returns `{"decision":"allow","body":"<exact stored body>"}`. Denied read returns `{"decision":"deny"}` with no body, ciphertext, proof, rule detail, debug value or other protected content. **[CHG]** The adapter response contains no `rule` field (the toolkit's demo returns one; it is not required, and it reveals policy structure). The rule ID is recorded in the audit event instead.
- Unknown actor, unknown asset, malformed-but-parseable IDs → deny, never an error.
- `revoke` persists the actor revocation before acknowledging; returns `{}`. **[NEW]** It is idempotent and works for an actor not named in `setup`.
- Revoking one actor does not affect another actor's resources or permissions.
- **[CHG]** Identifiers are opaque. Store them via D-04 (JSON-string encoding), never as filesystem paths, SQL fragments, log delimiters or raw TEXT.
- **[v0.3]** Never index a plain JS object with a client-supplied string. Immediately after parsing, `owners`/`contents` become `Map`s (or SQLite rows) and `disabled` a `Set`; lookups use `Map.get`/`Set.has`. Reason (measured): assigning `obj["__proto__"] = x` does not create a key, and `obj["constructor"]` returns `Function` without an own-property check. The toolkit's own demo uses `Object.defineProperty` precisely to survive `request_id = "__proto__"`, which suggests such identifiers are expected in testing.
- **[v0.3]** Actors in `setup.disabled` are treated exactly like revoked actors.

Interface limit (must appear in the threat model): the adapter's `actor` is a trusted input from the judging worker; `read` and `revoke` carry no device signature or authentication proof. The adapter demonstrates policy enforcement for a supplied actor; it cannot prove that a caller owns that identity. Device authentication is the P1 demo capability.

Acceptance: all public lost-device checks pass, including no content leakage on denial and peer access intact.

### P0-06. `audit` **[CHG]**
- Durable decision recorded for every `read` and `protected_read`: request ID, actor, asset, decision, rule ID, event sequence — all stored via D-04. **[v0.4]** The contract's `protected_read` carries no `request_id`; an optional `request_id` is accepted and recorded if present, otherwise the event is recorded with a null request ID (and so cannot be returned by `audit`).
- **[v0.4]** D-04 also applies to asset **bodies**: they are stored JSON-encoded so that bodies containing lone surrogates or NUL round-trip exactly.
- `audit(request_id)` returns `{"request_id":…,"decision":…}` for the **most recent** event with that ID **in the current setup generation** (D-02, [v0.3]); **[v0.4]** no other fields (D-16). Unknown ID (including one known only in an earlier generation) → D-03.
- A reused `request_id` creates a new event with a new sequence number; earlier events are never updated or deleted.
- Audit events live in an append-only table, separate from mutable current-state rows. **[NEW]** Enforce with SQLite triggers that `RAISE(ABORT)` on `UPDATE`/`DELETE` of the audit table, so an application bug cannot rewrite history (a defence-in-depth measure, not a defence against someone with file access — see P1-08).
- The decision row and its audit event commit in the same transaction.

Acceptance: audit correlates with the actual denied read; a reused request ID cannot erase or rewrite prior evidence; a unit test attempts `UPDATE audit …` and `DELETE FROM audit` and both fail.

### P0-07. `protected_read` interoperability
Pipeline order, which must not be reordered:
1. Validate request shape and bounds (strings, lengths, standard Base64; decoded public key length is exactly 1184 bytes). **[v0.3]** Node's Base64 decoder is lenient (measured: it accepts the URL-safe alphabet and silently skips invalid characters), so validate **before** decoding: `typeof s === "string" && s.length % 4 === 0 && /^[A-Za-z0-9+/]*={0,2}$/.test(s) && Buffer.from(s, "base64").toString("base64") === s`. `challenge` must be a string with a fixed maximum length (propose 4 KiB). A failure here is a denial with audit rule `invalid_request`, exit 0.
2. **Authorise first**: actor not revoked, owns/may read the asset. Denied → `{"decision":"deny"}`, no ciphertext, no proof, audit event written.
3. Import the recipient key as ML-KEM-768 `raw-public`. **[NEW]** An invalid key (fails the FIPS 203 encapsulation-key check — measured: Node returns `DataError` for coefficients ≥ q) is treated as a denial with audit rule `invalid_public_key`, exit 0, no ciphertext. It must never crash and never fall through to an allow.
4. Encapsulate with the vetted Node/OpenSSL implementation; return the KEM ciphertext as standard Base64 in `ciphertext`.
5. Return lowercase hex `HMAC-SHA-256(shared_secret, UTF-8(challenge + stored_body))`, no separator, in `proof`.
6. Do not return or persist the shared secret; clear mutable buffers best-effort.

**[NEW]** Cross-implementation test (dev-only): generate keys with `pqcrypto==0.4.0`, call the adapter, decapsulate with `pqcrypto`, recompute the proof. v0.2 spike result: 25/25 match; re-run in CI.
Also: a body containing non-ASCII characters (the spike used `ünïcode ✓`) must produce a matching proof — the HMAC is over UTF-8 bytes.

Scope clarification: this is a KEM/HMAC interoperability check, not end-to-end messaging, recipient binding, replay protection or forward secrecy.

Acceptance: independently reproduced shared secret and proof; a revoked actor cannot obtain a valid proof; invalid public keys are denied without a crash.

### P0-08. Input and output hardening
- Validate top-level JSON type, required properties, types, enum values, Base64 format, key lengths and size bounds. **[NEW]** Cap stdin at a fixed size (propose 4 MiB). Note the local validator rejects any stdout/stderr stream over 64 KiB, so responses must stay under that bound.
- Accept IDs as opaque strings under D-04. **[NEW]** Required negative-test identifiers: lone surrogates (`"\ud800"`, `"\udc00\ud800"`), embedded NUL, newline followed by a fake JSON event, `../../etc/passwd`, a SQL string, a 2 KB string, an emoji, the empty string, **[v0.3]** and the prototype keys `__proto__`, `constructor`, `prototype`, `toString`, `hasOwnProperty` — each used as actor, asset and request_id, including as keys of `owners`/`contents` in `setup`. Each must store as a distinct identity and round-trip exactly (verified in the spike for the v0.2 list).
- **[v0.3]** Strict standard-Base64 validation as in P0-07 step 1; never rely on `Buffer.from(…, "base64")` to reject bad input.
- Parameterised SQL only. JSON-encode user-controlled text; never concatenate it into a line-oriented log.
- Generic error messages; no stack traces, secrets or protected contents in diagnostics.
- A malformed or corrupt security state must not result in an allow.

Acceptance: negative tests cover missing fields, wrong types, long strings, quotes, newlines, path-like IDs, lone surrogates, NUL, prototype-key IDs, invalid and URL-safe Base64, wrong-length keys, oversized requests, unknown `op`, non-object requests, corrupt database, cold-start lock contention and marker leakage.

### P0-10. Adapter self-monitoring **[v0.4]**
Moved forward from P1-17 because Round 1 is adapter-only, and "detecting and responding during the assessment restores up to half the deduction" can only be earned there.
- Every adapter invocation that looks hostile or anomalous writes an **alert event** into the same audit chain, in the same transaction as the decision: rule ID, severity, actor (D-04 encoded), asset, request ID, reason code. Never the offending payload itself beyond a bounded, encoded excerpt.
- Alert rules (deterministic, explainable):
  - `A-REVOKED-RETRY`: a revoked or disabled actor attempts `read`/`protected_read`.
  - `A-CROSS-OWNER`: an actor requests an asset it does not own.
  - `A-INVALID-INPUT`: request fails validation (wrong types, oversize, bad Base64, wrong key length).
  - `A-INVALID-KEY`: ML-KEM public key fails the FIPS 203 import check.
  - `A-HOSTILE-ID`: identifier contains control characters, NUL, lone surrogates, path or prototype-key patterns (still processed normally as an opaque ID; the alert is informational).
  - `A-BURST`: ≥ N denials for the same actor within a sliding window (count from the audit table; N and window configurable, default 5 in 60 s).
  - `A-STATE-FAULT`: database corrupt, missing or locked beyond retries.
- **Response** is limited to what is safe and reversible: the decision itself is already deny; alerts never lock out an actor automatically (an auto-lock is a denial-of-service lever, P1-17). Alerts are visible through `kig alerts` and in the Round 2 demo.
- Alerts never change adapter response shapes (D-16) and never add stdout/stderr output.

Acceptance: each rule fires on its trigger and on nothing in the `validate.py` happy path; alert events are part of the verified audit chain; adapter responses are byte-identical with and without alerting.

### P0-09. Threat-model declaration and validator
- The worker recognises two fields in a root-level `threat-model.json`: `asset` and `boundary`. Use them **only if accurate**. The toolkit's example value `identity-check` for `boundary` is **not** accurate for the adapter, whose actor is an unauthenticated trusted input. Until organizers answer Q3, **omit the file or include only values we can defend in writing**; never copy the example.
- Run the public validator against the submission adapter and preserve the output as evidence (`evidence/validate-<commit>.txt`).
- Maintain additional tests for `protected_read`, since the public validator does not test it.

Acceptance: validator passes; protected-read interop test passes; the threat model states the adapter's identity-authentication limitation.

---

## 4. P1 — core security features mapped to the twelve track goals

### P1-01. Explicit account, device and credential model
- Account separate from device. Device: unique ID, owner account ID, status (pending, active, revoked), enrollment time, credential/key IDs, revocation epoch.
- ML-DSA-65 as the device's long-term identity key. Registered only through the explicit trusted enrollment flow; possession of an unregistered public key establishes nothing.
- Request authentication: verify a fresh, single-use challenge and a signature over a domain-separated transcript (protocol version, operation, account, device, resource, request ID, nonce, key epoch).
- **[NEW]** Domain separation uses the ML-DSA **context** parameter (verified working in Node 24.11.1; a signature made under one context fails under another). Fixed context strings: `kig/v1/request`, `kig/v1/handshake`, `kig/v1/revocation`, `kig/v1/checkpoint`, `kig/v1/backup`.
- **[NEW]** Challenges are stored with an expiry (propose 30 s) and marked used in the same transaction that accepts the request.
- Adapter actor-only mode stays clearly separate from the authenticated demo flow.

Acceptance: an enrolled active device verifies; altered fields, replayed challenges, expired challenges, unknown keys, wrong-context signatures and revoked devices are rejected.

### P1-02. Encrypted file storage and recipient envelopes
- Random per-file DEK. File content under AES-256-GCM; unique nonce per encryption under a key (D-10). Associated data: asset ID, content version, format metadata.
- Store ciphertext, nonce, tag and version metadata; no plaintext.
- One envelope per authorised recipient device: ML-KEM-768 to that device's enrolled KEM public key → HKDF-SHA-256 (info label includes asset ID, recipient account/device, envelope version, suite) → AES-GCM wrap of the DEK; the same fields in associated data.
- The device envelope KEM key is a separate key from the session-handshake KEM key (key purposes never conflated).
- **[NEW]** State honestly in the threat model: at-rest file confidentiality depends on the long-term device KEM key and is **not** forward-secret.
- **[v0.3]** Scope: this envelope model applies to the demo/CLI surface, where device private keys live outside the service's state. The judging adapter has no such external key, so D-14 governs what may be claimed for adapter-stored bodies.
- Explicit key IDs, algorithm identifiers and versions.

Acceptance: storage contains no plaintext; authorised devices recover exact content; altered ciphertext, tag, nonce, recipient metadata or asset metadata fails; an envelope for device A cannot be opened as device B.

### P1-03. Lost-device response and safe re-enrolment
- Revoke the lost device credential, not the account. Advance the revocation epoch; block new requests and new handshakes from that device; invalidate any live sessions of that device.
- **[CHG]** Re-enrolment requires a second factor: approval by a different enrolled device of the same account **or** an operator approval recorded with an approval ID (matches the approval model in `approvals.json`). It is logged. Rationale: "I lost my phone" is the standard social-engineering route.
- Rotate the affected file DEK after device loss, re-encrypt, create envelopes for the replacement and every remaining authorised device.
- Peers keep access (tested). Old DEK/envelopes do not unlock the new ciphertext.
- Record that revocation cannot erase copied content or keys.

Acceptance: lost device denied; replacement allowed after enrollment; peer allowed; old material cannot open new content; re-enrolment without approval refused.

### P1-04. Versioned key rotation (Goal 1) **[CHG]**
- State machine: `ACTIVE(v) → PREPARING(v+1) → STAGED(v+1) → COMMITTED(v+1) → ACTIVE(v+1)`; previous version `RETIRING → RETIRED`.
- Generate and persist the new version before distribution. Stage on every participating node and collect acknowledgements before commit; if not all required nodes staged, postpone or abort before commit. No partially committed active version.
- **Cutoff is an epoch (D-06).** A node rejects new requests carrying the old key version from the moment it applies the cutoff entry. **Grace window:** 30 s, node-local monotonic, applies only to transfers already authenticated before cutoff; new requests using the old version are rejected at/after cutoff even during the window. After the deadline in-flight old-version transfers are terminated.
- Requests identify the key version used. Record activation, cutoff, grace deadline and node acknowledgements without logging key values.

Acceptance: transfers complete during rotation; new requests use the new version; every node rejects new old-version requests after cutoff; in-flight old-version transfers expire at the stated deadline.

### P1-05. Multi-node revocation (Goal 2)
- At least three independently identified node processes with durable local enforcement state (each its own state directory).
- Signed, monotonically increasing revocation epoch/list from the control plane (`kig/v1/revocation` context). Nodes verify signature and monotonic epoch before applying; stale or invalid updates rejected; applied epoch acknowledged durably.
- Push plus periodic pull so a node that missed a push converges.
- Freshness lease: a node that cannot establish sufficiently fresh control-plane state fails closed for protected operations when its lease expires (lease length configurable; reported).
- **[CHG]** Measurement protocol: N ≥ 100 revocations; per-node time from revocation commit to the node's first denial of a probe request and to its durable acknowledgement; report p50, p95 and max per node and for last-node. All nodes run on one host and one monotonic clock; state this limitation. Also run a partition test and report the enforcement bound it demonstrates (lease expiry), not "instant".

Acceptance: all three nodes deny the revoked device; the peer remains authorised; a replayed/stale epoch is rejected; the measurement is reproducible from a seed and a command.

### P1-06. Crash-safe rotation and recovery (Goal 3)
- Persist a rotation journal: PREPARE, STAGE/REWRAP, COMMIT, DISTRIBUTE, COMPLETE. Atomic transitions via SQLite transactions (no homemade storage engine).
- Recovery: no durable commit → abort and keep the last committed version; durable commit → roll forward; never decrease the revocation epoch or restore a revoked credential; verify committed data and envelopes remain readable.
- **[CHG]** Deterministic crash injection by `SIGKILL` of the acting process at named points (after prepare, after stage, immediately before commit, immediately after commit, during distribution). The spike verified that `kill -9` mid-transaction leaves no partial row.
- **[NEW]** Recovery also checks the revocation epoch against the control-plane head and refuses to serve from state older than the highest epoch this node has ever recorded (rollback of the node's own state by restoring an old snapshot must not resurrect revoked keys).

Acceptance: every crash point recovers to one consistent authorised version; committed revocations stay revoked; committed data stays available; no partial state is reported as success.

### P1-07. Signed backup and restore verification (Goal 4) **[CHG]**
- Backup = encrypted key material/state + manifest (backup ID, schema version, key version, revocation epoch, log sequence, content digest, algorithm identifiers). Encrypted to the operator recovery ML-KEM-768 public key (D-07), AES-256-GCM under a fresh DEK.
- Manifest signed with ML-DSA-65 (`kig/v1/backup`). The verification public key (trust anchor) is supplied from outside the backup (CLI argument or pinned file).
- Restore only after: signature, digest, schema, required key material, and **anti-rollback** (`manifest.revocation_epoch` ≥ the highest epoch the live service has recorded and ≥ a minimum epoch pinned with the trust anchor). A valid but old backup is rejected for that reason.
- Report the failure category without disclosing secrets. Never fall back to unverified key material. A failed restore must not modify live state.

Acceptance: valid restore succeeds; flipped bit, truncation, bad signature, unsupported schema and older epoch are each rejected with the right category; live state untouched after a failed restore.

### P1-08. Tamper-evident audit log (Goal 5) **[CHG]**
- One structured event per decision/state change: sequence, request ID, actor, device, action, resource/service, decision, rule ID, key version, node ID, event time, receipt time, correlation/session IDs. In the full demo, actor derives from the authenticated server context; in adapter tests it is labelled a trusted harness input.
- **Encoding (D-08):** each field is length-prefixed; the hash input is a versioned domain label followed by the length-prefixed fields. User text can never alter record boundaries because there are no delimiters to forge.
- Chain: `hash_n = SHA-256(hash_{n-1} ‖ encoded_event_n)` — the Kelsey–Schneier construction. Periodic and final ML-DSA-65 checkpoints (`kig/v1/checkpoint`) over {sequence, head hash, checkpoint ID, previous checkpoint reference}.
- The verification public key and latest expected checkpoint are exported **outside** the mutable log store (`--anchor <path>`), refreshed at every checkpoint.
- `kig verify-log` runs offline and reports the first broken sequence, distinguishing: content edit, missing/reordered record, invalid checkpoint, truncation relative to the externally retained checkpoint.
- Limits to state: a chain without an independently retained signed checkpoint cannot prove the newest records were not deleted (this is the standard result in the tamper-evident-logging literature; Crosby & Wallach 2009 motivate commitments plus frequent auditing). If an attacker controls both the log store and the signing key or trust anchor, the guarantee is out of scope. A Merkle history tree (logarithmic inclusion/consistency proofs) is P2-03.

Acceptance: edit, deletion, insertion/reordering and truncation after the pinned checkpoint all fail verification; a valid export verifies offline; an actor-injection payload (newline + fake JSON event as an identifier) produces exactly one event with the true actor.

### P1-09. Explainable privilege-change detection (Goal 6)
- Parse structured access/administration events; detector independent of `labels.csv` (labels only in evaluation).
- Match every privilege change against `approvals.json` or the approval store: approval ID, approver, subject, operation, role, scope and time interval (`valid_until` exclusive). **[NEW]** Note the practice data: in `evt-004` the *actor* performing `role_change` is the subject (`user-alex`) while the approver is recorded in `evt-003` (`user-admin`); matching must cross-reference the approval event/store and must not require actor == approver.
- Matching in-scope in-time change → routine/approved. Unapproved role increase → high-severity alert linking later accesses in the same session/flow.
- **[v0.3] Two approval shapes.** `grant_role` approvals carry `scope`, `valid_from_utc` and exclusive `valid_until_utc`; `revoke_role` approvals (e.g. `change-101`) carry only `subject`, `role` and `effective_at_utc`. A revoke event matches on approval ID, subject and role with corrected event time ≥ `effective_at_utc` (`evt-016`). A role **decrease** is never a privilege-escalation alert; an unapproved decrease is at most a low-severity "unrecorded change" notice. An applied revocation updates the subject's expected role, so later events (`evt-017`, `evt-018`, `evt-021` with role `viewer`) are judged against the reduced role.
- Never infer intent from a role change alone; explain the missing/mismatched condition.

Acceptance: `evt-003`–`evt-005` approved; `evt-008` raises an alert linking `evt-009`; **[v0.3]** `evt-016` matches `change-101` as approved; alerts include event IDs and reason.

### P1-10. Explainable lateral-movement detection (Goal 7) **[CHG]**
**[v0.3] Baseline definition ("previously unseen").** The edge baseline is a **global (optionally per-role) set of directed service edges**, never a per-actor cold start. It is seeded from (a) the documented expected edges in the practice context (`viewer` → `catalog`; `report-reader` → `reports`, `reports-node-a`, `reports-node-b`; `svc-report-worker`: `reports` → `catalog`; sign-in and admin traffic to `identity`) and (b) a benign warm-up corpus from the seeded generator, kept separate from evaluation seeds. The baseline source, its size and its seed are reported with every benchmark. Reason (simulated on the practice data): a per-actor cold start makes `evt-007`–`evt-009` an LM-1 sequence, sweeping a routine sign-in into an alert; a global cold start passes only because alex's three first-seen edges span 66 s against a 60 s window, which is too fragile to rely on.

Rule set (all thresholds configurable and reported; all emit identity, source/target services, ordered path, supporting event IDs, rule ID, time window, allow/deny per request):
- **LM-1 sequence:** ≥ 3 previously unseen directed service edges for the same actor/session/flow within a configurable window (default 60 s). Fires on `evt-010`–`evt-012`.
- **LM-2 novel allowed edge:** a single *allowed* request over a previously unseen edge into a service on a configured sensitive list (e.g. identity, billing, archive) → medium alert. (LM-1 alone would miss a successful two-edge or one-edge attack.)
- **LM-3 deny burst:** ≥ N denied requests across ≥ 2 distinct unseen target services within the window → low-to-medium alert. **[v0.3]** Default **N = 3** (N = 2 fires on the routine denials `evt-017`/`evt-018`, measured in simulation).
- **[v0.3] Revocation context:** denials by an actor whose role or credential was revoked shortly before (an approved `revoke_role`, a device revocation, or a key cutoff), on services the revoked role used to cover, are classified as **expected enforcement** and excluded from LM-1/LM-3. They are still logged and counted by P1-17 (a revoked identity probing many services is a self-monitoring alert, not a lateral-movement one). This is the "uses context" requirement of Goal 6/7 applied to the practice story (`change-101` → `evt-017`, `evt-018`).
- A single isolated denial (`evt-020`) never alerts as lateral movement.
- Denied attempts are labelled "candidate lateral-movement attempt", never "compromise". Report the evasions (low-and-slow below thresholds) in the benchmark rather than hiding them.

Why the change: the ≥3 threshold reproduces the practice labels but is tuned to them; held-out two-edge and single-edge attacks are the counterexamples LM-2 and LM-3 exist for.

Acceptance: `evt-010`–`evt-012` grouped as one candidate sequence; `evt-020` alone does not alert; **[v0.3]** `evt-007`–`evt-009` produce no lateral-movement alert (the `evt-008`/`evt-009` privilege alert comes from P1-09); `evt-017`/`evt-018` produce no lateral-movement alert and are classified as expected enforcement; the practice-set result is unchanged when the window is varied between 30 s and 120 s; denied vs allowed distinguished; held-out generator attacks with ≤ 2 edges are measured and reported.

### P1-11. Clock-skew and event-order handling (Goal 8)
- Preserve raw source event time and collector receipt time; never overwrite raw values.
- Corrected event time = raw event time − `source_clock_offset_ms`. **Checked by hand against the practice data:** `evt-015` raw 09:06:03.000Z, offset +2000 ms → 09:06:01.000Z, receipt 09:06:01.200Z → 200 ms delay, matching `practice/examples.md`.
- Supported offset ±5,000 ms; outside the range → marked unsupported/uncertain, never clamped. Reorder window 5 s; events after the watermark are retained and marked late. `evt-013` arriving after `evt-014` (≈2 s gap) is inside the window.
- `order_uncertain=true` when uncertainty intervals overlap or the offset is untrusted. Keep ingestion order and event-time order separately.
- Alert latency measured on collector monotonic time.

Acceptance: `evt-013`/`evt-014` handled; `evt-015` corrected; raw/received/corrected preserved; out-of-range and ambiguous order flagged.

### P1-12. Authenticated end-to-end session establishment (Goal 9) **[CHG]**
Handshake (two messages plus key confirmation):
1. **Initiator → responder:** protocol version, suite, initiator and responder device IDs, nonce, a **fresh ephemeral ML-KEM-768 encapsulation key**, signature over the transcript hash (`kig/v1/handshake`, ML-DSA-65).
2. **Responder → initiator:** encapsulation ciphertext to that ephemeral key, responder nonce, key epoch, signature over the transcript including the ciphertext, and a key-confirmation MAC.
- Both sides verify the registered identity-to-key binding and every signature before accepting.
- `PRK = HKDF-Extract(salt = transcript hash, IKM = shared secret)`; directional traffic keys by `HKDF-Expand` with labels that include protocol version, suite, direction and both device IDs. **[NEW]** The key-confirmation step matters: KEM-based handshakes authenticate implicitly through key knowledge, and the AuthKEM/KEMTLS line of work treats explicit confirmation as part of the design.
- Message envelope: sender and intended recipient account/device, session ID, key epoch, sequence number, message ID, suite, ciphertext metadata — all as canonical AEAD associated data. The receiver checks its own identity before decrypting.
- Session IDs are labels, never credentials (D-05).

Acceptance: only the intended recipient decrypts; the same ciphertext fails for another recipient; any tampered handshake or envelope field fails; unregistered/revoked devices cannot establish a session; an old session ID or key presented after revocation is rejected.

### P1-13. Replay protection (Goal 9)
- Unique message ID and monotonic sequence per session and direction. Persist accepted IDs/sequence state (SQLite) so a fresh process cannot forget replay history.
- Reject duplicates, out-of-window sequences, stale epochs, revoked devices. Replay state bounded by session lifetime and retention policy.

Acceptance: a replayed message is delivered at most once; old sequence/epoch rejected; replay state survives process restart (test kills the receiver and replays).

### P1-14. Forward secrecy for completed sessions (Goal 10)
- Ephemeral KEM session material per session; never derive session keys solely from a long-term static KEM private key. Keep ephemeral private keys and session secrets out of backups/logs; release and best-effort clear on close.
- Do not claim physical zeroisation from managed JavaScript memory; document the limitation.
- **Exact claim:** later exposure of a device's long-term ML-DSA signing key alone must not reveal completed-session content, provided ephemeral KEM private material and session traffic keys were not retained or separately compromised. No post-compromise security is claimed.
- Compromise simulation: record a session, complete/close it, expose the long-term signing key, show the captured transcript still cannot be decrypted.
- Not covered: endpoint compromise during an active session, memory dumps during a session, stolen ephemeral keys, plaintext already copied by a recipient, and at-rest file envelopes (P1-02).

Acceptance: simulation passes under the stated assumptions.

### P1-15. Delivery under loss and reordering (Goal 11)
- Deterministic seeded transport simulator: drop, delay, duplicate, reorder chunks.
- Bounded chunks; each chunk's authenticated metadata binds message ID, session ID, sequence, chunk index, **total chunk count** and intended recipient. (An unauthenticated total lets an attacker drop the last chunk and rewrite the count so a truncated message looks complete.)
- Reassemble only after every chunk authenticated and whole-message length/integrity checks pass.
- Bounded retries, max chunk count, max message size, max buffered bytes, timeout; no unbounded reassembly state. Incomplete/invalid/expired messages discarded with a delivery-failure event and reason.
- Transport receipt, reassembly and application delivery are separate outcomes.

Acceptance: complete messages delivered despite recoverable loss/reordering; duplicates not double-delivered; incomplete, tampered or expired messages discarded and reported; truncation-by-count-rewrite test passes.

### P1-16. Session resumption (Goal 12) — **NOT SUPPORTED (D-05)**
Evidence-sheet status: `not supported`. The threat model states that every connection performs a full handshake. The retained negative test: an old session ID or old session key presented after revocation or after session close is rejected. The original ticket design (one-time, identity-bound, server-keyed ticket) moves to P2-04.

### P1-17. Security self-monitoring and operator alerts
**[v0.4]** The adapter-visible subset is now P0-10; this item covers the demo/CLI surface (nodes, rotation, backups, sessions).
- Alert on: revoked actor/device attempts, old-key use after cutoff, stale-node access attempts, invalid backup restores, audit verification failures, repeated authentication failures.
- **[NEW]** Automated responses (for example locking an identity after repeated failures) must be rate-limited and reversible, because an auto-lock is itself a denial-of-service lever against legitimate users.
- Alert content: actor/device, node, target, event IDs, timestamps, policy/key epoch, severity, rule ID, outcome. Never imply a denied action succeeded.

Acceptance: controlled attack scenarios create the expected alert and a verifiable audit trail.

### P1-18. Labelled detection benchmark (Goal 6 metrics)
- The 22-event practice set is a regression fixture, not the benchmark.
- Seeded synthetic generator: routine access, approved administration, unapproved escalation, unusual paths, denied attempts, revocation, clock skew, delayed/reordered arrival. **[NEW]** Hard benign cases (an approved off-hours administrator, a new hire's first accesses, a legitimate new service edge after deployment) and evasive attacks (low-and-slow, in-hours, one- and two-edge paths).
- Multiple seeds; at least one seed set held out from rule tuning. The detector never reads labels.
- Define the unit before reporting: event-level classification and incident/alert matching are not mixed.
- Report precision, recall, F1, median time-to-alert, false alerts per 1,000 benign events, plus dataset size, class distribution, seeds, thresholds, clock conditions and metric definitions. Report misses.
- Time-to-alert: collector/monotonic time from receipt of the final evidence needed to alert emission.

Acceptance: metrics from reproducible runs; nothing hard-coded; nothing claimed from 22 events alone.

### P1-19. Operator CLI and repeatable demo
**[v0.4]** This is the Round 2 judging surface (D-17): the judges' view of every P1 goal is through these commands. A GUI is optional (P2-01).
`kig demo`, `kig enrol`, `kig revoke`, `kig rotate`, `kig backup` / `kig restore`, `kig verify-log`, `kig detect`, `kig bench`, `kig crash-test`, **[NEW]** `kig compat`. `kig demo` prints narrated, reproducible PASS/FAIL outcomes with seeded synthetic identities only. **[NEW]** The demo must be runnable by a stranger from the README on a clean machine with only Node 24.11.1.

### P1-20. Performance and resource evidence
- p50/p95 latency for setup, read, revoke, protected_read, signature verify, rotation, backup verify, message encrypt/decrypt, log append/verify, detector processing.
- **[CHG]** Report adapter *process startup* separately from operation cost (measured baseline in the dev sandbox: empty Node process p50 15.6 ms; `protected_read`-equivalent whole-process p50 26.0 ms / p95 34.2 ms; in-process ML-DSA-65 sign p50 0.62 ms, verify p50 0.16 ms — to be re-measured in the final environment, these are not final numbers).
- Ciphertext expansion, key/envelope sizes (ML-KEM-768 ek 1184 B, ct 1088 B; ML-DSA-65 pk 1952 B, sig 3309 B), audit growth, DB size, memory where measurable. Record runtime version, host specs, dataset size, seed with each result.

### P1-21. Evidence and submission documentation
- Maintain the toolkit's evidence sheet: one row per goal; statuses `measured`, `partial`, `not tested`, `not supported` only. Measured means a repeatable run and an artifact.
- Record command, input, expected result (written *before* the run), actual result, environment, timestamps, path, limitations.
- Deliver: public repository created during the event, dependency/setup instructions (runtime: none; dev/test: Python + `pqcrypto` for interop only), two-page brief, one-page threat model, accessible five-minute demo video link.
- Keep the toolkit separate from the submission repository; copy only the Node starter adapter and stub to the root.

---

## 5. P2 — operator experience and stretch

- **P2-01** Static read-only dashboard generated from real run data (device status, node ack state, access timeline, alerts with evidence, audit verification, measured metrics). Contains no access-control or detection logic.
- **P2-02** Optional hybrid key establishment: X-Wing exactly as specified, with the draft's test vectors, or not at all (D-11). Never an improvised combiner.
- **P2-03** Merkle history tree for the audit log (inclusion and consistency proofs), per the Crosby–Wallach design, if time permits.
- **P2-04** Session resumption (one-time, identity-bound, time-limited ticket; ticket key server-side; re-check of current revocation on every resume), only after everything else passes. Until then the evidence status stays `not supported`.
- **P2-05** Incident bundles, searchable timelines, graph visualisation.

---

## 6. Explicit non-goals and honesty constraints
1. No custom cryptographic primitive.
2. No ML/AI detector.
3. No false identity-authentication claim for the adapter (P0-05).
4. No false E2E claim from `protected_read`.
5. No retroactive recall of copied plaintext.
6. No instantaneous distributed-revocation claim; state the measured bound and fail-closed behaviour.
7. No truncation claim from a hash chain alone.
8. No blanket forward-secrecy claim; no forward secrecy claimed for at-rest file envelopes.
9. No statistical claim from 22 events.
10. No hidden dependency assumption; nothing installed during judging.
11. No hard-coded secrets or seeded production keys; test fixtures with deterministic randomness are isolated and marked test-only.
12. No unsupported `threat-model.json` claims.
13. **[NEW]** No claim about the organizer's container beyond what the adapter contract states. All measurements in this document come from a stand-in environment (Appendix A).
14. **[v0.3]** No confidentiality claim for adapter-stored bodies against anyone who can read the state directory (D-14).
15. **[v0.4]** No claim that the adapter resists an attacker who can modify or roll back `TRACK4_STATE_DIR` (D-15).

---

## 7. Acceptance and evidence policy
Every feature needs: (1) observable behaviour a judge can execute; (2) a negative test; (3) captured evidence with the exact command and environment.

| Official goal | Feature IDs | Minimum evidence |
|---|---|---|
| 1. Key rotation | P1-04 | Old-key request rejected after cutoff; in-flight/grace result; per-node version state |
| 2. Revocation across nodes | P1-03, P1-05 | Three node decisions, replacement-device access, peer access, measured last-node latency, partition bound |
| 3. Crash recovery | P1-06 | Crash at each journal phase; recovered key/revocation/data state |
| 4. Backup integrity | P1-07 | Valid restore; tampered/truncated/stale backup rejection |
| 5. Log integrity | P1-08 | Offline verification; edit/delete/reorder/truncate results; injection test |
| 6. Routine/suspicious activity | P1-09, P1-18 | Approved vs unapproved changes; F1, median alert latency, false alerts per 1,000 benign events |
| 7. Lateral movement | P1-10 | Explained path with identity, events, rule and denied/successful distinction |
| 8. Clock differences | P1-11 | Raw/corrected/received timeline, ±5 s range, uncertain-order test |
| 9. Replay/recipient binding | P1-12, P1-13 | Wrong-recipient, altered-AAD, duplicate, sequence, revoked-device tests |
| 10. Forward secrecy | P1-14 | Completed-session compromise test with explicit assumptions |
| 11. Loss/reordering | P1-15 | Seeded loss/reorder/duplicate tests; incomplete rejection; count-rewrite test |
| 12. Session resumption | P1-16 | Status `not supported` plus the old-session negative test |

Design text is not evidence. The evidence-sheet status must reflect the result actually obtained.

---

## 8. Decisions architecture.md must resolve
1. Adapter-to-core call flow and the separate demo/CLI entry points.
2. Account/device/actor mapping; adapter actor revocation vs device-specific revocation.
3. SQLite schema, transaction boundaries (decision + audit in one transaction), state-directory layout, corruption handling, WAL-fallback.
4. Key hierarchy: file DEK, device envelope KEM key, device signing key, ephemeral session KEM key, audit-signing key, backup trust anchor, **operator recovery KEM key (D-07)**. Purposes never conflated; where each private key lives and who can read it. **[v0.3]** Private keys persist as seeds (measured `raw-seed` export: ML-DSA-65 32 B, ML-KEM-768 64 B); say where each seed is stored and under what protection, consistent with D-14.
5. File encryption, DEK envelope creation, sharing, rotation, lost-device re-encryption.
6. Rotation state machine, node acknowledgements, epoch cutoff, grace handling (D-06).
7. Revocation epoch distribution, freshness lease, partition behaviour.
8. Crash journal and forward-recovery rules.
9. Backup format, trust anchor, anti-rollback state.
10. Event schema, length-prefixed encoding (D-08), chain construction, checkpoint export/verification.
11. Detector rule configuration, graph baseline, time correction/watermark, metric definitions.
12. Handshake messages, key confirmation, envelope/AAD, replay state, chunking.
13. Threat model, attacker capabilities, limitations, claims we do not make.
14. **[v0.3] Runtime and components (replaces the separate `TECH_STACK.md`):** which Node built-in serves each purpose (`node:crypto` KeyObject vs WebCrypto per algorithm, `node:sqlite` settings from P0-03), module layout, process/node layout, algorithm and size table, dev-only tooling (pinned `node:24.11.1` container, Python + `pqcrypto` interop test, CI). The dependency list and clean-machine setup go in `README.md`. The former `TECH_STACK.md` (superseded Python design; it derived a root key from `key_material`, which P0-04 forbids) has been removed; port only its still-valid parts (algorithm/size table, process diagram) into `architecture.md`.

---

## 9. Build order, gates and scope risk **[NEW]**

How the scoring maps to the work. **[v0.4]** Organizers confirmed that Round 1 runs only the repository-root adapter, with hidden test cases and exploits, on an x86-64 container ([v0.5] corrected from ARM); Round 2 is judged through our CLI (D-17).

| Stage 1 criterion | Largely decided by |
|---|---|
| Security Correctness (25), Live/Automated Assessment (25, deductions 10/6/3/1 per finding) | P0 adapter hardening, `protected_read`, identifier handling, log integrity, crash behaviour |
| Functionality & Reliability (20) | `setup→read→revoke→audit` correctness, recovery after disruption, verifiable outcomes |
| Threat Model & Honesty (10) | Section 6 discipline, accurate `threat-model.json`, honest evidence statuses |
| Performance (10) | P1-20 |
| Usability & Documentation (10) | README, clean-machine setup, `kig demo` |

Only the top 10 teams reach the desk review (live demo, technical questions, live assessment). **Therefore P0 must be finished and hardened before breadth.**

Vertical slices, each with a gate:
1. **S0** `kig compat` + repo skeleton + CI in the pinned container. *Gate:* compat passes.
2. **S1** P0 complete (**[v0.4] the Round 1 deliverable**, including P0-10 alerts). *Gate:* `validate.py` exits 0 on x86-64 in the judging replica; protected-read interop (25/25); negative suite (including the [v0.3] prototype-key, strict-Base64 and exit-code cases); concurrent-process tests (warm **and** cold-start, P0-03) and `kill -9` tests.
3. **S2** Audit chain, checkpoints, `verify-log` (everything else logs through it).
4. **S3** Device identity, enrolment, envelopes, lost-device flow.
5. **S4** Rotation, three-node revocation, lease, measurements.
6. **S5** Crash journal, backup/restore, anti-rollback.
7. **S6** Detector, generator, benchmark, clock handling.
8. **S7** Handshake, replay, forward-secrecy test, chunking.
9. **S8** Performance report, evidence sheet, threat model, brief PDF, video.

Cut order if time runs short: P2 items, then detector graph extras beyond LM-1/LM-3, then simulator extras, then dashboards. **[v0.3]** If S7 (messaging, Goals 9–11) cannot be finished to the acceptance standard, build P1-12 and P1-13 properly and mark P1-15 `partial`; messaging is the largest code surface and the most likely source of assessment findings. Never cut: P0, audit verification, P1-17 self-monitoring (it is what earns back up to half of each assessment deduction), the threat model's honesty section.

**Scope risk, stated plainly.** v0.1 contained 21 P1 items; v0.2 keeps 20 (resumption removed). That is a lot for an unknown time box. I do not know the team size or the event length; if S5–S7 cannot all be completed to the acceptance standard, finish fewer goals fully and mark the rest `partial` or `not tested` honestly. A smaller surface that is rigorously correct scores better under the deduction rules than a wide one with findings.

---

## 10. Questions for organizers
**[v0.4] Answers received 2026-11-26:** container is x86-64 (first reported as ARM, corrected the same day); Round 1 runs our repository entry point only (no CLI/GUI) with hidden test cases and exploits; Round 2 is judged through our CLI; the AI/ML ban means components in the code, AI-assisted development is fine; Node pinned at 24.11.1; assume SQLite WAL works; response JSON shapes are ours to decide; team capacity to be confirmed.

- **Q1 (open).** Does the official worker call `setup` more than once against the same container/state directory (several scenarios)? D-01 handles both cases, so this is no longer a blocker.
- ~~**Q2.**~~ **Answered:** response shapes are ours to decide → D-02, D-03, D-16.
- ~~**Q2b.**~~ **Answered (ours to decide):** D-13 stands; we assume a strict worker.
- **Q3 (open, low priority).** What does the worker do with `threat-model.json` — is a mismatch penalised, and are values other than the example recognised? Until answered, P0-09 applies (omit or only defensible values).
- ~~**Q4.**~~ **Answered:** x86-64 (corrected from ARM); WAL works. Persistence of the temp directory across invocations is implied by the contract ("state that must survive between calls in the same container").
- ~~**Q5.**~~ **Answered:** Round 1 adapter only; Round 2 through the CLI.
- ~~**Q6.**~~ **Answered [v0.3]:** the `BUTTERFINGERS7498/trust-but-verify-toolkit` v1.0.0 ZIP and `ScalerOpenSourceLabs/Track-4-Toolkit` commit `8901dfb` are identical apart from CRLF line endings. No need to ask.
- ~~**Q7.**~~ **Answered:** Node 24.11.1.
- ~~**Q8.**~~ **Answered:** the ban covers AI/ML components in the code; AI-assisted development is encouraged.
- **Q9 (pending, organizers will inform).** Team capacity / event duration; sets the Section 9 cut line.

---

## 11. References
**Read in this pass (v0.2):** Node.js Web Crypto API documentation (Modern Algorithms section: Stability 1.1; ML-DSA added v24.7.0, ML-KEM v24.8.0 per the changelog); Node.js SQLite documentation (Stability 1.2 release candidate from v24.15.0, so 1.1 in 24.11.1); IETF drafts on KEM-based TLS authentication (AuthKEM, draft-celi-wiggers-tls-authkem) and the KEMTLS paper abstract; Crosby & Wallach, *Efficient Data Structures for Tamper-Evident Logging*, USENIX Security 2009 (and its summary of Kelsey–Schneier hash-chain logging); NIST SP 800-38D §8.3 random-IV limit (2^32 invocations per key) as restated by AWS and the Go project; IETF draft-connolly-cfrg-xwing-kem (revision 11, active Internet-Draft, Informational).

**Carried over from v0.1, not re-fetched in this pass:** NIST FIPS 203, FIPS 204, SP 800-227, SP 800-57 Part 1 Rev. 5; RFC 5869 (the HKDF vector was reproduced in the spike); RFC 9180; RFC 8452; Signal Double Ratchet specification; RFC 8785; OWASP Logging Cheat Sheet; the organizer sources (official problem statement, toolkit README, adapter contract v1, validator, practice data, evidence-sheet template — the last five were read directly from the cloned toolkit).

---

## Appendix A. Spike evidence (v0.2)

**Environment (stand-in, not the organizer container):** Linux sandbox; Node binary `v24.11.1` obtained from the npm registry (`node@24.11.1`), reporting OpenSSL 3.5.4, SQLite 3.50.4; Python 3.12.3 with `pqcrypto==0.4.0` (requires `cffi>=1.17.1`) in a virtualenv. Toolkit commit `8901dfb`.

| # | Check | Result |
|---|---|---|
| 1 | `crypto.webcrypto.subtle` ML-KEM-768: generateKey, export `raw-public` (1184 B), import `raw-public`, `encapsulateBits` (ct 1088 B, ss 32 B), `decapsulateBits` | PASS |
| 2 | Tampered ciphertext | different secret, no exception (implicit rejection) |
| 3 | 1183-byte public key; 1184 × `0xFF` public key | both rejected, `DataError` |
| 4 | `pqcrypto` encapsulating to 1184 × `0xFF` key | accepted (no encapsulation-key check) |
| 5 | `crypto.encapsulate`/`decapsulate` KeyObject API | PASS (alternative path available) |
| 6 | ML-DSA-65 sign/verify, tamper rejection, sizes, context separation, `raw-seed` export (32 B) | PASS |
| 7 | AES-256-GCM with AAD, tamper rejection; ChaCha20-Poly1305 | PASS |
| 8 | HKDF-SHA-256, RFC 5869 test case 1; `hkdfSync` equals `subtle.deriveBits`; HMAC-SHA-256 | PASS |
| 9 | Node encapsulate → `pqcrypto` decapsulate + recomputed HMAC proof (UTF-8 body) | 25/25 match |
| 10 | `pqcrypto` encapsulate → Node decapsulate | 10/10 match |
| 11 | 8 concurrent processes × 25 hash-chained appends, `BEGIN IMMEDIATE`, WAL, `synchronous=FULL`, 5 s timeout | 200 rows, chain valid |
| 12 | `SIGKILL` inside an open transaction | no partial row, chain valid |
| 13 | Corrupted database file | process terminates with an uncaught error (exit 1) — must be caught and fail closed |
| 14 | Warning suppression via `process.removeAllListeners('warning')` | stderr 0 bytes |
| 15 | Identifier edge cases as raw TEXT | lone surrogate stored as U+FFFD and collides with a real U+FFFD ID; NUL does not round-trip |
| 16 | Same edge cases as `JSON.stringify` strings | 11/11 distinct, exact round-trip |
| 17 | Latency (dev sandbox, whole process, 40 runs): Node `protected_read`-equivalent p50 26.0 ms / p95 34.2 ms; Python 18.8 / 19.7 ms; empty process Node 15.6 ms vs Python 8.9 ms; Node + SQLite open + one append p50 20.6 ms; in-process ML-DSA-65 sign p50 0.62 ms, verify 0.16 ms (200 runs) | informational |
| 18 | Toolkit: `python quickstart.py` | exit 0, all checks PASS |

### A.2 Independent re-verification and audit findings (v0.3, 2026-11-26)

**Environment (second stand-in, not the organizer container):** WSL2 Ubuntu x86-64; official `node-v24.11.1-linux-x64` tarball from nodejs.org (OpenSSL 3.5.4, SQLite 3.50.4); Python 3.12.3 venv with `pqcrypto==0.4.0`; toolkit commit `8901dfb`.

| # | Check | Result |
|---|---|---|
| R1 | Re-run of items 1–9 and 11–16 above | All reproduced (item 10 not re-run; item 9: 25/25) |
| R2 | `python3 quickstart.py node` with Node 24.11.1; `python3 -m unittest tests.test_validate` | exit 0, all checks PASS; 7 tests OK |
| R3 | Toolkit canonicality: BUTTERFINGERS v1.0.0 ZIP vs Scaler clone vs local sister repo | identical apart from CRLF line endings (answers Q6) |
| R4 | ML-DSA-65 signature under a context verified with no context | rejected (context separation is complete) |
| R5 | Private-key `raw-seed` export | ML-DSA-65 32 B, ML-KEM-768 64 B; PKCS#8 also works |
| R6 | Sync KeyObject API: `crypto.encapsulate`/`decapsulate`, `crypto.sign(null, m, {key, context})` | PASS |
| R7 | SLH-DSA | available via KeyObject (`slh-dsa-sha2-128f`); `NotSupportedError` in WebCrypto |
| R8 | `pqcrypto` ML-DSA API; Python AEAD packages | `sign(secret_key, message)`, no context; `cryptography`, `Crypto`, `nacl` absent, `cffi` present |
| R9 | 8 concurrent processes on a **cold** database, each setting `journal_mode=WAL` | 1 of 4 runs: one process threw `database is locked` from the pragma and exited 1 (175/200 rows); 3 of 3 runs on a pre-initialised WAL database clean → P0-03 change |
| R10 | `Buffer.from(…, "base64")` on URL-safe input and on input with junk characters | both decode without error → strict validator in P0-07 |
| R11 | `obj["__proto__"] = x` on a plain object; `JSON.parse('{"__proto__":…}')`; `owners["constructor"]` | not stored as an own key; kept as an own key; returns `Function` → `Map`/`Set` rule in P0-05/P0-08 |
| R12 | Lateral-movement rules simulated on `practice/events.csv` (corrected time, 60 s) | LM-1 per-actor cold start fires on `evt-007..009` and `evt-010..012`; global cold start only `evt-010..012` (margin 6 s); LM-3 N=2 fires on `evt-017/018`; N=3 only `evt-010..012` → P1-10 changes |
| R13 | Whole-process latency, 40 runs (WSL is slower than the first sandbox) | Node empty p50 45 ms; Node with sqlite + ML-KEM encaps p50 55 ms / p95 59 ms; Python empty 29 ms; Python with pqcrypto + sqlite + encaps p50 35 ms / p95 42 ms. Gap consistent with item 17; informational |

**[v0.5] All Appendix A results are from x86-64, which is the judging architecture.**

**Not tested, and therefore not claimed:** the organizer's actual judging container (x86-64 per organizers; filesystem, tmpfs/WAL behaviour, read-only root); the official worker's behaviour; Node 24.11.1 under a read-only root filesystem; Node ↔ `pqcrypto` ML-DSA signature interoperability (not required by the adapter contract); multi-node simulation; any detection metric.