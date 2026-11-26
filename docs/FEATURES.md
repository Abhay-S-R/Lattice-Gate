# Key Identity Guard: Proposed Feature List

**Workflow we protect:** A user owns a sensitive file and shares it over an end-to-end encrypted channel. Their device is reported lost. The system **protects** the file with post-quantum crypto, **enforces** the access change on every node, and **shows** the operator what happened in a log they can verify.

**Security claim judges can test:**
> After `revoke`, no node returns the lost device's file content or a valid ML-KEM proof for it. The peer keeps access. Every decision is recorded in a hash-chained, ML-DSA-signed log that the operator can verify offline.

Priority legend: **P0** = needed to pass Stage 1 automated grading Â· **P1** = scores the 4 pillars and the 12 goals Â· **P2** = for the desk review and finals

---

## A. Stage 1 adapter (P0)

| # | Feature | Detail |
|---|---|---|
| A1 | `track4_service.py` root adapter | One JSON request per process. Exits 0. Fixed error codes on stdout, generic message on stderr, no echo of secrets. |
| A2 | `setup` | Fresh state for each `TRACK4_STATE_DIR`. Generates per-deployment keys at runtime (none hard-coded). `key_material` is only used as KDF input and is never stored in plaintext or printed. |
| A3 | `read` | Deny by default. Checks, in order: identity disabled/revoked, then device status, then owner policy. On deny, the response holds no content (no `body`, no debug fields). |
| A4 | `revoke` | Persisted atomically (temp file, `fsync`, rename) before the reply. Peers are not affected. |
| A5 | `audit` | Returns `request_id`, `decision`, `rule`, and the log sequence number and hash, so the outcome can be verified. |
| A6 | `protected_read` | Authorization first. Then ML-KEM-768 encapsulation via `pqcrypto` and an HMAC-SHA-256 proof over `challenge + body`. The shared secret is erased from memory after use. |
| A7 | Input hardening | Schema/type checks, size limits, opaque-ID handling, no path traversal from IDs, and safe handling of a missing or corrupt state file (fail closed). |
| A8 | `threat-model.json` | `{"asset":"protected-resource","boundary":"identity-check"}` |
| A9 | Offline-safe dependencies | Python 3.12 stdlib + `pqcrypto==0.4.0` only. A CI script runs `validate.py` in an offline `python:3.12` Docker container with a read-only root filesystem. |

## B. Cryptography and key management (P1)

| # | Feature | Goal |
|---|---|---|
| B1 | **Encryption at rest.** A per-file data key (DEK) encrypts the file body. A versioned key-encryption key (KEK) wraps the DEK. Key derivation uses HKDF-SHA-256. | Security correctness |
| B2 | **Device enrolment.** Each device has its own ML-KEM-768 and ML-DSA-65 keypair, and requests are signed by the device. | Identity control |
| B3 | **Key rotation** with versions `active â†’ retiring â†’ retired`. There is a documented grace window (e.g. 30 s) during which in-flight transfers finish. After the cutoff, every node rejects the old version. | Goal 1 |
| B4 | **Multi-node revocation.** Three simulated nodes pull a signed revocation list (monotonic epoch). Reports revocationâ†’last-node-enforcement latency in ms. | Goal 2 |
| B5 | **Lost device and re-enrolment.** The lost device is revoked. The owner enrols a new device, the DEK is re-wrapped for it, and other users keep access. | Goal 2 |
| B6 | **Crash-safe rotation (WAL).** Rotation runs as a write-ahead log: `PREPARE â†’ REWRAP â†’ COMMIT`. On restart, an incomplete rotation is rolled forward or back to the last committed version. Revocations are never rolled back. | Goal 3 |
| B7 | **Signed and verified backups.** The key backup has a SHA-256 manifest and an ML-DSA-65 signature. Restore rejects a backup that is altered, truncated or replayed from an older epoch, and reports which check failed. | Goal 4 |
| B8 | **Crash injection switch.** `KIG_CRASH_AT=<step>` triggers the crash scenario in demos and tests. | Goal 3 evidence |

## C. Tamper-evident audit log (P1)

| # | Feature | Goal |
|---|---|---|
| C1 | One canonical JSON object per record, with length-prefixed framing. User text is always a quoted field, so injected newlines, commas or `"actor":` strings cannot create a fake event or change the actor. | Goal 5 |
| C2 | SHA-256 hash chain (`prev_hash`) plus signed ML-DSA-65 checkpoints. | Goal 5 |
| C3 | `kig verify-log` command. Reports the first broken sequence number and what was wrong (edit, delete, reorder or truncation). | Goal 5 |
| C4 | Every decision record holds the actor, device, asset, rule that fired, key version and node ID. | Verifiable outcome |

## D. Explainable detector, no ML (P1)

| # | Feature | Goal |
|---|---|---|
| D1 | **Change-control correlation.** A role change counts as approved only if the subject, role, scope and time window all match `approvals.json` (`valid_until` is exclusive). | Goal 6 |
| D2 | **Unexpected privilege rule.** Raises a high alert for a role increase with no approval, and links later accesses in the same session (`evt-008` â†’ `evt-009`). | Goal 6 |
| D3 | **Service-graph rule.** Builds a baseline of allowed service edges. An alert fires when there are â‰¥ N new edges for the same actor, session and flow within a time window (`evt-010..012`). One isolated denial (`evt-020`) does not alert. Alerts state whether the requests were denied or succeeded. | Goal 7 |
| D4 | **Alert explanation.** Each alert gives the identity, services, path (`reportsâ†’billingâ†’archiveâ†’identity`), supporting event IDs, the rule ID and why it fired. | Goal 7 |
| D5 | **Clock handling.** Corrects each event time by its source offset, keeps the raw timestamps, and uses a reorder buffer (watermark). States the supported offset range (e.g. Â±5 s). Events within the uncertainty window are marked `order_uncertain`. | Goal 8 |
| D6 | **Labelled benchmark.** A seeded synthetic log generator (benign admin work, escalations, lateral paths, skew and reordering). Reports **F1, median time to alert, and false alerts per 1,000 benign events**, plus 22/22 on the practice set. | Goal 6 metrics |
| D7 | **Revocation self-monitoring.** Requests by a revoked identity or device, and old-key use after the cutoff, are turned into alerts. This supports the "detect and respond" recovery points in the live assessment. | Live assessment |

## E. PQ end-to-end messaging (P1)

| # | Feature | Goal |
|---|---|---|
| E1 | **Handshake.** Ephemeral ML-KEM-768, authenticated with ML-DSA-65 identity signatures. HKDF derives the session keys. | Goal 9 |
| E2 | **Recipient binding.** The AEAD associated data includes the sender, recipient, session ID, sequence number and message ID. Changing the recipient makes authentication fail. | Goal 9 |
| E3 | **Replay cache.** Rejects duplicate message IDs and sequence numbers outside the sliding window. | Goal 9 |
| E4 | **Forward secrecy.** Ephemeral KEM keys and session keys are erased when the session closes. A test leaks the long-term key afterwards and shows earlier sessions stay unreadable. | Goal 10 |
| E5 | **Chunked delivery.** A lossy, reordering transport simulator (seeded). Messages are reassembled in order with a timeout and bounded retries. Incomplete or failed messages are discarded and reported. | Goal 11 |
| E6 | **Session resumption.** A resumption ticket is bound to the peer's identity key, with a short lifetime and a fresh revocation check. A different identity presenting the same session ID is rejected. | Goal 12 |
| E7 | **Revoked device cut-off.** A revoked device cannot complete a handshake or resume a session. | Ties to the main story |

## F. Operator experience and evidence (P1/P2)

| # | Feature | Priority |
|---|---|---|
| F1 | `kig` command line: `demo`, `rotate`, `revoke`, `enrol`, `backup`, `restore`, `verify-log`, `detect`, `bench` | P1 |
| F2 | `python demo.py`: one command plays the full lost-device story in narrated steps, each with PASS/FAIL. Used for the video. | P1 |
| F3 | Test suite (stdlib `unittest`) with one test per goal plus negative/attack tests | P1 |
| F4 | Performance report: p50/p95 latency per operation, process start-up cost, ciphertext and state overhead | P1 |
| F5 | `docs/evidence-sheet.md` with all 12 goals filled in from real runs (commands, outputs, limits) | P1 |
| F6 | 2-page brief PDF (USP, architecture diagram, threat model, video link) and a 5-minute demo script | P1 |
| F7 | Read-only HTML operator dashboard (timeline, alerts, log-verify status) generated as a static file | P2 |
| F8 | Optional hybrid mode (X25519 + ML-KEM) documented as future work if the dependency is unavailable | P2 |

---

> [!WARNING]
> **Constraint: encryption at rest.** The judging container provides **only the standard library and `pqcrypto`**. Neither includes a symmetric cipher such as AES-GCM or ChaCha20-Poly1305, and building our own cipher from hashes would count as a "custom primitive", which is grounds for disqualification. Options:
> 1. **(Recommended)** Copy a pure-Python implementation of AES-GCM / ChaCha20-Poly1305 from an established library (e.g. `tlslite-ng`) into the repo, with credit and its RFC test vectors. Files are small, so slow pure-Python speed is acceptable.
> 2. Leave out encryption at rest in the adapter. Rely on access control plus ML-KEM proofs, and state this limit in the threat model.

> [!NOTE]
> Verified: `pqcrypto==0.4.0` ships `pqcrypto.kem.ml_kem_768`, `pqcrypto.sign.ml_dsa_65` and `pqcrypto.sign.sphincs_sha2_*` (SPHINCS+, round 3).


---

## Tech stack

**Runtime (offline judging container: Python 3.12 + `pqcrypto==0.4.0`, read-only root FS)**

| Layer | Choice |
|---|---|
| Language | Python 3.12, stdlib + `pqcrypto==0.4.0` only |
| KEM | `pqcrypto.kem.ml_kem_768` (FIPS 203) |
| Signatures | `pqcrypto.sign.ml_dsa_65` (FIPS 204); optional `sphincs_sha2_128f_simple` for backups |
| Hash / MAC / KDF / RNG | `hashlib` SHA-256, `hmac`, HKDF (RFC 5869, checked against its test vectors), `secrets` |
| AEAD at rest / messaging | Vendored pure-Python AES-256-GCM (from `tlslite-ng`, credited, LGPL), checked against NIST vectors |
| State + audit store | stdlib `sqlite3` (WAL mode) in `TRACK4_STATE_DIR` |
| Detector | Plain-Python rules, service graph and counters (no numpy/sklearn/ML) |
| Multi-node | 3 simulated node processes sharing a signed, epoch-versioned revocation list |

**Dev / delivery (not run by judges):** `unittest` + toolkit `validate.py`; Docker `python:3.12-slim` with `--network none --read-only`; static HTML dashboard; PyMuPDF for the brief PDF; GitHub Actions (optional); OBS + unlisted YouTube for the demo video.

**Known limits:** no hybrid X25519 + ML-KEM (X25519 isn't in the sandbox); pure-Python AES-GCM is slower than a native library (measured and reported).
