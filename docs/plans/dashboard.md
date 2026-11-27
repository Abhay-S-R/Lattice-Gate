# Plan & Prompt: KIG Trust & Verification Console (`dashboard.html`)

**Project:** Key Identity Guard (KIG) — DevForge Track 4 ("Trust, but verify")  
**Target Artifact:** `dashboard.html` (standalone, single-file static HTML5 + CSS3 + vanilla JS)  
**Status:** Refined specification aligned with `README.md`, `docs/architecture.md`, and `evidence/final-5410c49/`  
**Guardrails:** Do **not** modify any existing application, test, or evidence files. Do **not** commit or push unless explicitly instructed.

---

## 1. Objective & Core Constraints

Build a polished, offline-capable, single-file static dashboard (`dashboard.html`) for **KIG (Key Identity Guard)** that visualizes the system's 12 Track 4 security goals, 12-step live cluster storyboard, PQC/revocation benchmarks, tamper-evident audit chain, crash recovery invariants, explainable anomaly detector, and post-quantum E2EE messaging.

### Technical Constraints
- **Single self-contained file:** `dashboard.html` with all CSS and JavaScript embedded inline.
- **Zero external dependencies:** Pure HTML5, CSS3, and vanilla JavaScript (ES2022+). No React/Vue/Angular, no npm packages, no build tools, no external CDNs, no external fonts, no icon libraries.
- **Offline & `file://` compatible:** Must work directly when opened via `file://` as well as any static HTTP server, with zero network requests.
- **Inline SVG:** Use crisp, responsive inline SVG for topology diagrams, horizontal bar charts, hash-chain diagrams, timelines, and lateral-movement graphs.
- **Functional, not decorative:** Every control, filter, simulator toggle, and chart must be driven by parsed evidence state or deterministic simulation logic—no dead buttons or fabricated metrics.

---

## 2. Visual Identity & Design System

Adopt a restrained **Security Operations Center (SOC)** aesthetic consistent with KIG's engineering-first identity:

### Color Tokens (CSS Custom Properties)
- **Main background:** Deep navy / near-black (`#070b12`)
- **Sidebar / elevated rails:** Slightly lighter navy (`#0c121e`)
- **Panel surfaces:** Dark slate-navy (`#111827` / `#131c2e`) with `1px solid #1f2a40` borders and `8px–10px` border radius
- **Primary accent (Measured / Verified / Pass):** Emerald green (`#10b981` / `#34d399`)
- **Secondary accent (Telemetry / Active Nodes):** Cyan & electric blue (`#06b6d4` / `#38bdf8`)
- **Tertiary accent (Post-Quantum Cryptography):** Violet / purple (`#a855f7` / `#c084fc`)
- **Warning / Unsupported by Design / Synthetic:** Amber (`#f59e0b`)
- **Failure / Revoked / Tamper Detected:** Red (`#ef4444`)
- **Primary text:** Off-white (`#f1f5f9`)
- **Secondary / muted text:** Muted slate (`#94a3b8`)
- **Monospace font stack:** `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace` for IDs, hashes, ports, epochs, and latencies.
- **UI font stack:** `system-ui, -apple-system, Segoe UI, Roboto, sans-serif`

### Visual Discipline
- Subtle gradients and restrained status glows only on active/focused elements.
- Compact, scannable density with generous internal padding (`16px–20px` per card).
- Explicit honesty badges distinguishing **`measured`**, **`measured (synthetic)`**, **`measured (stated scope)`**, and **`not supported`**.

---

## 3. Application Shell & Persistent Chrome

### A. Left Sidebar (Persistent)
- **Brand:** Inline SVG KIG shield logo + `KIG Console`
- **Primary Navigation:**
  1. `Overview` (5-panel executive summary + 12-step storyboard + evidence loader)
  2. `Telemetry` (Revocation propagation, Round 1 adapter, in-process PQC/SQLite benchmarks)
  3. `Audit & Crash` (Tamper-evident SHA-256 chain + fault simulator + 5-point `SIGKILL` recovery matrix)
  4. `Detection` (Clock-skew correction, reorder watermark, lateral-movement graph, synthetic scorecard)
  5. `Messaging` (`ML-KEM-768` + `ML-DSA-65` handshake, forward secrecy, `16 KiB` chunk simulator, negative checks)
  6. `About & Scope` (Threat model, honest scope boundaries, Round 1 vs. Round 2 architecture)
- **Active State:** Highlighted background (`rgba(16, 185, 129, 0.12)`), left accent bar (`3px solid #10b981`), bright text.
- **Bottom Status Indicator:** Dynamic system-health pill (`All Systems Healthy` when loaded evidence passes, or warning count if a loaded file has failures/warnings).

### B. Top Header
- **Left:**
  - Title: **KIG | Trust & Verification Console**
  - Subtitle: `Zero Dependencies. Full Transparency.`
- **Right (Configurable Metadata Object `APP_META`):**
  - `Node.js v24.11.1`
  - `OpenSSL 3.5.4 (ML-KEM-768 / ML-DSA-65)`
  - `0 runtime dependencies`
  - `Evidence commit: 5410c49` (updates dynamically if a loaded `demo.json` / summary provides another commit)

### C. Twelve-Goal Navigation Strip (Always Accessible)
Horizontally arranged, scrollable on narrow viewports, matching the **exact 12 Track 4 Goals** from `README.md` and `evidence/evidence-sheet.md`:

| # | Goal Title | Default Status Badge | Maps Primarily To |
|---:|---|---|---|
| 1 | Key rotation | `measured` (Green) | `demo.json` Step 4, `bench-perf.json` |
| 2 | Revocation across nodes | `measured` (Green) | `bench-revocation.json`, `demo.json` Steps 2, 5, 6 |
| 3 | Crash recovery | `measured` (Green) | `crash-test.json`, `demo.json` Step 7 |
| 4 | Backup integrity | `measured` (Green) | `demo.json` Step 8 |
| 5 | Log integrity | `measured` (Green) | `demo.json` Step 9, `bench-perf.json` |
| 6 | Routine vs. suspicious activity | `measured (synthetic)` (Teal) | `detect-practice.json`, `bench-detect.json`, `demo.json` Step 10 |
| 7 | Lateral movement | `measured` (Green) | `detect-practice.json` (`LM-1`), `bench-detect.json` |
| 8 | Clock differences | `measured` (Green) | `detect-practice.json` (`evt-013..015`) |
| 9 | Replay & recipient binding | `measured` (Green) | `demo.json` Step 11 (`msg demo`) |
| 10 | Forward secrecy | `measured (stated scope)` (Teal) | `demo.json` Step 11, `bench-perf.json` |
| 11 | Delivery under loss/reordering | `measured` (Green) | `demo.json` Step 11 (`16 KiB` chunks) |
| 12 | Session resumption | `not supported` (Amber) | `demo.json` Step 11 (`D-05`) |

Clicking any goal pill opens the **Goal / Phase Explorer** in the main workspace (replacing Overview while keeping Sidebar, Header, and the 12-Goal Strip visible).

---

## 4. Overview Workspace (5 Panels + Evidence Loader)

Keep the Overview clean and high-signal, with **View Details** actions on Panels 2–5 that route directly to their dedicated views.

### Panel 1: 12-Step Cluster Storyboard (`demo.json`)
- **Interactive Topology Diagram (Inline SVG):**
  - **Control Plane (`127.0.0.1:7400`)** connected to **Node A (`7401`)**, **Node B (`7402`)**, **Node C (`7403`)** (signed policy snapshot push + 250 ms signed head poll).
  - **Devices:** `alice-phone`, `alice-laptop`, `bob-laptop`, `alice-phone-2` connected to nodes via challenge-signed requests (`GET /v1/challenge` + `POST /v1/<op>`).
  - **Node States:** `Healthy` (green), `Lease expired` (amber/red fail-closed at `5,000 ms`), `Disconnected` (muted/dashed).
  - **Device States:** `Active` (green), `Revoked` (red), `Pending` (amber).
- **12-Step Scrubber (`Step 1..12` from `demo.json`):**
  - Displays current step `n`, `title`, `goal`, `status`, `duration_ms`, and `details[]`.
  - Stepping from 1 to 12 dynamically updates node epochs/versions (`v1 → v2 → v3`), `alice-phone` (`Active → Revoked` at Step 5), `alice-phone-2` (`Pending → Active` at Step 6), CP `SIGKILL` state (Step 7), and links to the corresponding Goal view.

### Panel 2: Revocation & PQC Latency (`bench-revocation.json`, `bench-perf.json`)
- Compact horizontal SVG bar chart showing:
  - Nodes `A`, `B`, `C` first-denial `p50` (`32.7–33.7 ms`), `p95` (`45.8–48.3 ms`), and `max` (`147.7–160.5 ms`) vs. `5,000 ms` partition fail-closed bound.
  - Key primitive timings (`ML-KEM-768` encaps `0.033 ms`, `ML-DSA-65` sign `1.026 ms`, `AES-256-GCM 64 KiB` seal `0.066 ms`, Round 1 `protected_read` `54.1 ms`).
- **View Details** → opens `Telemetry` view.

### Panel 3: Tamper-Evident Audit Chain (`demo.json`, `crash-test.json`)
- Visual SVG chain: `Genesis → Seq 1 → Seq 2 → … → External ML-DSA-65 Anchor` with green verification checks.
- Compact status strip: `verifyChain` 1k events `p50 = 21.0 ms`, `~229 B/event`, `5/5` crash recovery points (`50/50` checks).
- **View Details** → opens `Audit & Crash` view.

### Panel 4: Explainable Anomaly Detector (`detect-practice.json`, `bench-detect.json`)
- Compact summary:
  - Practice set: `22/22` events handled (`0` false alerts), `PRIV-1` (`evt-008..009`), `LM-1` (`evt-010..012`), `evt-015` clock offset corrected (`+2,000 ms → 200 ms`), `evt-013/014` reordered.
  - Synthetic holdout scorecard badge: `F1 = 0.895`, `False alerts / 1k = 0.00`.
  - Mini event timeline strip.
- **View Details** → opens `Detection` view.

### Panel 5: E2EE Messaging & Chunk Simulator (`demo.json` Step 11, `bench-perf.json`)
- Compact summary:
  - Mutual `ML-KEM-768` + `ML-DSA-65` ephemeral handshake (`p50 = 47.5 ms`), `dk_e` wiped on close.
  - `16 KiB` chunk delivery (`4/4` received, `1` reassembled, `exact once` delivered).
  - Negative checks summary (`wrong recipient`, `tampered recipient_device AAD`, `duplicate/cross-restart replay` rejected) + `Session resumption: NOT SUPPORTED (D-05)`.
- **View Details** → opens `Messaging` view.

### Evidence Loader (Drag-and-Drop + Multi-File Picker)
- Supports loading any subset of:
  - `demo.json`
  - `bench-perf.json`
  - `bench-revocation.json`
  - `bench-detect.json`
  - `detect-practice.json`
  - `crash-test.json`
- Uses browser `FileReader` / `File.text()` + `JSON.parse` (strictly local, zero uploads).
- Displays per-file status card: filename, schema validation status (`valid` / `warning` / `error`), parsed record count, and a button to reset to embedded `final-5410c49` baseline data.

---

## 5. Goal / Phase Explorer (Primary Interactive Feature)

Clicking any of the 12 goal pills in the top strip opens a dedicated **Goal Detail View** in the main workspace (retaining Sidebar, Header, and 12-Goal Strip) with **Previous Goal**, **Next Goal**, and **Back to Overview** controls plus URL hash sync (`#goal/1` … `#goal/12`, `#overview`, `#telemetry`, `#audit`, `#detection`, `#messaging`, `#about`).

Each of the 12 Goals renders **five consistent sections**:

1. **Goal Overview:** Goal number (`1–12`), name, honesty status badge (`measured`, `measured (synthetic)`, `measured (stated scope)`, `not supported`), purpose, security objective, and involved KIG modules (`src/cp/*`, `src/node/*`, `src/core/*`, `src/detect/*`, `src/messaging/*`).
2. **Operations Performed (Chronological Timeline):** Numbered operation cards derived from `docs/architecture.md` and `demo.json`, each showing:
   - Operation name & description
   - Responsible actor/component (e.g., `CP`, `Node A/B/C`, `alice-laptop`, `Detector`)
   - Input → Action performed → Result
   - Linked evidence event/check (when present in loaded JSON)
3. **Architecture / Flow Diagram (Inline SVG):** Tailored diagram per goal:
   - Goal 1: `PREPARING → STAGED → COMMITTED → ACTIVE` + `30 s` grace vs. epoch cutoff
   - Goal 2: `CP revoke → signed PolicySnapshot push + 250 ms head poll → Nodes A/B/C deny`
   - Goal 3: `rotation_journal` 5-point `SIGKILL` abort vs. roll-forward
   - Goal 4: `VACUUM INTO → AES-256-GCM + ML-KEM-768 wrap → ML-DSA-65 manifest → 6-stage restore`
   - Goal 5: `Genesis → hash_n = SHA-256(hash_{n-1} || encode(event)) → external ML-DSA-65 anchor`
   - Goal 6: `Ingest → Clock → Reorder Buffer → Role Tracker → PRIV-1/PRIV-2`
   - Goal 7: Directed access graph (`reports → billing → archive → identity`) vs. `expected_enforcement`
   - Goal 8: `corrected = event_time - offset` (`±5,000 ms` bound, `5,000 ms` watermark, `±250 ms` uncertainty)
   - Goal 9: Record AAD binding (`session_id`, `sender_dev`, `recipient_dev`, `epoch`, `seq`, `chunk_idx`, `chunk_total`) + persisted 64-bit replay window
   - Goal 10: Ephemeral `(ek_e, dk_e)` lifecycle & `dk_e` zeroisation vs. post-close `ML-DSA-65` key leak
   - Goal 11: `16 KiB` chunk split → seeded loss/duplication/reordering → max 3 retries → reassembly
   - Goal 12: Explicit `D-05` rejection flow (fresh handshake required; closed/revoked `session_id` rejected)
4. **Evidence Inspector:** Source JSON filename, relevant record/event IDs, key fields, timestamps, parsed values, verification outcome, and an **expandable raw JSON viewer** (`<details>` / toggle).
5. **Verification & Metrics:** Expected vs. observed behavior, pass/fail result, relevant latency/accuracy numbers, and honest limitations/scope boundaries.

---

## 6. Dedicated Deep-Dive Views

### A. Telemetry View (`#telemetry`)
- **Revocation Benchmark (`bench-revocation.json`):** Per-node `first_denial_ms` & `signed_ack_ms` (`p50`, `p95`, `max`) across `n = 100` runs (`last_node: C`), plus `partition` (`node: A`, `lease_ms: 5000`, `result: lease_expired`).
- **Round 1 Adapter Whole-Process (`bench-perf.json` → `adapter_whole_process`):** `empty_node`, `setup_small`, `read_allow`, `read_deny`, `revoke`, `audit_hit`, `audit_miss`, `protected_read_allow`, `protected_read_invalid_key`, `setup_1mib`, `setup_near_4mib_cap` compared against the `8,000 ms` validator budget.
- **In-Process Primitives (`bench-perf.json` → `crypto_in_process`, `sqlite_in_process`, `cluster_round2`):** `ML-KEM-768`, `ML-DSA-65`, `AES-256-GCM` (`1/64/256 KiB`), `HKDF-SHA-256`, `HMAC-SHA-256`, `audit.append`, and Round 2 `file.read`.

### B. Audit & Crash Inspector (`#audit`)
- **Interactive Tamper Simulator** (operates on an in-memory copy, never mutates loaded evidence):
  - Buttons: `Valid Chain`, `Edit Row`, `Truncate Tail`, `Inject Newline JSON`, `Stale Backup`, `Bit Flip`.
  - Displays verification progress, first failing `seq`, failure code (`content_edit`, `truncated`, `stale_backup`, `digest_mismatch`, or `OK — single record` for newline injection), and chain integrity badge.
- **5-Point Crash Recovery Matrix (`crash-test.json`):** Interactive table/cards for `after_prepare`, `after_stage`, `before_commit`, `after_commit`, `during_distribute`, expanding all 10 invariant checks per point (`cp_killed_at_point`, `journal_at_crash`, `recovery_action`, `epoch_never_decreases`, `revoked_stays_revoked`, `custodian_test_decrypt`, etc.).

### C. Anomaly Detection View (`#detection`)
- **Practice Set Explorer (`detect-practice.json`):** Interactive alert list (`PRIV-1/PRIV-2`, `LM-1`, `LM-2`, `LM-3`), clock-skew & reorder watermark timeline (`evt-013/014/015`), lateral movement directed graph, and `expected_enforcement` (`evt-017/018`) filter.
- **Synthetic Benchmark Scorecard (`bench-detect.json`):** Clearly labeled **`SYNTHETIC GENERATOR (seeds 201–205, 6,784 events)`** — `F1: 0.895`, `Precision: 1.000`, `Recall: 0.810` (`1.000` on detectable), `Median TTA: 4,810 ms`, `False alerts / 1k benign: 0.00`, `Evasive misses (low-and-slow / 2-edge): 20`.

### D. E2EE Messaging View (`#messaging`)
- Interactive **3-Message Handshake & Forward Secrecy** walkthrough (`M1`, `M2`, `M3`, `TH1`, `TH2`, `session_id`, `dk_e` wipe).
- **16 KiB Chunk Delivery Simulator:** Deterministic seeded step-through showing chunk split (`4/4`), simulated drop/duplicate/reorder, `max 3` retries, `chunk_total` AAD authentication, and separate reporting of transport receipt vs. reassembly vs. exact-once delivery.
- **Negative-Test Matrix & Goal 12 Disclosure:** Wrong recipient, tampered `recipient_device` AAD, duplicate replay, cross-restart replay (`device.db` persisted window), and `Session resumption: NOT SUPPORTED (D-05)`.

---

## 7. Data Architecture & Parsing Rules

1. **Centralized State (`AppState`):**
   - `activeSection`: `'overview' | 'telemetry' | 'audit' | 'detection' | 'messaging' | 'about' | 'goal'`
   - `activeGoal`: `1..12`
   - `activeStoryboardStep`: `1..12`
   - `evidence`: `{ demo, benchPerf, benchRevocation, benchDetect, detectPractice, crashTest }`
   - `fileMeta`: per-file `{ loaded, source: 'embedded' | 'file', filename, status, recordCount, warnings[] }`
   - `auditSimMode`: `'valid' | 'edit_row' | 'truncate_tail' | 'newline_json' | 'stale_backup' | 'bit_flip'`
2. **Exact Schema Mapping (no invented fields):**
   - `demo.json`: reads `commit`, `duration_ms`, `fast`, `seed`, `pass`, `passed_steps`, `total_steps`, `steps[]` (`n`, `title`, `goal`, `status`, `details[]`, `duration_ms`).
   - `bench-perf.json`: reads `environment`, `config`, `results.process_baseline`, `results.adapter_whole_process`, `results.crypto_in_process`, `results.sqlite_in_process`, `results.cluster_round2`.
   - `bench-revocation.json`: reads `seed`, `n`, `clock`, `nodes.{A,B,C}.{first_denial_ms, signed_ack_ms}.{p50,p95,max}`, `last_node`, `partition.{node,lease_ms,result}`, `limitations[]`.
   - `bench-detect.json`: reads `data_origin`, `seeds`, `config`, `scenario_mix_per_seed`, and aggregate/per-seed metrics.
   - `detect-practice.json`: reads `alerts[]` (`alert_id`, `rule_id`, `severity`, `classification`, `identity`, `services[]`, `path[]`, `event_ids[]`, `outcomes[]`, `reason`, `order_uncertain`, `window`, `tta_ms`) and event/timeline fields if present.
   - `crash-test.json`: reads `points[]` (`point`, `expected_action`, `rotation.{from,to}`, `active_after`, `pass`, `checks[]`).
3. **Graceful Degradation:** Missing or partial files never crash rendering; unavailable metrics render as `N/A` with a visible notice, and newly loaded files never silently fall back to embedded sample values for fields that are missing in the uploaded file.

---

## 8. Code Organization Inside `dashboard.html`

Structure the `<script>` into clean, clearly delimited sections:
1. `APP_META` & `GOALS_CONFIG` (12 goals, operations, diagrams, scope notes)
2. `EMBEDDED_EVIDENCE` (initial snapshot from `evidence/final-5410c49/` for `file://` out-of-the-box usability)
3. `EvidenceParser` (safe validation, normalization, warning collection)
4. `AppState` & `Router` (hash navigation, state updates without losing loaded files)
5. `SvgCharts` (reusable horizontal bar, chain, topology, timeline, and graph builders)
6. `Views` (`renderOverview`, `renderGoalDetail`, `renderTelemetry`, `renderAudit`, `renderDetection`, `renderMessaging`, `renderAbout`)
7. `EventHandlers` (drag-and-drop, file input, storyboard scrubber, audit fault simulator, raw JSON toggles, keyboard accessibility)

---

## 9. Acceptance Checklist

1. Opens directly via `file://` in Chrome/Edge/Firefox with zero console errors and zero network requests.
2. All 12 Track 4 goal pills open full Goal Detail views with operations, SVG diagram, evidence inspector, and verification metrics; Prev/Next and Back to Overview preserve loaded evidence.
3. All 5 Overview panels + 12-step storyboard + drag-and-drop multi-file JSON loader work end-to-end.
4. Telemetry, Audit & Crash, Detection, and Messaging views render charts and tables from parsed evidence, display `N/A` for missing fields, and never misrepresent Goal 12 (`not supported`) or synthetic detection metrics.
5. Responsive down to tablet and mobile widths with collapsible/compact navigation and scrollable 12-goal strip.
