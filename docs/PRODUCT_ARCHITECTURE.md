# SecureEdge AI — Product Architecture (Phase 4 — Task 1)

## 1. Primary Interface Decision
**Decision:** Standardize on the **Flask Dashboard + REST API** (`app/main.py` + `app/templates/index.html`) as the single primary competition interface.

**Rationale:**
- `app/main.py` already powers the end-to-end integration test suite (`tests/integration/test_end_to_end_pipeline.py`), runs locally on `127.0.0.1:8501`, and serves both the 10-section SOC web UI and structured REST endpoints (`/api/v2/*`) from one lightweight Python process (`~72.5 MB` RSS in `FAST TRIAGE`).
- Maintaining a separate Streamlit UI (`app/streamlit_app.py`) alongside Flask would create inconsistent UX, duplicate state, and extra memory overhead on an 8 GB RAM host.

## 2. Layered Architecture
1. **Presentation Layer (`app/templates/index.html`):** 10-view dark SOC console (Overview, URL Scanner, SMS Analyzer, Network Analyzer, PCAP Upload/Replay, Unified Intelligence & Demo, Incident History, Incident Detail & Export, Performance Benchmarks, System & Offline Status) with strict client-side HTML escaping (`esc()`).
2. **API & Security Layer (`app/main.py`):** Localhost-only (`127.0.0.1`) Flask server with defensive HTTP headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`), input length caps (`URL <= 2048`, `SMS <= 5000`), bounded PCAP uploads (`2 MB`, magic-byte + extension validation, isolated `TemporaryDirectory`), and zero automatic remote URL fetching.
3. **Decision & Policy Layer (`src/threat_engine/calibrated_policy.py`):** `CalibratedThreatEngine` defaults to `FAST TRIAGE` (zero LLM, deterministic policy) with optional `DEEP ANALYSIS` (`SmolLM2-135M` comparison static graph) and graceful deterministic fallback.
4. **Correlation & Reporting Layer (`src/threat_engine/incidents.py`):** LLM-independent `IncidentCorrelationEngine` with bounded retention (`MAX_INCIDENTS = 200`), PII/network redaction, and JSON/Markdown export.
5. **Specialized Detectors (Phase 3):** `HardenedURLDetector`, `HardenedSMSDetector`, and `ContextAwareNetworkDetector`.
