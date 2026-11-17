# P0 Submission Stabilization Report

**Date:** 2026-11-17  
**Base Commit:** `93dbf8e` (uncommitted working-tree stabilization for user review)  
**Environment:** Windows 11, Intel Core i5-1135G7, ~8 GB RAM, Python `3.13.2`, CPU-only PyTorch `2.8.0+cpu`

---

## 1. Changes Made & Files Modified

1. **`app/main.py` (Telemetry Performance Fix):**
   - Cached `cpuinfo.get_cpu_info().get("brand_raw", platform.processor())` once at startup in `_CACHED_CPU_BRAND` instead of invoking WMI/subprocess CPU identification on every `GET /api/status` call.
   - Primed `psutil.cpu_percent(interval=None)` at startup and switched `get_system_telemetry()` to non-blocking `psutil.cpu_percent(interval=None)`.
   - Added a 15-second TTL cache (`_CONNECTIVITY_CACHE`) for `check_internet_connectivity()` while preserving all existing telemetry fields and fallback error handling.
2. **`.gitignore` (Git Hygiene):**
   - Backed up `data/processed/detection_history.json` and `data/processed/incidents_history.json` to the conversation scratch backup directory before restoring `detection_history.json`.
   - Added `data/processed/incidents_history.json` and `data/processed/detection_history.json` to `.gitignore` while keeping all datasets (`data/raw/*.csv`, `data/processed/dataset_manifest.json`, `data/processed/sample_network_traffic.pcap`), trained models, and evaluation results tracked.
3. **`README.md` (Setup, Offline Modes & Limitations Completion):**
   - Added Windows PowerShell virtual environment creation/activation (`python -m venv .venv`, `.\.venv\Scripts\Activate.ps1`) and dependency installation steps.
   - Added launch command (`python scripts/run_application.py --host 127.0.0.1 --port 8501`), browser URL (`http://127.0.0.1:8501`), and offline mode env vars (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`).
   - Documented `FAST TRIAGE` (default, zero LLM, no `.pte` required) vs `DEEP ANALYSIS` (optional, lazy-loads `SmolLM2-135M-Instruct` `.pte`, requires `python scripts/export_llama_executorch.py` on a fresh clone, deterministic fallback if unavailable).
   - Linked existing verified evaluation figures (`demo/screenshots/*.png`) and documented honest hardware/dataset limitations.

---

## 2. Before / After Telemetry Performance (`GET /api/status`)

| Metric | Before P0 Fix | After P0 Fix (25 consecutive requests) | Improvement |
|---|---:|---:|---|
| `GET /api/status` Median (P50) | `2,372.28 ms` | **`15.92 ms`** | **`149x` faster** (well below 50 ms target) |
| `GET /api/status` P95 | — | **`31.84 ms`** | — |
| `GET /api/status` Min / Max | — | `12.88 ms` / `113.31 ms` (1st req) | `25/25` HTTP `200 OK` |

---

## 3. Regression & Live Offline Endpoint Results

1. **Automated Test Suite (`python -m unittest discover -s tests -p "test_*.py" -v`):**
   - **`Ran 39 tests in 349.430s -> OK`** (`0` failures, `0` skipped).
2. **Live Flask Server (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, port `8519`):**
   - Server ready in `17.7 s` (`GET /`: `200`, `7.97 ms`).
   - `POST /api/v2/analyze/url`: `200` (`3610.06 ms` cold first call)
   - `POST /api/v2/analyze/sms`: `200` (`69.08 ms`)
   - `POST /api/v2/analyze/network`: `200` (`93.19 ms`, correlated into `INC-20261117-0025`)
   - `POST /api/v2/pcap/sample`: `200` (`1679.62 ms`)
   - `GET /api/v2/demo/scenarios`: `200` (`12.85 ms`)
   - `POST /api/v2/demo/run` (`demo_10_microservice_burst`): `200` (`92.77 ms`)
   - `GET /api/v2/incidents`: `200` (`34.29 ms`)
   - `GET /api/v2/benchmarks`: `200` (`24.42 ms`)
   - `GET /api/v2/incidents/<id>/export?format=json&redact=true`: `200` (`12.12 ms`, `1773` bytes)
   - `GET /api/v2/incidents/<id>/export?format=markdown&redact=true`: `200` (`25.43 ms`, `1306` bytes)

---

## 4. Remaining Issues

- `data/processed/detection_history.json` is still tracked in Git's index; if you want future runtime runs never to mark it modified, run `git rm --cached data/processed/detection_history.json` when committing.
- Live browser screenshots of the 10-view Flask UI are not yet captured (`README.md` currently links the verified evaluation plots in `demo/screenshots/`).
- Meta Llama 3.2 ExecuTorch (`.pte`) and physical ARM64 / PYNQ-Z2 hardware execution remain unverified on this Windows host.
