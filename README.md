# SecureEdge AI

**On-Device Threat, Phishing, and Scam Detection with Calibrated Risk Policy & Incident Correlation**  
**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 | **Problem Statement:** PS3 (Cybersecurity & Digital Safety)

---

## 1. Overview & Compliance Transparency

**SecureEdge AI** is an offline-capable cybersecurity assistant that detects **phishing URLs**, **obfuscated/Hinglish scam SMS messages**, and **network traffic threats** locally on-device, correlates related observations into unified incidents, and exports redacted JSON/Markdown reports.

> **Honest Hardware & Model Status:**
> - **Verified on Host:** Windows 11, Intel Core i5-1135G7, ~8 GB RAM, Python `3.13.2`, CPU-only PyTorch `2.8.0+cpu`.
> - **Comparison LLM:** Optional `DEEP ANALYSIS` runs **`HuggingFaceTB/SmolLM2-135M-Instruct`** (`134.5M` params, Apache-2.0, `LlamaForCausalLM`) via `torch.export.ExportedProgram`, with graceful deterministic fallback if unavailable.
> - **Not Verified Here:** Official **`meta-llama/Llama-3.2-1B-Instruct`** (`8da4w` XNNPACK `.pte`, Meta Llama 3.2 Community License) and **physical ARM64 / PYNQ-Z2 deployment** are prepared in `deployment/` but **not executed** on this Windows x86_64 machine.
> - **Evaluation Scope:** All Phase 1–4 accuracy, FPR, and demo benchmarks use **synthetic or curated local datasets**, not real-world field telemetry.

---

## 2. System Architecture

```text
  URL Input ──► HardenedURLDetector (44 lexical/IDN/redirect features) ──┐
  SMS Input ──► HardenedSMSDetector (Word+Char TF-IDF + 20 obf features) ├──► CalibratedThreatEngine
  PCAP/Flow ──► ContextAwareNetworkDetector (MAD + HGB + IsoForest) ─────┘      │
                                                                                ├── FAST TRIAGE (Default, Zero LLM)
                                                                                ├── DEEP ANALYSIS (Optional SmolLM2-135M + Fallback)
                                                                                ▼
                                                                   IncidentCorrelationEngine (Exact URL / Domain / IP)
                                                                                │
                                                                                ▼
                                                             10-View Flask Dashboard & Redacted JSON/MD Export
```

---

## 3. Windows PowerShell Setup & Launch

```powershell
# 1. Create and activate a Python virtual environment (Windows PowerShell)
python -m venv .venv
# If PowerShell blocks script execution, run:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

# 2. Upgrade pip and install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. (Optional — only if you want local LLM DEEP ANALYSIS on a fresh clone)
# Regenerate the >100 MB comparison .pte/.pt2 artifact excluded from Git:
python scripts/export_llama_executorch.py

# 4. Launch the unified 10-view localhost dashboard (FAST TRIAGE default)
python scripts/run_application.py --host 127.0.0.1 --port 8501
```

- **Browser URL:** Open `http://127.0.0.1:8501` (binds to localhost only).
- **Offline Mode:** Runs 100% locally with zero cloud APIs and zero automatic remote URL fetching. You can force strict offline mode in PowerShell with:
  ```powershell
  $env:HF_HUB_OFFLINE = "1"
  $env:TRANSFORMERS_OFFLINE = "1"
  python scripts/run_application.py --host 127.0.0.1 --port 8501
  ```

---

## 4. Operating Modes & Model Setup (`FAST TRIAGE` vs `DEEP ANALYSIS`)

| Mode | Default? | LLM Required? | Behavior & Resource Profile |
|---|---|---|---|
| **`FAST TRIAGE`** | **Yes** | **No** | Uses calibrated ML detectors + deterministic `CalibratedDecisionPolicy`. Zero LLM weights loaded into RAM (`~189 MB` RSS). Works immediately out of the box without any `.pte` file. |
| **`DEEP ANALYSIS`** | No (Opt-in) | Optional | Lazy-loads the exported `SmolLM2-135M-Instruct` static graph (`models/llama_executorch/smollm2_135m_cyber_advisor.pte` + `models/llama_executorch/tokenizer/`). Detector-locked `risk_level` cannot be downgraded; if the `.pte` artifact is missing or incompatible, falls back cleanly to a deterministic explanation. |

---

## 5. Feature & Baseline Comparison

| Modality | Baseline (Phase 1/2) | Hardened (Phase 3/4) | Key Verified Gain (Synthetic Benchmarks) |
|---|---|---|---|
| **SMS** | `ScamSMSDetector` (TF-IDF + LinearSVC) | `HardenedSMSDetector` (NFKC, homoglyph, spaced, leetspeak, Hinglish) | Adv Recall: `44.09%` -> **`100.0%`** (`220/220`); `0/55` FP across OTP, bank alert, personal, commercial |
| **URL** | `PhishingURLDetector` (32 lexical features) | `HardenedURLDetector` (44 features + IDN/Punycode + opt-in `SafeRedirectInspector`) | Adv Recall: `60.87%` -> **`93.91%`** (`216/230`); `0.0%` FPR on benign IDNs |
| **Network** | `AdaptiveNetworkDetector` (Phase 2) | `ContextAwareNetworkDetector` (Host MAD baselines + multi-signal confirmation) | Unseen Alert FPR: `85.6%` -> **`0.80%`** (`0/125` false `confirmed_malicious` on microservice bursts; `125/125` normal on SSH) |

---

## 6. Measured Benchmarks & Evaluation Figures

- **App Startup (Lazy LLM):** `~8.4–11.2 s` | **`FAST TRIAGE` Peak RSS:** `~189 MB` | **Dashboard `GET /`:** `~11–13 ms`
- **Per-Detector `FAST TRIAGE` Latency:** URL `P50 = 10.31 ms` (`0.342 MB`), SMS `P50 = 5.54 ms` (`0.169 MB`), Network `P50 = 28.11 ms` (`2.216 MB`), 24-flow PCAP replay `< 1.6 s`.
- **`DEEP ANALYSIS` (`SmolLM2-135M-Instruct`):** `P50 = 11.83 s`, `P95 = 19.79 s`, `RSS = 595.43 MB` (`520.94 MB` `.pte`, `.gitignore`'d).

### Verified Evaluation Plots & Dashboard Screenshots
- [Model Comparison (F1 / AUC)](demo/screenshots/model_comparison_f1_auc.png)
- [Pipeline Latency Breakdown](demo/screenshots/pipeline_latency_breakdown.png)
- [Confusion Matrices](demo/screenshots/confusion_matrices.png)
- [Dashboard: Security Overview](docs/submission/screenshots/01_security_overview.png) | [URL Scanner](docs/submission/screenshots/02_url_threat_scanner.png) | [SMS Analyzer](docs/submission/screenshots/03_sms_scam_analyzer.png) | [Network Analyzer](docs/submission/screenshots/04_network_analyzer.png) | [Incident History](docs/submission/screenshots/05_incident_history.png) | [Incident Detail & Export](docs/submission/screenshots/06_incident_detail_export.png)

---

## 7. Known Limitations, Testing & Provenance

- **Known Limitations:** Meta Llama 3.2 (`meta-llama/Llama-3.2-1B-Instruct`, Meta Llama 3.2 Community License) + native ExecuTorch (`8da4w` XNNPACK) and physical ARM64 / PYNQ-Z2 execution remain **unverified** on this Windows host (see `deployment/linux/export_meta_llama_executorch.sh`). Evaluation datasets are synthetic/curated.
- **Automated Test Suite:** `python -m unittest discover -s tests -p "test_*.py" -v` (`39` unit, integration, security, and E2E tests).
- **Phase 3 Evaluation:** `python scripts/evaluation/run_phase3_hardening.py`
- **Offline Demo Mode:** Open `6. Unified Intelligence & Demo` in the dashboard (`http://127.0.0.1:8501`) for 1-click synthetic scenarios (see [`docs/DEMO_SCENARIOS.md`](docs/DEMO_SCENARIOS.md)).
- **Audit Reports:** [`docs/FINAL_SUBMISSION_READINESS_AUDIT.md`](docs/FINAL_SUBMISSION_READINESS_AUDIT.md), [`docs/PHASE5_FINAL_INTEGRATION_AUDIT.md`](docs/PHASE5_FINAL_INTEGRATION_AUDIT.md).
