# SecureEdge AI

**On-Device Threat, Phishing, and Scam Detection with Calibrated Risk Policy & Incident Correlation**  
**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 | **Problem Statement:** PS3 (Cybersecurity & Digital Safety)

---

## 1. Overview & Compliance Transparency

**SecureEdge AI** is an offline-capable cybersecurity assistant that detects **phishing URLs**, **obfuscated/Hinglish scam SMS messages**, and **network traffic threats** locally on-device, correlates related observations into unified incidents, and exports redacted JSON/Markdown reports.

> **Honest Hardware & Model Status:**
> - **Verified on Host:** Windows 11, Intel Core i5-1135G7, ~8 GB RAM, Python `3.13.2`, CPU-only PyTorch `2.8.0+cpu`.
> - **Comparison LLM:** Optional `DEEP ANALYSIS` runs **`HuggingFaceTB/SmolLM2-135M-Instruct`** (`134.5M` params, Apache-2.0, `LlamaForCausalLM`) via `torch.export.ExportedProgram`, with graceful deterministic fallback if unavailable.
> - **Not Verified Here:** Official **`meta-llama/Llama-3.2-1B-Instruct`** (`8da4w` XNNPACK `.pte`, Meta Llama 3.2 Community License) and **physical ARM64 deployment** are prepared in `deployment/` but **not executed** on this Windows x86_64 machine.
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

## 3. Feature & Baseline Comparison

| Modality | Baseline (Phase 1/2) | Hardened (Phase 3/4) | Key Verified Gain (Synthetic Benchmarks) |
|---|---|---|---|
| **SMS** | `ScamSMSDetector` (TF-IDF + LinearSVC) | `HardenedSMSDetector` (NFKC, homoglyph, spaced, leetspeak, Hinglish) | Adv Recall: `44.09%` -> **`100.0%`** (`220/220`); `0/55` FP across OTP, bank alert, personal, commercial |
| **URL** | `PhishingURLDetector` (32 lexical features) | `HardenedURLDetector` (44 features + IDN/Punycode + opt-in `SafeRedirectInspector`) | Adv Recall: `60.87%` -> **`93.91%`** (`216/230`); `0.0%` FPR on benign IDNs |
| **Network** | `AdaptiveNetworkDetector` (Phase 2) | `ContextAwareNetworkDetector` (Host MAD baselines + multi-signal confirmation) | Unseen Alert FPR: `85.6%` -> **`0.80%`** (`0/125` false `confirmed_malicious` on microservice bursts; `125/125` normal on SSH) |

---

## 4. Measured Benchmarks (Windows 11 x86_64 CPU-Only)

- **App Startup (Lazy LLM):** `8.38 s` | **`FAST TRIAGE` Peak RSS:** `188.81 MB` | **Dashboard `GET /`:** `13.03 ms`
- **Per-Detector `FAST TRIAGE` Latency:** URL `P50 = 10.31 ms` (`0.342 MB`), SMS `P50 = 5.54 ms` (`0.169 MB`), Network `P50 = 28.11 ms` (`2.216 MB`), 24-flow PCAP replay `982.24 ms`.
- **`DEEP ANALYSIS` (`SmolLM2-135M-Instruct`):** `P50 = 11.83 s`, `P95 = 19.79 s`, `RSS = 595.43 MB` (`520.94 MB` `.pte`, `.gitignore`'d).

---

## 5. Installation, Demo & Testing

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the unified 10-view localhost dashboard (FAST TRIAGE default)
python scripts/run_application.py --host 127.0.0.1 --port 8501
# Open http://127.0.0.1:8501 (follow docs/DEMO_SCRIPT.md for the 5-min walkthrough)

# 3. Run Phase 3 hardening & adversarial evaluation
python scripts/evaluation/run_phase3_hardening.py

# 4. Run complete automated test suite (unit + integration + security + E2E)
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 6. Model Provenance, Licenses & Documentation

- **Comparison LLM:** `HuggingFaceTB/SmolLM2-135M-Instruct` (Apache-2.0) — exported locally via `scripts/export_llama_executorch.py`.
- **Target Meta Llama 3.2:** `meta-llama/Llama-3.2-1B-Instruct` (Meta Llama 3.2 Community License) — Linux export script at `deployment/linux/export_meta_llama_executorch.sh`.
- **Key Reports:**
  - [`docs/PHASE5_FINAL_INTEGRATION_AUDIT.md`](docs/PHASE5_FINAL_INTEGRATION_AUDIT.md)
  - [`docs/PHASE4_PRODUCTIZATION_REPORT.md`](docs/PHASE4_PRODUCTIZATION_REPORT.md)
  - [`docs/PHASE3_EVALUATION_REPORT.md`](docs/PHASE3_EVALUATION_REPORT.md)
  - [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md)
