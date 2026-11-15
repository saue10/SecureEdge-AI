# SecureEdge AI — Initial Competition Readiness Audit

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27  
**Problem Statement:** PS3 — On-Device Threat, Phishing & Scam Detection  
**Audited Repository State:** Branch `main` at commit `f2f5715` (following `4c005b3`)  
**Audit Date:** 15 November 2026  
**Confirmed Phase 1 Submission Deadline:** 23 November 2026  

---

## 1. Executive Assessment

**SecureEdge AI** is a well-structured, modular, offline-capable cybersecurity prototype combining three calibrated ML threat detectors (URL, SMS, Network/Scapy), a schema-validated Unified Threat Engine, a dark-themed Flask dashboard with REST APIs, and a local `LlamaForCausalLM` explanation path (`SmolLM2-135M-Instruct` via `torch.export.ExportedProgram`). All 16 automated unit and integration tests pass (`213.959s`) on the Windows 11 development laptop.

However, from a **competition-winning and PS3-compliance** standpoint, this audit identifies **two critical credibility gaps** and **two concrete technical gaps** that must be addressed honestly and decisively before submission:
1. **Mandatory Technology Gap (Meta Llama + Native ExecuTorch):** The current runnable LLM is `HuggingFaceTB/SmolLM2-135M-Instruct` (a SmolLM2-family comparison model), **not** an authentic Meta Llama checkpoint, and runs via `torch.export.ExportedProgram.module()` on Windows rather than native `executorch.runtime.Runtime` (which is blocked on this Windows 11 host by `torch >= 2.10` `c10.dll` DLL initialization failures and missing `HF_TOKEN`).
2. **Dataset Realism & Leakage Gap (`F1 = 1.0000` Investigation):** All three detectors report `F1 = 1.0000` on synthetic/templated corpora (`scripts/download_datasets.py`). Crucially, `data/raw/sms_dataset.csv` contains **390 exact duplicate rows (32.5%)**, causing **103 exact training messages (`34.3%` of the 300-row test set)** to leak into the stratified test split.

---

## 2. Current Implementation Status (Repository Audit)

### 2.1 Git & Workspace State
- **Active Branch:** `main` (`f2f5715` — *Finalize evidence-based Llama & ExecuTorch compliance audit after 4c005b3*).
- **Backup Baseline:** Branch `backup-baseline` / tag `pre-audit-baseline` at `adf65b9`.
- **Uncommitted Changes:** `M data/processed/detection_history.json` (runtime history log appended during Flask integration tests). All source code, models, and documentation files are committed.

### 2.2 Directory & Module Inventory
- **`src/` (Core Engine):**
  - `src/common/`: `config.py`, `logger.py`, `schemas.py` (Pydantic contracts).
  - `src/url_detection/`: `features.py` (32 lexical/host features), `detector.py` (`RandomForest_Calibrated`).
  - `src/sms_detection/`: `features.py` (word/char TF-IDF + 12 structural indicators), `detector.py` (`Calibrated_LinearSVC`).
  - `src/network_detection/`: `collector.py` (Scapy `rdpcap`/`sniff` + 5-tuple flow aggregator), `features.py` (16 flow features), `detector.py` (`RandomForest_Calibrated` + `IsolationForest`).
  - `src/threat_engine/`: `engine.py` (`UnifiedThreatEngine` with detector-locked `risk_level` guardrails).
  - `src/executorch/`: `exporter.py`, `runtime.py` (dual-path native `executorch` + Windows `ExportedProgram` fallback; auto-discovers `llama_3_2_1b_8da4w.pte` if present).
  - `src/llama/`: `advisor.py` (offline HF tokenizer + bounded prompt + Pydantic output), `tokenizer.py` (legacy 512-token fallback).
- **`app/`:** `main.py` + `templates/index.html` (8-section offline dark Flask dashboard + REST API); `streamlit_app.py` (secondary duplicate UI).
- **`scripts/`:** `download_datasets.py`, `train_models.py`, `evaluate_models.py`, `export_llama_executorch.py`, `run_application.py`.
- **`deployment/`:** `linux/export_meta_llama_executorch.sh`, `arm64/Dockerfile.arm64`, `arm64/verify_arm64_executorch.py`, `raspberry_pi/setup_rpi5.sh`, `android/setup_termux_android.sh`.
- **`models/`:**
  - `url_detector/url_detector_pipeline.joblib` (`0.256 MB`), `sms_detector/sms_detector_pipeline.joblib` (`0.063 MB`), `network_detector/network_detector_pipeline.joblib` (`0.530 MB`).
  - `llama_executorch/smollm2_135m_cyber_advisor.pte` & `.pt2` (`520.943 MB` each, `.gitignore`d >100 MB), `tokenizer/` (`3.360 MB`), `experimental_mini_llama/` (`3.165 MB` 574K-param prototype preserved).
- **`tests/`:** `tests/unit/test_detectors_and_llama.py` (12 tests) and `tests/integration/test_end_to_end_pipeline.py` (4 tests).

### 2.3 Compliance Matrix Against PS3 Requirements

| PS3 Requirement | Status | Category | Evidence / Notes |
| :--- | :---: | :--- | :--- |
| **Phishing URL Detection** | ✅ | Demonstrated | 32 lexical/host features + `RandomForest_Calibrated` (`49.14 ms` mean latency) |
| **Scam & Spam SMS Detection** | ✅ | Demonstrated | Word/Char TF-IDF + 12 fraud rules + OTP safeguard (`5.46 ms` mean latency) |
| **Network Anomaly Detection** | ✅ | Demonstrated | Scapy PCAP replay (`126` packets) + `RandomForest_Calibrated` & `IsolationForest` (`43.71 ms`); live sniff requires Npcap/Admin |
| **Offline Operation & Local UI** | ✅ | Demonstrated | Zero cloud APIs, zero CDN links in `index.html`, local `tokenizer/` (`local_files_only=True`) |
| **Plain-Language Explanation & Remediation** | ✅ | Demonstrated | `LlamaCyberAdvisor` + `UnifiedThreatEngine` grounded advisories (using `SmolLM2-135M-Instruct` on host) |
| **Meta Llama Checkpoint (`Llama-3.2-1B-Instruct`)** | ⚠️ | Implemented / Unverified | Auto-discovery & `8da4w` export code/scripts ready; **blocked** by `gated=manual` (`HF token present: False`) |
| **Native ExecuTorch Runtime (`.pte`)** | ⚠️ | Implemented / Unverified | Native `executorch.exir` / `executorch.runtime` paths wired; **blocked** on Windows (`torch>=2.10` `c10.dll` error) |
| **ARM64 Edge Deployment** | ❌ | Missing Physical Validation | Scripts/Dockerfile ready (`HOST_PREPARED_PENDING_PHYSICAL_ARM64_BOARD`); no Raspberry Pi 5 / Android hardware attached |

---

## 3. Hardware & Software Limitations (Laptop Capability Audit)

- **OS & Architecture:** `Windows-11-10.0.26200-SP0`, `AMD64`
- **CPU:** `Intel64 Family 6 Model 140 Stepping 1` (11th Gen Intel Core i5-1135G7 @ 2.40 GHz, 4 physical / 8 logical cores, no GPU)
- **RAM:** `8.32 GB` (`7.75 GiB`) total; **`0.93 GB` available (`88.8%` used)** under normal desktop load; `15.10 GB` swap free
- **Disk Space:** `C:/` `6.53 GB` free (too tight for large HuggingFace caches); `F:/` `52.44 GB` free
- **Python Environment:** `Python 3.13.2`, `torch 2.8.0+cpu`, `transformers 5.17.0`, `huggingface_hub 1.32.0`, `scikit-learn 1.8.0`, `scapy 2.6.1`
- **Unavailable Tools:** No `docker`, no `wsl` (`Wsl/E_ACCESSDENIED`), no `executorch`, no `torchao`.
- **What Can Be Developed & Tested Entirely on Windows:** All ML detector improvements, real-world dataset curation & deduplication, adversarial robustness evaluation, latency/memory optimization, Flask dashboard/API enhancements, `SmolLM2-135M` static-graph testing, and documentation/demo recording.

---

## 4. Compliance Gaps

1. **Meta Llama Provenance Gap:** `SmolLM2-135M-Instruct` uses `LlamaForCausalLM` but is **not** a Meta Llama checkpoint. Meta Llama compliance cannot be claimed until `meta-llama/Llama-3.2-1B-Instruct` (or `1B`/`3B` Meta checkpoint) is exported and executed through ExecuTorch.
2. **Native ExecuTorch Runtime Gap:** On Windows, `ExportedProgram.module()` executes `.pt2` static graphs rather than `executorch.runtime.Runtime` executing an XNNPACK-lowered FlatBuffer `.pte`.
3. **Physical ARM64 Hardware Gap:** Zero measured Raspberry Pi 5 / Android latency or wattmeter telemetry exists yet.

---

## 5. Dataset & Model Evaluation Audit (Why `F1 = 1.0000` Is Misleading)

| Dataset | Rows | Class Balance | Exact Duplicates | Split & Leakage Findings | Reported Metrics |
| :--- | :---: | :--- | :---: | :--- | :--- |
| **`url_dataset.csv`** | 1,600 | 800 benign / 800 phishing | 4 | `GroupShuffleSplit` on `registered_domain` (`0` domain overlap across 300 test domains), **but 100% synthetically generated** from templates in `download_datasets.py` | `RF_Calibrated`: Acc `1.0000`, F1 `1.0000`, FPR `0.0000` (TN=176, FP=0, FN=0, TP=208) |
| **`sms_dataset.csv`** | 1,200 | 600 ham / 514 scam / 86 spam | **390 (32.5%)** | **Severe Leakage:** Stratified 75/25 split leaks **103 exact training messages (`34.3%` of 300 test rows)** into the test set | `Calibrated_LinearSVC`: Acc `1.0000`, F1 `1.0000`, FPR `0.0000` (TN=150, FP=0, FN=0, TP=150) |
| **`network_flows_dataset.csv`** | 1,500 | 750 benign / 750 anomaly | 0 | Stratified 75/25 split (375 test flows), **synthetically generated** from non-overlapping statistical distributions | `RF_Calibrated`: Acc `1.0000`, F1 `1.0000`, FPR `0.0000` (TN=188, FP=0, FN=0, TP=187); `LogReg` F1 `0.9106` |

**Audit Conclusion:** Reporting `F1 = 1.0000` across all three modalities without disclosing synthetic generation and the `34.3%` SMS duplicate test leakage will undermine technical credibility with cybersecurity judges.

---

## 6. Critical Defects & Technical Quality Findings

1. **Defect 1 (Critical — Data Leakage):** `sms_dataset.csv` has `390` exact duplicate texts (`34.3%` train-to-test leakage).
2. **Defect 2 (High — Native ExecuTorch I/O Signature Mismatch):** `deployment/linux/export_meta_llama_executorch.sh` invokes `executorch.examples.models.llama.export_llama` (KV-cache `(tokens, input_pos)` signature), whereas `ExecuTorchLlamaRuntime.forward_Step()` passes a stateless `(1, seq_len)` `[input_ids]` tensor.
3. **Defect 3 (Medium — Metadata & Tokenizer Edge Cases):**
   - `LlamaExecuTorchExporter.export_llama_to_pte()` hardcodes `"quantization": "float32 (...)"` in `export_metadata.json` even when `8da4w` is requested.
   - `ExecuTorchLlamaRuntime` falls back to SmolLM2's `export_metadata.json` if `llama_3_2_1b_export_metadata.json` is missing.
   - `LlamaCyberAdvisor.explain()` casts `eos_token_id` with `int(...)`, which fails if Llama 3.2 provides a list (`[128001, 128008, 128009]`).
4. **Technical Quality Strengths:** Good XSS sanitization (`escapeHtml()`), bounded API inputs (`[:4096]` URL, `[:10000]` SMS), strict detector-locked `risk_level`, offline tokenizer loading (`local_files_only=True`), and clean error handling for unprivileged Scapy capture.

---

## 7. Top Five Competitive Improvements (Achievable on Windows Laptop)

1. **Eliminate SMS Duplicate Leakage & Add Real-World External Holdout Benchmarks:** Deduplicate `sms_dataset.csv` (`drop_duplicates(subset=["text"])`) and add a held-out real-world benchmark suite (e.g., real UCI SMS Spam / PhishTank-style / CICIDS-style noisy samples) so metrics reflect realistic generalization (`~95–98%` F1 with honest error analysis) instead of synthetic `1.0000`.
2. **Adversarial & Evasion Stress-Test Suite (`tests/adversarial/`):** Benchmark resilience against Punycode/IDN homoglyphs, URL shortener chains, leetspeak/zero-width obfuscated KYC SMS scams, and low-and-slow network port scans—and turn those into a measurable "Robustness Score" chart for the technical report.
3. **Sub-100ms Fast-Path vs. Deep-Path Triage Mode:** Expose a fast-path mode using `LogisticRegression`/`HistGB` (`0.2–2.0 ms`, `1.7–120 KB`) + deterministic structured advisory for instant bulk scanning, reserving the `~5.0 s` local LLM pass for user-requested deep explanations.
4. **Fix the 3 Exporter/Runtime/Advisor Compatibility Bugs:** Propagate `quantization` into `export_metadata.json`, handle list `eos_token_id` in `advisor.py`, isolate metadata fallback per `.pte`, and align `export_meta_llama_executorch.sh` with `LlamaExecuTorchExporter` so Linux/ARM64 switchover is 100% seamless.
5. **SOC-Grade Incident Export & Model Comparison View in Dashboard:** Add one-click JSON/Markdown incident report download and a side-by-side comparison card (Specialized Detectors vs. SmolLM2-135M vs. Meta Llama 3.2 1B Target) in the Flask UI.

---

## 8. Prioritized Implementation Roadmap

| Priority | Task | Effort | Impact |
| :---: | :--- | :---: | :--- |
| **P0** | Deduplicate `sms_dataset.csv`, re-train SMS detector, and document honest non-leaked metrics | Low | Eliminates critical scientific credibility flaw |
| **P0** | Fix `eos_token_id` list cast, `quantization` metadata, and `export_llama` alignment | Low | Ensures clean Meta Llama 3.2 1B execution on Linux/ARM64 |
| **P1** | Build Adversarial Evasion Stress-Test Suite & Confusion/Error Analysis figures | Medium | Differentiates from ordinary classifiers with real security rigor |
| **P1** | Add Fast-Path (`<5 ms`) vs. Deep LLM Advisory (`~5 s`) toggle + Incident Report export | Medium | Makes live demo snappy and practical for edge SOC workflows |
| **P2** | Execute `export_meta_llama_executorch.sh` on a Linux/RPi5 host when `HF_TOKEN` is available | External | Closes final Meta Llama + native ExecuTorch + ARM64 requirement |

---

## 9. Initial Submission Checklist

- [x] Working offline prototype (`app/main.py` Flask dashboard + `--cli-demo`)
- [x] Specialized URL, SMS, and Scapy Network detectors + Unified Threat Engine
- [x] 16/16 automated unit & integration tests passing (`unittest`)
- [x] Local LLM comparison baseline (`SmolLM2-135M-Instruct` via `torch.export`)
- [ ] Deduplicated SMS dataset + adversarial robustness benchmark (recommended before final freeze)
- [ ] Authentic `meta-llama/Llama-3.2-1B-Instruct` `.pte` execution on Linux/ARM64 (`HF_TOKEN` required)
- [ ] GitHub remote push, 4–6 min demo video (`demo/demo_script.md`), and official form submission (by **23 November 2026**)

---

## 10. Honest Readiness Assessment

- **Current Readiness:** **~75% Competition-Ready (Strong Prototype, Not Yet Full PS3 Compliance).**
- **Why:** The software architecture, offline UI, 3-modality detection + Scapy PCAP replay, and `torch.export` static-graph pipeline are solid and tested (`16/16` pass). However, winning PS3 requires (1) fixing the `34.3%` SMS duplicate leakage so evaluation metrics are unimpeachable, and (2) executing the prepared `meta-llama/Llama-3.2-1B-Instruct` `8da4w` export on a Linux/ARM64 environment with `HF_TOKEN` so mandatory Meta Llama + ExecuTorch compliance is genuinely demonstrated rather than only prepared.
