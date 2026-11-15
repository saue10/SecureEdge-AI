# SecureEdge AI — Workspace & System Audit Report

**Project:** SecureEdge AI: An Intelligent On-Device Cybersecurity Assistant for Phishing, Scam and Network Threat Detection Using ARM-Based Edge Computing  
**Competition:** Bharat AI-SoC Challenge 2026–27 | Problem Statement 3 (PS3)  
**Audit Date:** 15 November 2026  
**Confirmed Phase 1 Submission Deadline:** 23 November 2026  

---

## 1. Executive Summary

An exhaustive audit of the active workspace (`f:\AI_SOC_Challenge`) and host system environment was conducted on 15 November 2026 prior to beginning development. The workspace directory was completely empty (uninitialized, no existing Git repository, no legacy source code, no datasets, and no pre-trained models). The host environment is a Windows 11 x86_64 machine equipped with an 11th Gen Intel Core i5-1135G7 CPU (4 cores / 8 threads), 7.75 GB RAM, and 49.88 GB free disk space on Drive `F:`. A rich scientific Python 3.13.2 environment is already installed with `torch 2.8.0+cpu`, `transformers 5.17.0`, `scikit-learn 1.8.0`, `scapy 2.6.1`, `pandas 3.0.1`, `numpy 2.3.4`, `flask 3.0.3`, `matplotlib 3.10.8`, and `seaborn 0.13.2`.

---

## 2. Host Hardware & Operating System Profile

| Component | Observed Specification | Impact on Project Execution |
| :--- | :--- | :--- |
| **Working Directory** | `f:\AI_SOC_Challenge` | Clean slate; full project hierarchy to be initialized in place. |
| **Operating System** | Windows 11 (10.0.26200-SP0, AMD64 / x86_64) | Host development and testing on x86_64 Windows; cross-platform ARM64 deployment artifacts & scripts required. |
| **CPU** | 11th Gen Intel Core i5-1135G7 @ 2.40 GHz (4 Physical Cores, 8 Logical Processors) | Capable of fast tabular/text ML training and 135M–1B parameter LLM export/inference on CPU. |
| **System RAM** | 7.75 GB Total (~0.74–1.5 GB Free under normal load) | **Critical Constraint:** High memory pressure. Model training, dataset loading, and ExecuTorch export must use memory-efficient batching, float16/int8 quantization, and garbage collection. |
| **GPU** | Integrated Intel Iris Xe Graphics (`torch.cuda.is_available() == False`) | All training, quantization, and inference must execute on CPU. |
| **Disk Space (`F:`)** | 100.0 GB Total / 50.12 GB Used / **49.88 GB Free** | Sufficient storage for datasets, specialized detectors, and `.pte` / quantized Llama weights, provided massive raw datasets are not duplicated unnecessarily. |
| **ARM Hardware / Emulators** | No physical Raspberry Pi 5, Android device (`adb` not found), or `qemu-system-aarch64` attached; WSL access returns `Wsl/E_ACCESSDENIED` in standard shell. | Host testing will be rigorously labelled as **x86_64 Host Verification**. Complete ARM64 Linux / Raspberry Pi 5 / Android Termux deployment scripts, Dockerfiles, and verification harnesses will be engineered and clearly documented as **ARM Target Deployment Ready (Pending Physical Board Verification)** unless a physical board is connected. |

---

## 3. Software & Python Environment Audit

### 3.1 Core Installed Packages (`Python 3.13.2`)
- **Deep Learning & LLM Ecosystem:** `torch 2.8.0+cpu`, `transformers 5.17.0`, `tokenizers 0.23.2`, `huggingface_hub 1.32.0`, `safetensors 0.8.0`, `sentence-transformers 6.1.0`
- **Machine Learning & Data Science:** `scikit-learn 1.8.0`, `scipy 1.17.0`, `pandas 3.0.1`, `numpy 2.3.4`, `joblib 1.5.3`, `rank-bm25 0.2.2`, `statsmodels 0.14.6`
- **Networking & Security Analysis:** `scapy 2.6.1`, `pefile 2024.8.26`, `urllib3 2.6.3`, `requests 2.32.5`, `httpx 0.28.1`, `beautifulsoup4 4.14.3`
- **Web / UI & Visualization:** `Flask 3.0.3`, `Flask-SocketIO 5.3.6`, `Jinja2 3.1.6`, `matplotlib 3.10.8`, `seaborn 0.13.2`, `pillow 12.0.0`, `rich 15.0.0`, `typer 0.27.2`
- **System & Diagnostics:** `psutil 7.2.2`, `py-cpuinfo 9.0.0`, `pydantic 2.12.5`

### 3.2 Missing / Additional Packages to Check or Install
- **ExecuTorch (`executorch`)**: Not currently installed in the global Python 3.13 site-packages. Note that upstream PyTorch ExecuTorch prebuilt wheels often target Linux/macOS or specific Python versions (3.10–3.12). We will test installing `executorch` via `pip` with network access, and also inspect `torch.export` (`ExportedProgram` / `.pt2` / AOTInductor / XNNPACK lowering and ExecuTorch `.pte` serialization) so that both genuine `torch.export` / ExecuTorch `.pte` generation and runtime execution work reliably on this machine and on ARM64 Linux targets.
- **Streamlit (`streamlit`) & Pytest (`pytest`)**: Not currently installed (`Flask` and `unittest` are pre-installed). We can install `streamlit` and `pytest` via `pip`, AND ensure our application supports both Streamlit (`app/main.py`) and a built-in Flask/standalone dark cybersecurity dashboard or CLI fallback so the UI is 100% guaranteed to launch offline even in restricted environments.

---

## 4. Existing Workspace & Repository Status

- **Workspace Contents:** Empty directory (`f:\AI_SOC_Challenge`).
- **Git Repository:** Not initialized (`fatal: not a git repository`).
- **GitHub Remote:** None configured yet.
- **Mentoring Video / Prior Docs:** None present in workspace; all requirements derived directly from the official Bharat AI-SoC Challenge PS3 specification.
- **Datasets & Models:** None present locally yet; must be acquired/curated, documented, and split reproducibly without data leakage.

---

## 5. Official PS3 Requirements vs. Technical Strategy

| PS3 Requirement | Technical Implementation Strategy |
| :--- | :--- |
| **1. Phishing URL Detection** | Lexical, host, TLD, entropy, suspicious token, and structural feature extractor (28+ domain-agnostic features) + benchmarked comparison across Logistic Regression, Random Forest, HistGradientBoosting, and MLP on domain-separated dataset splits. |
| **2. Scam SMS & Fraud Detection** | Multi-tier text pipeline combining character/word TF-IDF + structural financial/urgency/UPI/KYC scam indicators (distinguishing general spam from financial fraud) evaluated on the UCI SMS Spam Collection + curated Indian/global financial scam corpus. |
| **3. Network Anomaly Detection** | Passive `scapy` packet capture + PCAP/flow replay engine extracting 20+ flow statistics (packet rate, byte asymmetry, SYN/RST ratios, port entropy, flow duration) paired with Random Forest / Isolation Forest anomaly detection trained on NSL-KDD / UNSW-NB15 / CICIDS flow features. |
| **4. Unified Threat Engine** | Standardized Pydantic/dataclass schema (`ThreatAssessment`) aggregating multi-modal evidence, calibrated risk scores (0–100), severity classification (`benign`, `suspicious`, `malicious`), and audit logging. |
| **5. Llama Family + ExecuTorch** | Genuine Llama-architecture model (`Llama-3.2-1B-Instruct` or open-gated Llama-family architecture such as `SmolLM2-135M-Instruct` / `TinyLlama-1.1B` / `Llama-3.2-1B-Instruct` depending on HuggingFace token availability) exported via PyTorch `torch.export` / ExecuTorch pipeline into `.pte` artifact, with strict JSON schema validation ensuring Llama explains detector evidence without hallucinating or overriding detector verdicts. |
| **6. ARM Edge Deployment** | Complete ARM64 deployment suite (`deployment/arm64`, `deployment/raspberry_pi`, `deployment/android`) with XNNPACK delegate configuration, NEON/quantization setup, cross-compilation/export scripts, and honest distinction between measured x86_64 host benchmarks and target ARM64 specifications. |
| **7. Local Security Dashboard** | Dark-themed "SECUREEDGE AI" web dashboard (supporting both Streamlit and native Flask/HTML5 dark UI) featuring all 8 required views: Dashboard, URL Scanner, SMS Detector, Network Monitor (Live Scapy + Replay Mode), AI Threat Explanation, Detection History, System Info, and Edge Benchmarks. |

---

## 6. Risk Assessment & Mitigations

1. **Risk: Low Available Host RAM (~0.74–1.5 GB free on 7.75 GB machine)**
   - *Mitigation:* Avoid loading multi-gigabyte dataframes or unquantized 4GB+ models in memory simultaneously. Use streaming/chunked data processing, compact feature matrices, `torch.no_grad()`, `gc.collect()`, and quantized/compact Llama checkpoints.
2. **Risk: ExecuTorch Wheel Availability on Windows Python 3.13**
   - *Mitigation:* Test `pip install executorch` directly. Because PyTorch ExecuTorch officially prioritizes Linux/macOS (aarch64/x86_64) and Python 3.10–3.12 wheels, if a native Windows Python 3.13 wheel for `executorch` is not published on PyPI, we will:
     1. Implement the complete, standards-compliant ExecuTorch export & runtime module (`src/executorch/`) using PyTorch 2.8's native `torch.export.export()` + XNNPACK/Edge dialect serialization and `.pte` container generation.
     2. Provide a full Linux/ARM64 Docker & Raspberry Pi 5 build/verification harness where native `executorch` C++/Python runtime executes the `.pte` artifact directly.
     3. Document exact runtime compatibility transparently without ever faking compliance.
3. **Risk: Gated Access to `meta-llama/Llama-3.2-1B-Instruct` on HuggingFace**
   - *Mitigation:* Check if HuggingFace authentication token is cached on the host. If `meta-llama/Llama-3.2-1B-Instruct` requires an unconfigured HF login token, support seamless configuration of `HF_TOKEN` while automatically provisioning an open-access Llama-architecture model (`LlamaForCausalLM` architecture, e.g., `HuggingFaceTB/SmolLM2-135M-Instruct` or `TinyLlama/TinyLlama-1.1B-Chat-v1.0` or custom Llama-3.2 config checkpoint) so local Llama inference, `torch.export`, `.pte` generation, and end-to-end testing work immediately out-of-the-box, and ask the user only if they wish to supply their HuggingFace token for gated Meta weights.
