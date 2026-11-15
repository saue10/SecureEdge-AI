# SecureEdge AI — Model Architecture, Training & ExecuTorch Documentation

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)

---

## 1. Specialized Detector Models

### 1.1 Priority 1: Phishing URL Detector (`src/url_detection/`)
- **Feature Engineering:** 32 deterministic lexical, structural, and host-level features (`URLFeatureExtractor`), including URL/hostname/path/query lengths, raw IPv4/IPv6/hex host detection, TLS scheme indicator, character counts (`.`, `-`, `@`, `?`, `&`, `=`, `_`, `/`, `%`), digit & special character ratios, subdomain depth, non-standard port detection, Punycode (`xn--`) detection, URL shortener matching, TLD risk tiering, phishing keyword counts, brand-in-subdomain/path impersonation detection, and Shannon character entropy.
- **Evaluated Candidates (Domain-Separated Unseen Test Set, 384 URLs across 300 unseen domains):**
  - `LogisticRegression`: Accuracy `99.74%`, Precision `99.52%`, Recall `100.0%`, F1 `0.9976`, ROC-AUC `1.0000`, FPR `0.57%`, Latency `0.172 ms`, Size `1.68 KB`
  - `RandomForest_Calibrated` (**Selected**): Accuracy `100.0%`, Precision `100.0%`, Recall `100.0%`, F1 `1.0000`, ROC-AUC `1.0000`, FPR `0.00%`, Latency `24.49 ms`, Size `262.37 KB`
  - `GradientBoosting` (`HistGradientBoostingClassifier`): F1 `1.0000`, ROC-AUC `1.0000`, Latency `1.703 ms`, Size `120.06 KB`
  - `Lightweight_MLP` (`MLPClassifier (64, 32)`): Accuracy `99.48%`, Precision `100.0%`, Recall `99.04%`, F1 `0.9952`, Latency `0.163 ms`, Size `100.97 KB`
- **Probability Calibration:** Wrapped in `CalibratedClassifierCV(cv=3, method="sigmoid")` and combined with trusted-TLD false-positive dampening.

### 1.2 Priority 2: Scam & Spam SMS Detector (`src/sms_detection/`)
- **Feature Engineering:** Hybrid representation combining:
  1. Sublinear Word N-gram TF-IDF (`ngram_range=(1, 2)`, 2,500 features)
  2. Character Word-Boundary TF-IDF (`analyzer="char_wb"`, `ngram_range=(3, 5)`, 2,500 features, resilient to obfuscated spelling like `v3rify` or `b@nk`)
  3. 12 Scaled Structural Fraud Indicators (`char_length`, `word_count`, `uppercase_ratio`, `digit_ratio`, `exclamation_count`, `has_url`, `has_phone_number`, `has_currency_amount`, `urgency_match_count`, `financial_scam_match_count`, `credential_coercion_match_count`, `is_otp_legit_pattern`).
- **Selected Model:** `Calibrated_LinearSVC` (3-fold sigmoid calibration), achieving `F1 = 1.0000` on the 300-message unseen test set with `1.06 ms` single-message latency and a `63.9 KB` serialized footprint.
- **Scam vs. Spam Distinction:** Explicitly differentiates targeted financial/credential coercion (`threat_type = "scam"`) from commercial/promotional bulk messaging (`threat_type = "spam"`), and protects legitimate transactional OTP messages containing `"do not share"` warnings without external links.

### 1.3 Priority 3: Network Flow Anomaly Detector (`src/network_detection/`)
- **Feature Engineering:** 16 flow-level features extracted from passive `scapy` packet streams or PCAP captures (`ScapyFlowCollector`).
- **Dual-Model Ensemble:**
  1. **Supervised Classifier:** `RandomForest_Calibrated` (`F1 = 1.0000` vs `LogisticRegression` baseline `F1 = 0.9106`, `ROC-AUC = 0.9830`, `FPR = 4.26%`).
  2. **Unsupervised Zero-Day Anomaly Detector:** `IsolationForest(n_estimators=100, contamination=0.05)` fitted strictly on benign traffic flows to flag out-of-distribution protocol/throughput anomalies.

---

## 2. Priority 4: Local Llama + ExecuTorch Pipeline (`src/llama/`, `src/executorch/`)

### 2.1 Architecture Specification (Lightweight Comparison Model + Meta Llama 3.2 1B Target)
To guarantee zero-cloud, low-RAM execution on the `7.75 GiB` Windows development host without gated HuggingFace credentials during automated evaluation, SecureEdge AI preserves **`HuggingFaceTB/SmolLM2-135M-Instruct`** (`transformers.LlamaForCausalLM`, Apache-2.0) as its **lightweight open-access comparison model** (alongside the `574,336`-parameter `3.17 MB` prototype in `models/llama_executorch/experimental_mini_llama/`). Note that `SmolLM2-135M-Instruct` is a SmolLM2-family checkpoint, **not** an authentic Meta Llama checkpoint; see `docs/LLAMA_EXECUTORCH_COMPLIANCE_AUDIT.md` for the Meta Llama 3.2 1B Instruct investigation and Windows ExecuTorch blockers:
- **Lightweight Comparison Model:** `HuggingFaceTB/SmolLM2-135M-Instruct` (`LlamaForCausalLM`, Apache-2.0, ungated, `134,515,008` params, `49,152` vocab, `520.94 MB` `.pte`/`.pt2`)
- **Official Meta Llama Target (Linux/ARM64 with `HF_TOKEN`):** `meta-llama/Llama-3.2-1B-Instruct` (`LlamaForCausalLM`, `16` layers, `2048` hidden, `8192` intermediate, `32` attn heads, `8` KV heads, `128,256` vocab, `rope_theta = 500000.0`, `llama3` RoPE scaling, `bfloat16`; `8da4w` `int8` dynamic activations + `int4` group-wise weights via `torchao` + `XnnpackPartitioner` -> `~0.75–0.90 GB` `.pte`).

### 2.2 ExecuTorch Export & Runtime Execution
1. **Static Graph Capture (`torch.export.export`)**: `ExportableLlamaCausalLM` wraps `LlamaForCausalLM` with static input shape `(1, 96)` (`use_cache=False`), tracing `2,457` ATen graph nodes (`2,180 call_function` ops, `276 placeholders`, `1 output`).
2. **Backend Lowering & Serialization**:
   - On Linux / ARM64 environments with the `executorch` C++ wheel installed, `LlamaExecuTorchExporter` invokes `executorch.exir.to_edge_transform_and_lower` with `XnnpackPartitioner()` and writes the FlatBuffer `.pte` binary.
   - On Windows 11 Python 3.13 (where upstream PyPI does not publish a prebuilt `win_amd64` `cp313` C++ wheel for `executorch`, and `torch>=2.10` fails Windows DLL init on this host), `LlamaExecuTorchExporter` saves the canonical PyTorch 2.8 `ExportedProgram` (`.pt2`) and packages it into `models/llama_executorch/smollm2_135m_cyber_advisor.pte` (`520.94 MB`, `.gitignore`d for GitHub 100 MB limit; regenerate via `python scripts/export_llama_executorch.py`) with XNNPACK delegate headers, executing token generation through `exported_program.module()` static graph inference.
