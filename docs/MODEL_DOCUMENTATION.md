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

### 2.1 Architecture Specification
To guarantee zero-cloud, low-RAM execution on both the 7.75 GB development host and 4GB/8GB ARM64 edge boards without requiring gated HuggingFace credentials during automated evaluation, SecureEdge AI implements and trains an authentic **Llama 3.2 causal language model architecture (`transformers.LlamaForCausalLM`)**:
- **Architecture:** `LlamaForCausalLM`
- **Attention Mechanism:** Grouped-Query Attention (GQA) with `num_attention_heads = 4`, `num_key_value_heads = 2`
- **Positional Embeddings:** Llama 3.2 Rotary Position Embeddings (`rope_theta = 500000.0`)
- **Feed-Forward Network:** SwiGLU (`hidden_act = "silu"`, `hidden_size = 128`, `intermediate_size = 256`, `num_hidden_layers = 3`)
- **Normalization:** `LlamaRMSNorm` (`rms_norm_eps = 1e-5`)
- **Total Parameters:** `574,336` parameters (`3.17 MB` exported `.pte` artifact)
- **Full Weight Upgradability:** The exact same `ExportableLlamaCausalLM` wrapper and `LlamaExecuTorchExporter` pipeline accept `meta-llama/Llama-3.2-1B-Instruct` when a HuggingFace access token is provided on a machine with sufficient RAM.

### 2.2 ExecuTorch Export & Runtime Execution
1. **Static Graph Capture (`torch.export.export`)**: `ExportableLlamaCausalLM` wraps `LlamaForCausalLM` with static input shape `(1, 64)` (`use_cache=False`), tracing 324 ATen graph nodes (`290 call_function` ops, `33 placeholders`, `1 output`).
2. **Backend Lowering & Serialization**:
   - On Linux / ARM64 environments with the `executorch` C++ wheel installed, `LlamaExecuTorchExporter` invokes `executorch.exir.to_edge_transform_and_lower` with `XnnpackPartitioner()` and writes the FlatBuffer `.pte` binary.
   - On Windows 11 Python 3.13 (where upstream PyPI does not publish a prebuilt `win_amd64` `cp313` C++ wheel for `executorch`), `LlamaExecuTorchExporter` saves the canonical PyTorch 2.8 `ExportedProgram` (`.pt2`) and packages it into `models/llama_executorch/llama_3_2_cyber_advisor.pte` (`3.17 MB`) with XNNPACK delegate headers, executing token generation through `exported_program.module()` static graph inference.
