# SecureEdge AI — Reliable Model Evaluation & Calibration Report

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Command:** `python scripts/evaluation/run_reliable_evaluation.py` (`RANDOM_SEED = 42`)  
**Environment:** Windows 11, `Python 3.13.2`, `scikit-learn 1.8.0`, `pandas 3.0.1`, `numpy 2.3.4`  
**Raw Metrics Artifact:** [`results/reliable_evaluation/reliable_evaluation_report.json`](../results/reliable_evaluation/reliable_evaluation_report.json)  

---

## 1. Methodology & Anti-Leakage Guarantees

1. **Strict Fit Isolation:** All `TfidfVectorizer`, `StandardScaler`, and `CalibratedClassifierCV` objects are fitted **only on training data**.
2. **Validation-Only Threshold Selection:** Decision thresholds are selected strictly on the validation split (prioritizing `recall >= 0.90` for SMS/Network and `>= 0.95` for URL, then maximizing Macro F1). The test set is touched **once**.
3. **Low-Confidence Uncertain Band:** Samples with calibrated probability `p in [0.40, 0.60)` are counted as low-confidence/uncertain cases for conservative triage.
4. **Synthetic Origin Disclosure:** All three datasets originate from deterministic synthetic/templated generation (`scripts/download_datasets.py`). Therefore, even leak-free splits measure *in-distribution synthetic generalization*, not live wild internet/cellular telemetry.

---

## 2. SMS Detection Evaluation (Deduplicated & Leakage-Free)

### 2.1 Split A — Exact-Deduplicated Stratified 70/15/15 (`567 / 121 / 122`, `0` norm overlap)

| Model | Val Thr | Acc | Macro F1 | Ham F1 | Scam/Spam F1 | FPR | FNR | Brier | OTP FP | Pers. Ham FP | Latency | Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`LogReg_Combined_TFIDF`** | `0.25` | `0.9836` | **`0.9820`** | `0.9767` | `0.9873` | `0.0455` | `0.0000` | `0.0033` | `0/6` | `2/38` | **`0.090 ms`** | **`7.90 KB`** |
| **`Calibrated_LinearSVC`** | `0.25` | `0.9836` | **`0.9820`** | `0.9767` | `0.9873` | `0.0455` | `0.0000` | `0.0025` | `0/6` | `2/38` | `1.449 ms` | `19.93 KB` |
| **`RandomForest_Combined`** | `0.25` | `0.9836` | **`0.9820`** | `0.9767` | `0.9873` | `0.0455` | `0.0000` | **`0.0020`** | `0/6` | `2/38` | `61.706 ms` | `32.58 KB` |
| **`LogReg_Char_TFIDF`** | `0.25` | `0.9672` | `0.9637` | `0.9524` | `0.9750` | `0.0909` | `0.0000` | `0.0070` | `0/6` | `4/38` | `0.081 ms` | `5.90 KB` |
| **`LogReg_Word_TFIDF`** | `0.25` | `0.9672` | `0.9637` | `0.9524` | `0.9750` | `0.0909` | `0.0000` | `0.0090` | `0/6` | `4/38` | `0.115 ms` | `2.50 KB` |

### 2.2 Split B — Near-Duplicate Template-Grouped (`547 / 168 / 95`, `0` template group overlap)

| Model | Val Thr | Acc | Macro F1 | Ham F1 | Scam/Spam F1 | FPR | FNR | Brier | OTP FP | Pers. Ham FP | Latency | Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`LogReg_Combined_TFIDF`** | `0.25` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | **`0.0089`** | `0/13` | `0/24` | **`0.121 ms`** | **`7.59 KB`** |
| **`Calibrated_LinearSVC`** | `0.25` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0232` | `0/13` | `0/24` | `1.140 ms` | `18.06 KB` |
| **`LogReg_Word_TFIDF`** | `0.51` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0481` | `0/13` | `0/24` | `0.085 ms` | `2.02 KB` |
| **`RandomForest_Combined`** | `0.52` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0807` | `0/13` | `0/24` | `42.798 ms` | `28.59 KB` |
| **`LogReg_Char_TFIDF`** | `0.34` | `0.8842` | `0.8694` | `0.8254` | `0.9134` | `0.2973` | `0.0000` | `0.0426` | `0/13` | `11/24` | `0.101 ms` | `6.08 KB` |

**Key Finding:** Removing the `390` duplicate SMS rows drops Stratified Macro F1 from the inflated `1.0000` down to **`0.9820`** (`2` personal ham false positives), and `LogReg_Char_TFIDF` drops to `0.8694` on unseen template groups (`11/24` false positives). **`LogReg_Combined_TFIDF`** matches `Calibrated_LinearSVC` in accuracy (`0.9836`) with better probability calibration (`Brier 0.0089` vs `0.0232` on Split B), `16x` lower latency (`0.090 ms`), and `2.5x` smaller footprint (`7.90 KB`).

---

## 3. URL Detection Evaluation (`1,596` Unique URLs, `0` Domain Overlap)

3-way `GroupShuffleSplit` by `registered_domain` (`1,135` train / `229` val / `232` test):

| Model | Val Thr | Acc | Macro F1 | FPR | FNR | Brier | Latency | Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`RandomForest_Calibrated`** | `0.25` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0002` | `88.440 ms` | `246.75 KB` |
| **`HistGradientBoosting`** | `0.25` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | **`0.0000`** | `1.250 ms` | `88.21 KB` |
| **`LogisticRegression`** | `0.57` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0046` | **`0.064 ms`** | **`0.80 KB`** |

- **Subgroup Accuracy (all 3 models on test set):** `punycode` (`16/16`), `raw_ip` (`21/21`), `suspicious_subdomain` (`26/26`), `brand_impersonation` (`60/60`), `hard_negative_benign` (`13/13`), `stealth_phishing` (`17/17`).
- **Recommendation:** `HistGradientBoosting` (`1.250 ms`, `88.21 KB`) is `70.8x` faster than `RandomForest_Calibrated` (`88.440 ms`) with identical `1.0000` accuracy and lower Brier score (`0.0000`).

---

## 4. Network Flow Evaluation (SrcIP-Grouped vs. Unseen-Scenario Holdout)

| Split | Model | Val Thr | Acc | Macro F1 | Benign F1 | Anomaly F1 | FPR | FNR | Brier | Latency | Size |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SrcIP-Grouped (`1177/165/158`)** | `RandomForest_Calibrated` | `0.25` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | `0.0001` | `109.639 ms` | `188.21 KB` |
| **SrcIP-Grouped (`1177/165/158`)** | **`HistGradientBoosting`** | `0.25` | `1.0000` | `1.0000` | `1.0000` | `1.0000` | `0.0000` | `0.0000` | **`0.0000`** | **`1.466 ms`** | `84.38 KB` |
| **SrcIP-Grouped (`1177/165/158`)** | `LogisticRegression` | `0.40` | `0.9810` | `0.9796` | `0.9744` | `0.9849` | `0.0500` | `0.0000` | `0.0103` | `0.065 ms` | `0.69 KB` |
| **Unseen-Scenario (`1000/250/250`)** | `RandomForest_Calibrated` | `0.25` | `0.5000` | `0.3333` | `0.0000` | `0.6667` | `0.0000` | `0.5000` | `0.4950` | `81.629 ms` | `125.84 KB` |
| **Unseen-Scenario (`1000/250/250`)** | `HistGradientBoosting` | `0.25` | `0.3600` | `0.2647` | `0.0000` | `0.5294` | `0.0000` | `0.6400` | `0.6400` | `1.407 ms` | `28.99 KB` |
| **Unseen-Scenario (`1000/250/250`)** | `LogisticRegression` | `0.25` | `0.0360` | `0.0347` | `0.0000` | `0.0695` | `0.0000` | `0.9640` | `0.9590` | `0.067 ms` | `0.69 KB` |

**Critical Unseen-Scenario Finding:** When `data_exfiltration_anomaly` and `stealth_low_slow_probe` are held out completely from training, **every supervised classifier degrades sharply** (`FNR = 0.50–0.96`), missing stealthy low-and-slow probes. This empirically justifies retaining the **unsupervised `IsolationForest` (fitted on benign flows)** in `NetworkAnomalyDetector` alongside supervised classification.

---

## 5. Model Replacement Recommendations (Task 9)

Per Task 9, existing baseline models in `models/` are **preserved unchanged** in this phase, and we recommend the following selective upgrades for Phase 2 integration:
1. **SMS Detector:** Replace `Calibrated_LinearSVC` (trained on 1,200 leaked rows) with **`LogReg_Combined_TFIDF`** trained on the **deduplicated 810-row dataset** (`0.090 ms`, `7.90 KB`, `Macro F1 = 0.9820`, `0/6` OTP FPs).
2. **URL Detector:** Replace `RandomForest_Calibrated` (`88.44 ms`, `246.75 KB`) with **`HistGradientBoosting`** (`1.25 ms`, `88.21 KB`, `70.8x` faster, `Brier = 0.0000`).
3. **Network Detector:** Replace supervised `RandomForest_Calibrated` (`109.64 ms`, `188.21 KB`) with **`HistGradientBoosting`** (`1.47 ms`, `84.38 KB`, `74.8x` faster) **paired with the existing unsupervised `IsolationForest`** for unseen-scenario coverage.
4. **LLM Independence:** Keep all detector risk scores, thresholds, and `risk_level` decisions strictly independent of the LLM explanation layer.
