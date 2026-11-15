# SecureEdge AI — Dataset Integrity & Leakage Audit Report

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Script:** [`scripts/evaluation/run_reliable_evaluation.py`](../scripts/evaluation/run_reliable_evaluation.py)  
**Random Seed:** `42`  
**Audit Date:** 15 November 2026  

---

## 1. Executive Summary

A forensic audit of SecureEdge AI's raw datasets (`data/raw/`) was conducted without modifying the original files. While `url_dataset.csv` and `network_flows_dataset.csv` had minimal/zero exact row duplicates, **`sms_dataset.csv` contained 390 exact duplicate rows (32.5%)**, causing **103 exact training messages (`34.3%` of the 300-row test split)** to leak into the earlier stratified evaluation. Deduplicated datasets and removed-row audit logs have been saved separately under `results/reliable_evaluation/datasets/`.

---

## 2. Dataset Provenance, Hashes & Deduplication Summary

| Dataset | SHA-256 (Raw) | Raw Rows | Removed Duplicates | Clean Unique Rows | Label Conflicts | Origin Disclosure |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **`sms_dataset.csv`** | `59f9bc5a5bd85d05f5fac5c5c03c8e566e6b3edeacfbf11e39433330e2f60fdc` | 1,200 | **390** (`306` ham, `84` spam) | **810** (`514` scam, `294` ham, `2` spam) | 0 | Synthetic/templated Indian financial scams + UCI-style ham/spam |
| **`url_dataset.csv`** | `results/reliable_evaluation/reliable_evaluation_report.json` | 1,600 | **4** (`4` benign) | **1,596** (`1,200` unique domains) | 0 | Synthetic parameterized URL templates (PhishTank/Tranco-inspired) |
| **`network_flows_dataset.csv`** | `results/reliable_evaluation/reliable_evaluation_report.json` | 1,500 | **0** | **1,500** (`12` scenarios × `125`) | 0 | Synthetic statistical flow distributions (CICIDS/UNSW-inspired) |

---

## 3. SMS Dataset Integrity Findings (`sms_dataset.csv`)

1. **Exact & Normalized Duplicates:** Both exact string matching and normalized text matching (lowercasing, whitespace collapsing, punctuation stripping) identified **390 duplicate rows** (`306` ham, `84` spam), leaving **810 unique normalized messages**. Note that `84` of `86` raw `spam` rows were duplicates of just **2 unique spam messages**.
2. **Zero Label Conflicts:** `0` normalized messages appeared with conflicting labels (`benign` vs `malicious`) or conflicting categories.
3. **Near-Duplicate Template Grouping:** Masking normalized URLs, currencies, phone numbers (`SMSFeatureExtractor.clean_text`), and digits (`<NUM>`) revealed that the `810` unique messages originate from **40 underlying template groups** (with up to `43` parameterized variants per scam template).
4. **Leakage-Resistant Splits Implemented:**
   - **Split A (`Exact-Dedup Stratified 70/15/15`):** `567` train / `121` val / `122` test (`normalized_text_overlap = 0`).
   - **Split B (`Template-Grouped GroupShuffleSplit 70/15/15`):** `547` train (`28` groups) / `168` val (`6` groups) / `95` test (`6` groups) with **`normalized_text_overlap = 0`** and **`template_group_overlap = 0`**.

---

## 4. URL & Network Dataset Integrity Findings

- **URL (`url_dataset.csv`):** Deduplicated to `1,596` unique normalized URLs across `1,200` registered domains. Split via 3-way `GroupShuffleSplit` on `registered_domain` (`1,135` train / `229` val / `232` test) with **`domain_overlap = 0`**.
- **Network (`network_flows_dataset.csv`):** `0` exact duplicates, balanced `750` benign / `750` anomaly across `12` `attack_type` scenarios (`125` each) and `91` unique `src_ip` values.
  - **Collinear Feature Pairs (`|r| >= 0.85`):** `packet_count` ↔ `byte_count` (`0.9642`), `byte_count` ↔ `bytes_per_sec` (`0.9306`), `packet_count` ↔ `bytes_per_sec` (`0.9097`), `syn_flag_ratio` ↔ `payload_byte_ratio` (`0.8629`).
  - **Top Label Correlations:** `syn_flag_ratio` (`0.5250`), `connection_frequency` (`0.5089`), `protocol_id` (`0.4472`), `is_sensitive_admin_port` (`0.4285`).
  - **Splits Implemented:** `SrcIP-Grouped 70/15/15` (`1,177 / 165 / 158`) and `Unseen-Scenario Grouped` (`1,000 / 250 / 250`, holding out `data_exfiltration_anomaly` and `stealth_low_slow_probe` entirely into the test set).

---

## 5. Preserved Audit Artifacts

- Cleaned SMS dataset: `results/reliable_evaluation/datasets/sms_deduplicated.csv` (`810` rows)
- Removed SMS duplicates log: `results/reliable_evaluation/datasets/sms_removed_duplicates.csv` (`390` rows)
- Cleaned URL dataset: `results/reliable_evaluation/datasets/url_deduplicated.csv` (`1,596` rows)
- Removed URL duplicates log: `results/reliable_evaluation/datasets/url_removed_duplicates.csv` (`4` rows)
- Original `data/raw/*.csv` files remain **100% untouched**.
