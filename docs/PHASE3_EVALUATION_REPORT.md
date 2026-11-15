# Phase 3 Evaluation & Edge Efficiency Report

## 1. Environment & Methodology
- **Hardware / OS:** Windows 11, Intel Core i5-1135G7, ~8 GB RAM, CPU-only PyTorch `2.8.0+cpu`, Python `3.13.2`, `scikit-learn 1.8.0`, `psutil 7.2.2`.
- **Leakage Control:** Exact-text deduplicated split (`70/15/15`) for SMS; `registered_domain` group split (`70/15/15`) for URL; known-vs-unseen scenario split for Network. Validation splits (`15%`) were used exclusively for probability calibration (`CalibratedClassifierCV`). Adversarial benchmarks (`220+` attack / `220+` benign hard negatives per modality) are synthetic and strictly disjoint from training.

## 2. Summary of Key Improvements
1. **SMS Adversarial Recall:** Baseline `ScamSMSDetector` `0.4409` (and `0.0000` on Phase 2's 12-item suite) -> **`HardenedSMSDetector` `1.0000`** (`220/220` detected, `0.0000` FPR across `benign_otp`, `benign_banking_alert`, `benign_personal`, `benign_commercial`).
2. **URL Adversarial Recall:** Baseline `PhishingURLDetector` `0.6087` (`0.5714` in Phase 2) -> **`HardenedURLDetector` `0.9391`** (`216/230` detected, `0.0000` FPR on `benign_idn`, `benign_official_brand`, and `benign_research_blog`).
3. **Network Unseen FPR Reduction:** Phase 2 `AdaptiveNetworkDetector` Alert FPR `0.8560` -> **`ContextAwareNetworkDetector` `0.0080`** (`90.40%` recall, `0.9479` Macro F1; `0/125` `confirmed_malicious` on `benign_microservice_burst`, `125/125` `normal` on `benign_ssh_session`).

## 3. Edge Efficiency & Operating Modes Benchmark
Measured via `scripts/evaluation/run_phase3_hardening.py` (`results/phase3_hardening/phase3_results.json`):

| Component / Mode | P50 Latency | P95 Latency | Model Size | RSS Memory | Notes |
|---|---:|---:|---:|---:|---|
| `HardenedSMSDetector` (Adv) | `1.808 ms` | `2.744 ms` | `0.169 MB` | — | CPU-only TF-IDF + 20 features |
| `HardenedURLDetector` (Adv) | `3.115 ms` | `4.054 ms` | `0.342 MB` | — | 7x faster than baseline RF |
| `ContextAwareNetworkDetector` (Unseen) | `14.362 ms` | `16.592 ms` | `2.216 MB` | — | Includes MAD + IsolationForest |
| **`FAST TRIAGE` (`CalibratedThreatEngine`, 45 runs)** | **`3.674 ms`** | **`17.319 ms`** | — | **`72.49 MB`** | Zero LLM calls (`cpu_percent=398.8%` burst) |
| **`DEEP ANALYSIS` (`SmolLM2-135M`, 2 runs)** | **`11,832.114 ms`** | **`19,793.904 ms`** | — | **`595.43 MB`** | `torch.export.ExportedProgram` |

## 4. Regression Testing
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
Covers all 20 prior tests plus 11 Phase 3 regression tests (`tests/unit/test_phase3_hardening.py`).
