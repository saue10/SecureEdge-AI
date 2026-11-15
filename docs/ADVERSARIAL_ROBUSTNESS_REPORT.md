# SecureEdge AI — Adversarial Robustness Evaluation Report

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Command:** `python scripts/evaluation/run_phase2_adaptive_and_adversarial.py`  
**Results Artifact:** [`results/adaptive_threat_intelligence/phase2_results.json`](../results/adaptive_threat_intelligence/phase2_results.json)  

---

## 1. Evaluation Design

Separate adversarial holdout suites (never used during training) were evaluated against the existing baseline detectors (`PhishingURLDetector`, `ScamSMSDetector`) and the new `AdaptiveNetworkDetector`.

---

## 2. Clean vs. Adversarial Performance Summary

| Modality | Clean / Known Macro F1 | Adversarial Macro F1 | Adversarial Acc | Adversarial Recall | Adversarial FPR | Adversarial FNR | P50 / P95 Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **URL (`PhishingURLDetector`)** | `1.0000` (synthetic) | **`0.7483`** | `0.7500` | `0.5714` (`8/14`) | `0.0000` (`0/10`) | `0.4286` (`6/14`) | `28.17 / 33.94 ms` |
| **SMS (`ScamSMSDetector`)** | `0.9820` (dedup) | **`0.3125`** | `0.4545` | **`0.0000`** (`0/12`) | `0.0000` (`0/10`) | **`1.0000`** (`12/12`) | `2.45 / 3.49 ms` |
| **Network (`AdaptiveNetworkDetector`)** | `1.0000` (strict) | **`0.9307`** | `0.9375` | **`1.0000`** (`10/10`) | `0.1667` (`1/6`) | `0.0000` (`0/10`) | `13.65 / 18.67 ms` |

---

## 3. Honest Failure Analysis (Negative Results Reported Directly)

1. **SMS Baseline Evasion (`0/12` Adversarial Recall):** The existing `ScamSMSDetector` (trained on templated data) failed on **all 12** adversarial obfuscations (`risk_score = 6–34`), including spaced punctuation (`S.B.I K.Y.C`, `O T P`, `U-P-I P!N`), leetspeak (`V3r1fy`), and mixed Hinglish (`Aapka KYC pending hai...`). Why: word/char TF-IDF weights learned clean template tokens, and punctuation/spacing breaks n-gram alignment.
2. **URL Baseline Evasion (`6/14` Missed):** `PhishingURLDetector` missed:
   - Unicode Cyrillic confusable `http://раypal-security.com/signin` (`score=10`) — ASCII `has_punycode` does not flag raw UTF-8 Cyrillic homoglyphs.
   - Shorteners (`bit.ly/3xKycVerify`, `tinyurl.com/sbi-reward-claim`, `score=7, 13`).
   - Mixed-case `HtTp://PaYpAl-SeCuRe-UpDaTe.CoM/...` (`score=11`), excessive subdomains (`score=11`), and `icici-online-update.xyz` (`score=12`).
3. **Network Adversarial Resilience (`10/10` Caught, `1/6` Benign Hard-Negative Flagged):** `AdaptiveNetworkDetector` detected all 10 adversarial flows (slow-rate scan, high destination diversity, outbound exfiltration, SYN bursts, low-and-slow probes, RST storms), flagging 1 benign SSH session (`45s`, `90` pkts) conservatively as `suspicious_unknown` (`sup=0.0`, `anom=0.008`) rather than `confirmed_malicious`.
