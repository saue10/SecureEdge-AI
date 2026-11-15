# SecureEdge AI — Network Unknown-Threat & Unseen-Scenario Evaluation

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Command:** `python scripts/evaluation/run_phase2_adaptive_and_adversarial.py`  
**Results Artifact:** [`results/adaptive_threat_intelligence/phase2_results.json`](../results/adaptive_threat_intelligence/phase2_results.json)  

---

## 1. Phase A Audit: Why Naive Anomaly Detection Fails on Unseen Benign Bursts

Holding out **both** unseen benign scenarios (`benign_ssh_session`, `benign_microservice_burst`, `250` rows) and unseen attack scenarios (`data_exfiltration_anomaly`, `stealth_low_slow_probe`, `250` rows) from `network_flows_dataset.csv` (`1,500` total) revealed:
- Training benign traffic (`dns`, `http`, `https`, `ntp`) has `is_sensitive_admin_port = 0.00` everywhere.
- Consequently, `EllipticEnvelope` suffered a singular covariance matrix (`FPR = 1.0000`, `Macro F1 = 0.3333`) and `LocalOutlierFactor(novelty=True)` flagged **100%** of unseen benign traffic (`FPR = 1.0000`, `Macro F1 = 0.3333`).
- `IsolationForest` achieved `ROC-AUC = 0.8288` (`FPR = 0.5000`, `Recall = 1.0000`), demonstrating useful separation between unseen attacks and SSH, though `benign_microservice_burst` (`syn_flag_ratio=0.33`, `8.02` ports) triggered novelty alerts.

---

## 2. Known vs. Unseen Scenario Results

| Model | Known Macro F1 | Unseen Acc | Unseen Macro F1 | Unseen Recall | Unseen FPR | Unseen FNR | Unseen AUC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`AdaptiveNetworkDetector` (Strict `confirmed_malicious`)** | `1.0000` | `0.6440` | `0.6433` | `0.6880` | `0.4000` | `0.3120` | — |
| **`AdaptiveNetworkDetector` (Alert = `confirmed` ∪ `suspicious_unknown`)** | `0.9560` | `0.5840` | `0.4989` | **`0.9960`** | `0.8280` | **`0.0040`** | — |
| **`IsolationForest_Raw`** | `0.8611` | `0.7500` | `0.7333` | `1.0000` | `0.5000` | `0.0000` | **`0.8288`** |
| **`RandomForest`** | `1.0000` | `0.7320` | `0.7168` | `0.9640` | `0.5000` | `0.0360` | `0.5784` |
| **`HistGradientBoosting`** | `1.0000` | `0.6440` | `0.6433` | `0.6880` | `0.4000` | `0.3120` | `0.6440` |
| **`LogisticRegression`** | `1.0000` | `0.6620` | `0.6529` | `0.8240` | `0.5000` | `0.1760` | `0.5392` |
| **`LOF_Novelty_Raw`** | `0.9560` | `0.5000` | `0.3333` | `1.0000` | `1.0000` | `0.0000` | `0.4644` |
| **`EllipticEnvelope_Raw`** | `0.9720` | `0.5000` | `0.3333` | `1.0000` | `1.0000` | `0.0000` | `0.6251` |

**Per-Scenario Breakdown (`AdaptiveNetworkDetector` on Unseen Scenarios):**
- `data_exfiltration_anomaly` (`125`): `107` `confirmed_malicious`, `18` `suspicious_unknown`, `0` `normal` (`99.2–100%` caught).
- `stealth_low_slow_probe` (`125`): `65` `confirmed_malicious`, `59` `suspicious_unknown`, `1` `normal` (`99.2%` caught).
- `benign_ssh_session` (`125`): **`0` `confirmed_malicious`**, `82` `suspicious_unknown`, `43` `normal` (never falsely confirmed malicious).
- `benign_microservice_burst` (`125`): `100` `confirmed_malicious`, `25` `suspicious_unknown`, `0` `normal` (synthetic burst overlaps `port_scan` SYN/port-diversity distributions).

**Disclosure:** All network flows are from the synthetic `network_flows_dataset.csv`; real-world CICIDS2017/UNSW-NB15 generalization is not claimed from these numbers.
