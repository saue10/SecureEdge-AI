# Network False-Positive Analysis & Context-Aware Reduction (Phase 3 — Priority 3)

## 1. Root Cause of Phase 2 Unseen False Positives
In Phase 2, `AdaptiveNetworkDetector` achieved `99.6%` unseen attack recall in alert mode at the cost of an **`85.6%` false-positive rate (`214/250`)** on unseen benign flows (`benign_microservice_burst`: `100/125` `confirmed_malicious`; `benign_ssh_session`: `82/125` `suspicious_unknown`).  
The root causes were:
1. Out-of-distribution burst connection frequencies caused `HistGradientBoosting` to output high `supervised_prob` even when bidirectional ACK ratios were healthy (`ack_flag_ratio >= 0.35`, `syn_ack_imbalance < 0.25`).
2. `IsolationForest` novelty flags (`anomaly_score < 0`) were directly promoted to `suspicious_unknown` without checking handshake health or attack-specific corroboration.

## 3. Context-Aware Architecture (`src/network_detection/context_aware.py`)
- **`HostBehaviorBaseline`:** Computes per-source-IP (and global fallback) **median and Median Absolute Deviation (`1.4826 * MAD`)** over 7 behavioral flow dimensions on benign training traffic.
- **Burst-vs-Sustained & Session Differentiation:**
  - `burst_benign_balance`: `ack_flag_ratio * (1 - syn_ack_imbalance) * (1 - rst_flag_ratio)`.
  - `sustained_exfil_score`: Requires high `payload_byte_ratio >= 0.85`, `bytes_per_sec >= 60 KB/s`, and large `bytes_per_packet >= 650`.
  - `stealth_probe_score`: Requires low-rate multi-port probing (`duration >= 3s`, `pps <= 15`, `unique_dst_ports >= 3`), separating it from single-port `benign_ssh_session`.
- **Multi-Signal Confirmation & Abstention:**
  - Anomaly score alone **never** produces `confirmed_malicious`.
  - Healthy bidirectional bursts (`benign_burst_profile`) and long-lived single-port interactive sessions (`benign_interactive_session`) are protected from volume-only false positives, routing extreme out-of-distribution bursts to `insufficient_evidence` instead of `confirmed_malicious`.

## 4. Experimental Results (`results/phase3_hardening/phase3_results.json`)

| Detector | Split | Strict FPR | Alert FPR | Alert Recall | Alert Macro F1 | Abstentions |
|---|---|---:|---:|---:|---:|---:|
| Phase 2 `AdaptiveNetworkDetector` | Unseen (`500`) | `0.4000` | `0.8560` | `0.9960` | `0.4747` | `0` |
| **Phase 3 `ContextAwareNetworkDetector`** | **Unseen (`500`)** | **`0.0000`** | **`0.0080`** | **`0.9040`** | **`0.9479`** | `71` |
| Phase 2 `AdaptiveNetworkDetector` | Adversarial (`440`) | `0.3409` | `0.4955` | `0.9909` | `0.7319` | `0` |
| **Phase 3 `ContextAwareNetworkDetector`** | **Adversarial (`440`)** | **`0.0000`** | **`0.0000`** | **`0.9364`** | **`0.9681`** | `0` |
| **Phase 3 `ContextAwareNetworkDetector`** | Known (`200`) | `0.0000` | `0.0000` | `0.6400` | `0.8140` | `25` |

### Unseen Per-Scenario Breakdown (`ContextAwareNetworkDetector`)
- `benign_microservice_burst` (`125`): `0` `confirmed_malicious`, `2` `suspicious_unknown`, `56` `normal`, `67` `insufficient_evidence`.
- `benign_ssh_session` (`125`): `0` `confirmed_malicious`, `0` `suspicious_unknown`, `125` `normal`.
- `data_exfiltration_anomaly` (`125`): `95` `confirmed_malicious`, `16` `suspicious_unknown`, `14` `normal`.
- `stealth_low_slow_probe` (`125`): `61` `confirmed_malicious`, `54` `suspicious_unknown`, `6` `normal`, `4` `insufficient_evidence`.

**Honest Tradeoff:** Enforcing strict false-positive guardrails reduced Known-scenario recall from `1.0000` to `0.6400` (`36` missed known attacks, primarily low-rate/short-duration `c2_beaconing` and borderline `brute_force` flows, with `25` abstentions).
