# SecureEdge AI — Adaptive Threat Intelligence & Resource-Efficient Inference

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Command:** `python scripts/evaluation/run_phase2_adaptive_and_adversarial.py`  
**Results Artifact:** [`results/adaptive_threat_intelligence/phase2_results.json`](../results/adaptive_threat_intelligence/phase2_results.json)  

---

## 1. Architecture & Decision Policy

`AdaptiveThreatIntelligenceEngine` ([`src/threat_engine/adaptive_engine.py`](../src/threat_engine/adaptive_engine.py)) unifies specialized detectors with `AdaptiveNetworkDetector` ([`src/network_detection/adaptive.py`](../src/network_detection/adaptive.py)) under a transparent four-state policy:

1. **`insufficient_evidence`**: Empty URL/SMS string or zero-packet network flow (`packet_count = 0`).
2. **`confirmed_malicious`**: Supervised calibrated probability `>= calibrated_threshold` (e.g., `0.60` for network, `0.57` for URL).
3. **`suspicious_unknown`**: Supervised probability is below confirmed threshold, **but** either `IsolationForest` `anomaly_score > 0.0` or probability lies in the `[0.40, threshold)` uncertainty band. Bounded risk score (`40–74`), never forced into `confirmed_malicious`.
4. **`normal`**: Both supervised probability (`< 0.40`) and anomaly score (`<= 0.0`) remain within baseline bounds.

**Anti-Double-Counting & Guardrails:**
- `supervised_probability` and `anomaly_score` are reported as **separate fields** (never merged via arbitrary weights).
- Duplicate or semantically identical evidence strings are collapsed via `_deduplicate_evidence()`.
- `risk_level` is strictly derived from detector/engine risk scores; the LLM cannot override detector verdicts.

---

## 2. Operating Modes Benchmark (`FAST TRIAGE` vs `DEEP ANALYSIS`)

Measured on Windows 11 (`Intel Core i5-1135G7`, `7.75 GiB` RAM, CPU-only PyTorch `2.8.0+cpu`):

| Operating Mode | Runs | P50 Latency | P95 Latency | Process RSS | LLM Backend |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`FAST TRIAGE` (No LLM)** | 45 | **`16.291 ms`** | **`36.051 ms`** | **`205.07 MB`** | `None (FAST TRIAGE)` |
| **`DEEP ANALYSIS` (Local LLM)** | 3 | `4,142.068 ms` | `20,559.422 ms` | `1,085.48 MB` | `torch.export.ExportedProgram (SmolLM2-135M-Instruct)` |

- **Speedup & Memory Savings:** `FAST TRIAGE` is **`254.3x` faster at P50** and consumes **`5.3x` less RAM** (`205.07 MB` vs `1,085.48 MB`), enabling high-throughput edge triage without loading LLM weights.
- **Graceful Degradation:** When the local LLM raises an error or is unavailable, `DEEP ANALYSIS` automatically falls back to deterministic structured advisories (`Fallback-Deterministic`).
