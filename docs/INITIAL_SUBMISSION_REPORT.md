# SecureEdge AI — Initial Submission Technical Report

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27  
**Problem Statement:** PS3 — On-device threat, phishing & scam detection  
**Deadline:** 23 November 2026 | **Base Commit:** `93dbf8e` (+ P0 & Packaging updates on `main`)

---

## 1. Problem Statement
End users and edge devices face growing exposure to phishing URLs (including IDN homographs, Punycode, and encoded redirects), adversarial scam SMS messages (spaced text, leetspeak, zero-width characters, and Hinglish social engineering), and network anomalies. Cloud-centric security APIs leak sensitive user telemetry, fail in air-gapped environments, and incur network latency.

## 2. Proposed Solution
**SecureEdge AI** is an offline-first, privacy-preserving cybersecurity assistant that combines calibrated, adversarial-hardened ML detectors across URL, SMS, and network modalities with a deterministic `CalibratedDecisionPolicy`, LLM-independent incident correlation, redacted JSON/Markdown reporting, and a 10-view localhost Flask SOC dashboard (`FAST TRIAGE` default).

## 3. System Architecture
```text
  URL Input  ──► HardenedURLDetector (44 features) ──────────┐
  SMS Input  ──► HardenedSMSDetector (Word+Char TF-IDF + 20) ├──► CalibratedThreatEngine
  PCAP/Flow  ──► ContextAwareNetworkDetector (MAD + HGB+IF) ─┘       │
                                                                     ├── FAST TRIAGE (Default, Zero LLM)
                                                                     └── DEEP ANALYSIS (Optional SmolLM2-135M + Fallback)
                                                                     ▼
                                                        IncidentCorrelationEngine (Exact URL / Domain / IP)
                                                                     ▼
                                                  10-View Flask Dashboard (127.0.0.1:8501) & Redacted Export
```

## 4. URL, SMS and Network Detection Modules
- **URL (`src/url_detection/hardened.py`, `0.342 MB`):** 44 lexical/host/IDN features detecting Punycode impersonation, Cyrillic/Greek confusables, mixed scripts, mixed-case obfuscation, excessive subdomains, and encoded redirect parameters, paired with an opt-in, SSRF-safe `SafeRedirectInspector` (disabled during ordinary offline scans).
- **SMS (`src/sms_detection/hardened.py`, `0.169 MB`):** `HardenedSMSPreprocessor` strips zero-width chars, normalizes NFKC + homoglyphs, collapses spaced tokens (`k y c`) and repeated chars, selectively decodes leetspeak, and extracts Hinglish scam markers into Word+Char TF-IDF + 20 structural features (`CalibratedClassifierCV`) while protecting legitimate OTPs and bank debit/balance alerts.
- **Network (`src/network_detection/context_aware.py`, `2.216 MB`):** Combines per-host/global Median & MAD baselines (`HostBehaviorBaseline`), `HistGradientBoostingClassifier`, and benign-fitted `IsolationForest` with multi-signal confirmation so high-volume microservice bursts and long-lived SSH sessions are not flagged `confirmed_malicious` from volume alone.

## 5. Unified Threat Engine
`CalibratedThreatEngine` (`src/threat_engine/calibrated_policy.py`) outputs four operational states (`confirmed_malicious`, `suspicious_unknown`, `normal`, `insufficient_evidence`), separates calibrated `supervised_probability` from `anomaly_score`, deduplicates evidence, supports confidence-aware abstention, and locks `risk_level` deterministically so optional LLM explanations can never downgrade detector verdicts.

## 6. Offline-First Operation
- Default `FAST TRIAGE` runs with zero LLM weights loaded (`llm_used = False`).
- Live Flask server verified with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`: all 12 tested endpoints returned `200 OK`, zero automatic remote URL fetching occurs, and `DEEP ANALYSIS` falls back cleanly to deterministic advisories if unavailable.

## 7. Incident Correlation and Reporting
`IncidentCorrelationEngine` (`src/threat_engine/incidents.py`) correlates non-normal observations **strictly** on exact URL, exact registered domain, or exact IP address matches (independent of the LLM), bounds retention (`MAX_INCIDENTS = 200`), and exports JSON and Markdown reports with optional redaction of phone numbers, OTPs, query tokens, and partial IPv4 octets.

## 8. Dataset Provenance and Limitations
- **Training/Clean Evaluation:** Curated local CSV datasets (`data/raw/url_dataset.csv` 1,600 rows; `sms_dataset.csv` 1,200 rows deduplicated to 810; `network_flows_dataset.csv` 1,500 rows across 12 scenarios) plus `data/processed/sample_network_traffic.pcap`.
- **Adversarial Evaluation:** Synthetic disjoint benchmarks (`220+` attacks and `220+` benign hard negatives per modality) generated in `scripts/evaluation/run_phase3_hardening.py` with zero train/test overlap.
- **Limitation:** Results reflect synthetic and curated local datasets rather than real-world field telemetry.

## 9. Experimental Results (Actual Measurements)
- **SMS (`HardenedSMSDetector` vs Baseline `ScamSMSDetector`):**
  - Clean (`122` deduplicated): `Macro F1 = 0.9544`, `Recall = 1.0000`, `FPR = 0.1136` (`5/44`).
  - Adversarial (`440`): `Recall = 1.0000` (`220/220` vs baseline `44.09%`), `FPR = 0.0000` (`0/55` FP across `benign_otp`, `benign_banking_alert`, `benign_personal`, `benign_commercial`).
- **URL (`HardenedURLDetector` vs Baseline `PhishingURLDetector`):**
  - Clean domain-group-split (`227`): `Macro F1 = 0.9867`, `FPR = 0.0288` (`3/104`).
  - Adversarial (`450`): `Recall = 0.9391` (`216/230` vs baseline `60.87%`), `0.0%` FPR on `benign_idn`, `benign_official_brand`, `benign_research_blog` (`benign_shortener` intentionally flagged `suspicious`).
- **Network (`ContextAwareNetworkDetector` vs Phase 2 `AdaptiveNetworkDetector`):**
  - Unseen (`500`, Alert Mode): `FPR` reduced **`85.6%` -> `0.80%`** (`2/250`), `Recall = 0.9040` (`226/250`), `Macro F1 = 0.9479`; `benign_microservice_burst`: `0/125` `confirmed_malicious`; `benign_ssh_session`: `125/125` `normal`.
  - Adversarial (`440`, Alert Mode): `Recall = 0.9364` (`206/220`), `FPR = 0.0000`, `Macro F1 = 0.9681`.
  - Known (`200`): `Precision = 1.0000`, `Recall = 0.6400` (`25` abstentions / `36` missed low-rate flows due to strict FP guardrails).

## 10. Performance Results (Windows 11, Intel Core i5-1135G7, ~8 GB RAM)
- **`/api/status` (25 consecutive requests):** **`P50 = 15.92 ms`**, **`P95 = 31.84 ms`** (down from `2,372.28 ms`).
- **Per-Detector `FAST TRIAGE` Latency:** URL `P50 = 10.31 ms`, SMS `P50 = 5.54 ms`, Network `P50 = 28.11 ms`; `FAST TRIAGE` peak RSS `~188.81 MB`; bundled 24-flow PCAP replay `~1.68 s`.
- **`DEEP ANALYSIS` (`SmolLM2-135M-Instruct`):** `P50 = 11.83 s`, `P95 = 19.79 s`, `RSS = 595.43 MB` (`520.94 MB` `.pte`).
- **Automated Tests:** `python -m unittest discover -s tests -p "test_*.py" -v` -> **`39/39` PASS (`349.430 s`)**.

## 11. Current Hardware Status
All verified metrics were measured on a **Windows 11 `x86_64` CPU-only laptop** (`Intel Core i5-1135G7`, ~8 GB RAM, Python `3.13.2`, PyTorch `2.8.0+cpu`). **Physical ARM64 and PYNQ-Z2 FPGA execution are NOT verified** on this host.

## 12. Meta Llama / ExecuTorch Compliance Status
- **Working Local Model:** `HuggingFaceTB/SmolLM2-135M-Instruct` (`134.5M` params, Apache-2.0, `LlamaForCausalLM`) via `torch.export.ExportedProgram`.
- **Meta Llama 3.2 (`meta-llama/Llama-3.2-1B-Instruct`, `8da4w` XNNPACK `.pte`):** **NOT verified/executed** on Windows (requires `HF_TOKEN` + Linux/ARM64 `executorch` wheel; `ExecuTorchLlamaRuntime.forward_Step()` also uses a stateless `(1, 96)` signature that must be aligned with KV-cache `(tokens, input_pos)` / `TextLLMRunner` on Linux/ARM64).

## 13. Limitations and Future Development
1. Execute `deployment/linux/export_meta_llama_executorch.sh` on Linux/ARM64 with `HF_TOKEN` and align `ExecuTorchLlamaRuntime` with `TextLLMRunner`.
2. Validate on real-world telemetry and physical ARM64 / PYNQ-Z2 hardware.
3. Tune Known-scenario network recall (`0.6400`) without regressing unseen `0.80%` FPR.
