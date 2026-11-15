# Calibrated Threat Decision & Abstention Policy (Phase 3 — Priority 4)

## 1. Operational Decision States

Every assessment returned by `CalibratedThreatEngine` (`src/threat_engine/calibrated_policy.py`) maps to one of four explicit operational states:

1. **`confirmed_malicious`**: High calibrated malicious probability (`>= 0.65`) corroborated by at least one independent forensic/behavioral attack signal.
2. **`suspicious_unknown`**: Moderate calibrated risk (`>= 0.40`), bare URL shortener without destination visibility, or out-of-distribution behavioral anomaly without full multi-signal confirmation.
3. **`normal`**: Low calibrated malicious probability (`< 0.40` outside abstention band) and no unmitigated threat indicators.
4. **`insufficient_evidence`**: Explicit confidence-aware abstention triggered by empty/truncated input, incomplete flow telemetry (`flow_duration_sec <= 0` or `packet_count <= 0`), or ambiguous probability in `[0.32, 0.54)` with zero corroborating indicators.

## 2. Documented Thresholds (`PolicyThresholds`)

| Parameter | Value | Rationale |
|---|---:|---|
| `confirmed_prob_min` | `0.65` | Validation-calibrated probability floor requiring >= 1 independent forensic indicator to prevent single-score false positives. |
| `suspicious_prob_min` | `0.40` | Moderate-risk triage boundary for manual review or secondary inspection. |
| `abstention_low` | `0.32` | Lower bound of the uncertainty/abstention band when no forensic signal is present. |
| `abstention_high` | `0.54` | Upper bound of the uncertainty/abstention band when no forensic signal is present. |
| `min_sms_chars` | `4` | Minimum SMS length before abstaining on insufficient context. |
| `min_url_chars` | `4` | Minimum URL length (plus domain structure check) before abstaining. |
| `anomaly_z_suspicious` | `4.0` | Robust MAD z-score threshold relative to per-host (or global) baseline. |

## 3. Core Design Guarantees

- **Validation-Only Probability Calibration**: Classifiers are calibrated via `CalibratedClassifierCV` (`sigmoid`) strictly on held-out validation splits—never on training or test splits.
- **Strict Separation of Probability and Anomaly Score**: `supervised_probability` and unsupervised `anomaly_score` / `host_robust_z` are reported as separate fields and never arbitrarily averaged.
- **No Double-Counting**: `_deduplicate_evidence` normalizes and deduplicates overlapping indicator strings before advisory generation.
- **Detector-Controlled Risk Guardrail**: `risk_level` (`low`, `medium`, `high`, `critical`) is locked deterministically by `CalibratedDecisionPolicy.risk_level_from_state_and_score` before any optional `DEEP ANALYSIS` LLM call. `FAST TRIAGE` never invokes an LLM (`llm_used = False`).
