# Incident Correlation & Report Export Design (Phase 4 — Tasks 3 & 4)

## 1. Unified Incident Schema (`src/threat_engine/incidents.py`)
Each scan produces an `IncidentObservation` attached to an `IncidentRecord`:
- `incident_id`: Deterministic daily sequence (`INC-YYYYMMDD-NNNN`).
- `observations`: Normalized modality outputs (`url`, `sms`, `network`), detector name, operating mode, `llm_used` flag, `supervised_probability`, `anomaly_score`, and forensic evidence.
- `correlated_entities`: Recorded links explaining *why* observations were grouped.
- `timeline`: Chronological event log.
- `severity` & `decision_state`: Escalated monotonically to the highest observed risk level across linked observations.
- `limitations`: Explicit hardware/dataset scope disclaimers included in every exported report.

## 2. Defensible Correlation Rules (LLM-Independent)
`IncidentCorrelationEngine._find_defensible_match` links a new non-normal observation to an existing incident **only** when there is an exact entity match:
1. **`exact_url`**: Normalized URL string matches an observation already in the incident.
2. **`exact_registered_domain`**: Effective registered domain (e.g., `sbi-kyc-update99.xyz` extracted from an SMS body) matches a URL scan or network flow `dst_domain`.
3. **`exact_ip_address`**: Exact `src_ip` or `dst_ip` matches an existing non-normal incident.

**Anti-Hallucination Guardrail:** Fuzzy or similar-looking domain names (e.g., `sbi-kyc-update98.xyz` vs `sbi-kyc-update99.xyz`) are **never** correlated.

## 3. Sensitive-Data Redaction & Export
`export_json(id, redact=True)` and `export_markdown(id, redact=True)` mask phone numbers (`[PHONE_REDACTED]`), OTP codes (`[OTP_REDACTED]`), URL query secrets (`?token=[REDACTED]`), and the last two IPv4 octets (`192.168.*.*`).
