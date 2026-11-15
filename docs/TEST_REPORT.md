# SecureEdge AI — Quality Assurance, Unit & Integration Test Report

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Framework:** Python `unittest` (`tests/unit/` and `tests/integration/`)  
**Latest Verified Run:** 16 tests passed in `317.241s` (`OK`, 0 failures, 0 skipped) using `HuggingFaceTB/SmolLM2-135M-Instruct` (`smollm2_135m_cyber_advisor.pte`)  
**Execution Command:** `python -m unittest discover -s tests -p "test_*.py" -v`

---

## 1. Test Suite Summary

| Test Module | Test Class | Test Case | Target Capability | Status |
| :--- | :--- | :--- | :--- | :--- |
| `tests/unit/test_detectors_and_llama.py` | `TestURLDetectionUnit` | `test_url_feature_extraction_phishing_indicators` | 32-feature URL lexical/host extraction & evidence generation | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestURLDetectionUnit` | `test_url_registered_domain_extraction` | Effective registered domain extraction for anti-leakage group split | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestURLDetectionUnit` | `test_url_prediction_malicious_and_benign` | Calibrated RF phishing vs. government `.gov.in` benign inference | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestURLDetectionUnit` | `test_url_edge_cases_empty_and_malformed` | Blank URLs, broken IPv6 brackets, missing model fallback | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestSMSDetectionUnit` | `test_sms_cleaning_meta_tokens` | Normalization of URLs, currencies, and phone numbers | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestSMSDetectionUnit` | `test_sms_prediction_scam_vs_legit_otp` | KYC/PAN bank scam vs. legitimate transactional OTP | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestSMSDetectionUnit` | `test_sms_edge_cases_empty_and_very_long` | Empty SMS & 15,000-character benign message outlier stability | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestNetworkDetectionUnit` | `test_scapy_pcap_flow_extraction` | Scapy `rdpcap` reading & 5-tuple flow aggregation | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestNetworkDetectionUnit` | `test_network_syn_flood_and_benign_https` | TCP SYN flood detection vs. normal TLS 1.3 web session | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestNetworkDetectionUnit` | `test_network_empty_flow_handling` | Malformed / empty flow dictionary safety | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestLlamaExecuTorchUnit` | `test_tokenizer_encode_decode_roundtrip` | `CyberLlamaTokenizer` deterministic encode/decode | ✅ PASS |
| `tests/unit/test_detectors_and_llama.py` | `TestLlamaExecuTorchUnit` | `test_llama_input_validation_and_output_grounding` | Pydantic schema enforcement & `.pte` graph execution | ✅ PASS |
| `tests/integration/test_end_to_end_pipeline.py` | `TestEndToEndPipelineIntegration` | `test_e2e_url_to_llama_pipeline` | `URL -> Detector -> Threat Engine -> Llama (.pte) -> Explanation` | ✅ PASS |
| `tests/integration/test_end_to_end_pipeline.py` | `TestEndToEndPipelineIntegration` | `test_e2e_sms_to_llama_pipeline` | `SMS -> Detector -> Threat Engine -> Llama (.pte) -> Explanation` | ✅ PASS |
| `tests/integration/test_end_to_end_pipeline.py` | `TestEndToEndPipelineIntegration` | `test_e2e_network_pcap_to_llama_pipeline` | `Scapy PCAP -> Flow Extractor -> Detector -> Threat Engine -> Llama` | ✅ PASS |
| `tests/integration/test_end_to_end_pipeline.py` | `TestEndToEndPipelineIntegration` | `test_web_dashboard_and_rest_api_integration` | Full Flask REST API (`/`, `/api/status`, `/api/scan/*`, `/api/explain`, `/api/benchmarks`) | ✅ PASS |

---

## 2. Issues Identified & Fixed During QA

During initial test execution (`task-102`), three genuine bugs were uncovered and resolved prior to final validation:

1. **Scapy PCAP Connection Frequency Aggregation (`src/network_detection/collector.py`)**:
   - *Symptom:* `test_e2e_network_pcap_to_llama_pipeline` flagged a 18-packet benign HTTPS session as anomalous.
   - *Root Cause:* `packets_to_flows()` incremented `src_conn_counts[(src_ip, dst_port)]` on every packet rather than on TCP SYN handshakes.
   - *Fix:* Counted SYN handshakes (`tcp_flags_int & 1`) as distinct connection attempts, accurately reporting `connection_frequency = 1` for single persistent HTTPS flows.

2. **Extreme-Length Benign SMS Scaling Outlier (`src/sms_detection/features.py` & `detector.py`)**:
   - *Symptom:* `test_sms_edge_cases_empty_and_very_long` misclassified a 15,250-character benign lecture note as malicious.
   - *Root Cause:* Unbounded `char_length` and `word_count` produced a `>100σ` outlier after `StandardScaler` in the linear SVM decision function, compounded by bare `"today"` matching `URGENCY_PATTERNS`.
   - *Fix:* Capped structural length features at `(500 chars, 100 words)`, tightened urgency regexes to contextual phrases (`blocked today`, `today only`), and added a conversational guardrail when zero financial/URL/phone/urgency indicators are present.

3. **High-Risk Structural Phishing Dilution (`src/url_detection/detector.py`)**:
   - *Symptom:* Multi-indicator phishing URLs on unseen domains could be softened into the `suspicious` band (`risk_score < 60`) if tree probabilities were slightly conservative.
   - *Fix:* Enforced a structural floor (`blended_prob = max(blended_prob, heuristic_score / 100.0)`) whenever deterministic structural indicators exceed `70/100` on non-trusted TLDs.
