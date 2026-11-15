# SecureEdge AI — System Architecture Specification

**Project:** SecureEdge AI: An Intelligent On-Device Cybersecurity Assistant for Phishing, Scam and Network Threat Detection Using ARM-Based Edge Computing  
**Competition:** Bharat AI-SoC Challenge 2026–27 | Problem Statement 3 (PS3)

---

## 1. High-Level Modular Architecture

```
INPUT SOURCES
    |
    |--------------------|----------------------|
    |                    |                      |
 Phishing URLs        Scam SMS             Network Traffic
    |                    |                      |
    v                    v                      v
 URL Detector       SMS Classifier        Scapy Collector
 (32 Lexical/        (Word+Char TF-IDF     (Passive Sniff /
  Host Features)      + 12 Fraud Rules)     PCAP Flow Parser)
    |                    |                      |
    |                    |                 Flow Features (16D)
    |                    |                      |
    |                    |                 Anomaly Model
    |                    |                 (Calibrated RF +
    |                    |                  IsolationForest)
    |                    |                      |
    |--------------------|----------------------|
                         |
                         v
               UNIFIED THREAT ENGINE
               (src/threat_engine/engine.py)
                         |
                         v
                RISK ASSESSMENT (0-100)
                & CALIBRATED CONFIDENCE
                         |
                         v
                 STRUCTURED EVIDENCE
                 (LlamaExplanationInput)
                         |
                         v
                 LLAMA 3.2 ARCHITECTURE
                 (LlamaForCausalLM)
                         |
                         v
                   EXECUTORCH (.pte)
               (torch.export / XNNPACK)
                         |
                         v
                 ARM CPU INFERENCE
                         |
                         v
               SECURITY ASSISTANT UI
             -------------------------
             |           |           |
          Threat     Explanation   Recommended
          Status      and Evidence   Actions
```

---

## 2. Strict Separation of Responsibilities

A foundational engineering principle of **SecureEdge AI** is the strict separation between **Specialized Threat Detection** and **Generative AI Advisory**:

1. **Specialized Detectors (`src/url_detection/`, `src/sms_detection/`, `src/network_detection/`)**:
   - Extract deterministic, domain-specific mathematical features (entropy, lexical ratios, n-gram TF-IDF, TCP flag ratios, port anomalies).
   - Compute calibrated classification probabilities (`predict_proba` via `CalibratedClassifierCV`).
   - Produce a normalized risk score (`0–100`), categorical severity (`benign`, `suspicious`, `malicious`), and verifiable forensic evidence items (`evidence: List[str]`).

2. **Local Llama + ExecuTorch Advisor (`src/llama/`, `src/executorch/`)**:
   - Receives **only** the bounded `LlamaExplanationInput` JSON (`threat_type`, `risk_level`, `confidence`, `evidence`).
   - Translates technical forensic indicators into plain, understandable language for non-expert end users and provides safe remediation steps.
   - **Guardrail Enforcement:** The Unified Threat Engine (`UnifiedThreatEngine._finalize_report`) enforces that Llama **cannot** invent unverified threat evidence and **cannot** override the detector's `risk_level` or `classification`.

---

## 3. Data Schemas & Contracts

### 3.1 Unified Threat Engine Output Schema (`DetectorResult.to_spec_dict()`)
```json
{
  "source": "url | sms | network",
  "threat_type": "phishing | scam | spam | network_anomaly | benign",
  "classification": "benign | suspicious | malicious",
  "confidence": 0.94,
  "risk_score": 94,
  "evidence": [
    "Brand impersonation indicator: sbi found outside registered domain (auth-gateway-99.xyz)",
    "High-risk top-level domain (.xyz) frequently abused in phishing campaigns"
  ],
  "timestamp": "2026-11-15T08:36:18.102931+00:00",
  "model_version": "url-randomforest_calibrated-v1.0"
}
```

### 3.2 Llama + ExecuTorch Input & Output Schemas
- **Input (`LlamaExplanationInput`)**:
```json
{
  "threat_type": "phishing",
  "risk_level": "critical",
  "confidence": 0.94,
  "evidence": [
    "Suspicious URL structure",
    "Credential-related path",
    "Unusual hostname characteristics"
  ]
}
```
- **Output (`LlamaExplanationOutput`)**:
```json
{
  "explanation": "The URL exhibits critical-risk characteristics commonly associated with phishing (detector confidence: 94.0%). Key verified indicators: Suspicious URL structure; Credential-related path; Unusual hostname characteristics.",
  "recommendation": "Do not open the link or enter any login credentials, OTPs, or financial details. Verify the request independently by navigating directly to the organization's official application or website.",
  "risk_level": "critical"
}
```
