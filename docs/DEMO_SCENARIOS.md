# Controlled Offline Synthetic Demonstration Scenarios (Phase 4 — Task 5)

All 10 scenarios in `src/threat_engine/demo_scenarios.py` are **clearly labelled synthetic offline examples** runnable with one click via the dashboard (`6. Unified Intelligence & Demo`) or `POST /api/v2/demo/run` (defaulting to `FAST TRIAGE`, zero internet required).

| # | Scenario ID | Modality | Expected State | Purpose |
|---:|---|---|---|---|
| 1 | `demo_01_benign_url` | URL | `normal` | Official documentation URL baseline |
| 2 | `demo_02_phishing_url` | URL | `confirmed_malicious` | Brand subdomain + `.xyz` phishing URL |
| 3 | `demo_03_idn_homograph` | URL | `confirmed_malicious` | Cyrillic confusable `раypal-security.com` |
| 4 | `demo_04_legit_otp_sms` | SMS | `normal` | Legitimate OTP with non-sharing warning |
| 5 | `demo_05_scam_kyc_sms` | SMS | `confirmed_malicious` | Spaced-out KYC scam (`sbi-kyc-update99.xyz`) |
| 6 | `demo_06_hinglish_scam_sms` | SMS | `confirmed_malicious` | Hinglish eKYC lure (`sbi-kyc-update99.xyz`) |
| 7 | `demo_07_normal_network` | Network | `normal` | Standard HTTPS browsing flow |
| 8 | `demo_08_slow_probing_network` | Network | `suspicious_unknown` | Low-and-slow multi-port reconnaissance |
| 9 | `demo_09_outbound_exfil_network` | Network | `confirmed_malicious` | Sustained outbound transfer to `sbi-kyc-update99.xyz` |
| 10 | `demo_10_microservice_burst` | Network | `normal` | Legitimate RPC burst (FP reduction proof) |

**Cross-Modality Correlation Demo:** Running Scenarios `5`, `6`, and `9` automatically correlates them into a single `IncidentRecord` via `exact_registered_domain = sbi-kyc-update99.xyz`.
