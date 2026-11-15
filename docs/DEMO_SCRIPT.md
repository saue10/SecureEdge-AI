# 5-Minute Competition Demonstration Script (Phase 4 — Task 10)

## Launch Command (Localhost Only, Offline-Ready)
```bash
python scripts/run_application.py --host 127.0.0.1 --port 8501
```
Open `http://127.0.0.1:8501` in a browser.

## 5-Minute Live Walkthrough Sequence

1. **0:00–0:45 | System & Offline Readiness (`10. System & Offline Status` & `1. Security Overview`):**
   - Show local host telemetry (`Windows 11 x86_64`, `8 GB RAM`, zero cloud calls) and default `FAST TRIAGE` mode.
   - State transparently that Meta Llama 3.2 ExecuTorch and physical ARM64 deployment are not executed on this Windows laptop, while SmolLM2-135M serves as the local comparison static graph.

2. **0:45–1:45 | URL & SMS Adversarial Hardening (`2. URL Threat Scanner` & `3. SMS Scam Analyzer`):**
   - Load Scenario 3 (`https://раypal-security.com/account/login?id=demo1`) -> show `confirmed_malicious`, Cyrillic confusable evidence, and sub-5 ms `FAST TRIAGE` response.
   - Load Scenario 4 (Legitimate OTP) -> `normal`, followed by Scenario 6 (Hinglish eKYC scam) -> `confirmed_malicious`.

3. **1:45–2:45 | Network False-Positive Reduction (`4. Network Analyzer` & `5. PCAP Upload & Replay`):**
   - Run Scenario 10 (Legitimate Microservice Burst) -> show `normal` (`0/125` false confirmed malicious in unseen evaluation).
   - Run Scenario 9 (Outbound Exfiltration to `sbi-kyc-update99.xyz`) -> `confirmed_malicious`.
   - Click `Replay Bundled sample_network_traffic.pcap` to show safe Scapy PCAP parsing.

4. **2:45–3:45 | Cross-Modality Incident Correlation & Redacted Export (`7. Incident History` & `8. Incident Detail & Export`):**
   - Open the correlated incident linking Scenario 5/6 (SMS) and Scenario 9 (Network) via `exact_registered_domain: sbi-kyc-update99.xyz`.
   - Toggle `Redact sensitive data` and download the Markdown/JSON incident report.

5. **3:45–5:00 | Verified Benchmarks & Optional Deep Analysis (`9. Performance Benchmarks`):**
   - Review Phase 1–3 metrics (SMS `100%` synthetic adv recall, URL `93.91%` adv recall, Network unseen alert FPR reduced `85.6% -> 0.8%`), emphasizing synthetic evaluation scope and `38+` passing automated tests.
