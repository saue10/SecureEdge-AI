# 5-Minute Competition Demonstration Script (Bharat AI-SoC PS3)

## 1. Pre-Recording Windows PowerShell Launch (Offline-Ready, Localhost Only)
```powershell
.\.venv\Scripts\Activate.ps1
$env:HF_HUB_OFFLINE = "1"
$env:TRANSFORMERS_OFFLINE = "1"
python scripts/run_application.py --host 127.0.0.1 --port 8501
```
Wait ~15 seconds for `Running on http://127.0.0.1:8501`, then open `http://127.0.0.1:8501` in Microsoft Edge / Chrome.

---

## 2. Exact 5-Minute Recording Sequence

### **0:00–0:45 | System & Offline Readiness (`10. System & Offline Status` & `1. Security Overview`)**
- Open **`10. System & Offline Status`**: highlight Windows 11 `x86_64` host telemetry, `FAST TRIAGE` default mode (`Lazy-Ready` LLM with `0` weights loaded at startup), and loaded Phase 3 detectors (`url-hardened-calibrated-v3.0`, `sms-hardened-calibrated-v3.0`, `network-context-aware-v3.0`).
- **Transparency Statement:** Explicitly state that this demo runs on the Windows 11 laptop in offline `FAST TRIAGE` mode; genuine Meta Llama 3.2 ExecuTorch (`.pte`) and physical ARM64 / PYNQ-Z2 hardware acceleration are **not** executed on this machine.
- Switch to **`1. Security Overview`** to show live incident KPIs.

### **0:45–1:45 | One-Click Synthetic Adversarial URL & SMS Detection (`6. Unified Intelligence & Demo`, `2. URL`, `3. SMS`)**
- Open **`6. Unified Intelligence & Demo`** (confirm mode is **`FAST TRIAGE`**).
- Click **Run Scenario** on **Scenario 3 (`3. IDN Homograph URL`)**: `https://раypal-security.com/account/login?id=demo1` -> observe `confirmed_malicious`, Cyrillic confusable evidence, and `llm_used: false`.
- Click **Run Scenario** on **Scenario 4 (`4. Legitimate Banking OTP SMS`)** -> observe `normal` (no false positive).
- Click **Run Scenario** on **Scenario 6 (`6. Hinglish Scam SMS`)** -> observe `confirmed_malicious` (links `sbi-kyc-update99.xyz`).
- Optionally open **`2. URL Threat Scanner`** or **`3. SMS Scam Analyzer`** to paste a custom input live.

### **1:45–2:45 | Network False-Positive Reduction & PCAP Replay (`6. Demo`, `4. Network`, `5. PCAP`)**
- In **`6. Unified Intelligence & Demo`**, click **Run Scenario** on **Scenario 10 (`10. Legitimate Microservice Burst`)** -> observe `normal` (healthy ACK ratio protected from volume-only false positives).
- Click **Run Scenario** on **Scenario 9 (`9. Suspicious Outbound Transfer`)** -> observe `confirmed_malicious` (targeting `dst_domain: sbi-kyc-update99.xyz`).
- Open **`5. PCAP Upload & Replay`** and click **`Replay Bundled sample_network_traffic.pcap`** -> show safe Scapy parsing of 24 flows.

### **2:45–3:45 | Cross-Modality Incident Correlation & Redacted Export (`7. Incident History` & `8. Incident Detail & Export`)**
- Open **`7. Incident History`** -> point out the correlated incident merging **Scenario 6 (SMS)** and **Scenario 9 (Network)** via `exact_registered_domain: sbi-kyc-update99.xyz`.
- Click **`Inspect`** to open **`8. Incident Detail & Export`**.
- Keep **`Redact sensitive data`** checked, then click **`Download JSON Report`** and **`Download Markdown Report`** to show masked phone numbers/IPs and explicit limitations.

### **3:45–5:00 | Verified Benchmarks & Testing Summary (`9. Performance Benchmarks`)**
- Open **`9. Performance Benchmarks`**: walk through the Phase 3 synthetic gains (SMS Adv Recall `100%`, URL Adv Recall `93.91%`, Network Unseen Alert FPR reduced `85.6% -> 0.80%`), `/api/status` P50 `15.92 ms`, and `39/39` passing automated tests.
- Reiterate that all accuracy metrics are from synthetic/curated benchmarks rather than live field telemetry.
