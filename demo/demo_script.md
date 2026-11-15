# SecureEdge AI — Official Phase 1 Demonstration Video Script & Recording Guide

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 | Problem Statement 3 (PS3)  
**Project Title:** SecureEdge AI: An Intelligent On-Device Cybersecurity Assistant for Phishing, Scam and Network Threat Detection Using ARM-Based Edge Computing  
**Target Duration:** 4 Minutes 45 Seconds (Within the 4–6 Minute Official Requirement)

---

## Pre-Recording Setup Instructions

1. Open a terminal in `f:\AI_SOC_Challenge`.
2. Ensure all models and the ExecuTorch `.pte` artifact are built:
   ```bash
   python scripts/train_models.py
   python scripts/evaluate_models.py
   ```
3. Launch the local **SECUREEDGE AI** dashboard:
   ```bash
   python scripts/run_application.py --host 127.0.0.1 --port 8501
   ```
4. Open `http://127.0.0.1:8501` in a browser window at `1920x1080` resolution.
5. Keep a terminal window open side-by-side to show `python scripts/run_application.py --cli-demo` and `python deployment/arm64/verify_arm64_executorch.py`.

---

## Scene-by-Scene Speaking Script (4:45 Total)

### Scene 1: Project Introduction (0:00 – 0:30)
- **Visual:** Show the **SECUREEDGE AI** Dashboard Overview tab (`1. Dashboard Overview`) with the top status pills visible (`ExecuTorch .pte: VERIFIED (3.17 MB)`, `100% On-Device Inference`).
- **Narration:**
  > "Hello everyone. We present **SecureEdge AI: An Intelligent On-Device Cybersecurity Assistant for Phishing, Scam, and Network Threat Detection Using ARM-Based Edge Computing**, developed for Problem Statement 3 of the Bharat AI-SoC Challenge 2026–27. Our tagline is *'Your Security. Your Device. Your Privacy.'* SecureEdge AI executes multi-modal threat detection and local Llama language model reasoning entirely on edge hardware using PyTorch ExecuTorch—with zero cloud dependency."

### Scene 2: Problem & Motivation (0:30 – 1:00)
- **Visual:** Highlight the threat breakdown cards and architecture diagram in `docs/ARCHITECTURE.md`.
- **Narration:**
  > "Users across India and globally face surging credential-harvesting phishing links, UPI and KYC bank-suspension SMS scams, and local network intrusions. Traditional security tools rely on cloud APIs that introduce network latency, fail when offline, and require uploading private SMS messages and browsing URLs to external servers. Furthermore, raw detector scores alone do not tell a non-expert user *why* a message is dangerous or *what safe action* to take."

### Scene 3: Modular Architecture & Separation of Responsibilities (1:00 – 1:40)
- **Visual:** Show the System Architecture flow in `docs/ARCHITECTURE.md` and switch to the dashboard navigation sidebar.
- **Narration:**
  > "SecureEdge AI solves this through a strictly separated two-tier edge architecture:
  > First, three specialized, probability-calibrated machine learning detectors inspect URLs, SMS messages, and passive Scapy network flows in under 38 milliseconds, extracting deterministic forensic evidence and calculating a calibrated risk score from 0 to 100.
  > Second, our Unified Threat Engine passes that structured evidence to a local **Llama 3.2 causal language model** exported via **PyTorch `torch.export` and ExecuTorch (`.pte`)**. By architectural design, Llama explains the detector's findings in plain language and recommends safe remediation steps—but is strictly prevented from inventing unverified evidence or overriding the detector's verdict."

### Scene 4: Live Phishing URL Detection Demo (1:40 – 2:20)
- **Visual:** Click **`2. URL Phishing Scanner`**. Click **`Preset: Banking KYC Phishing`**, then click **`Preset: Raw IP Credential Harvester`**, and finally **`Preset: Benign Government Portal`** (`https://www.india.gov.in/...`). Expand the JSON schema drawer.
- **Narration:**
  > "Let's test Priority 1: our Phishing URL Scanner, which extracts 32 domain-agnostic lexical, TLD, entropy, and brand-impersonation features trained with zero domain leakage across 1,200 registered domains.
  > When we inspect this SBI KYC phishing link hosted on a disposable `.xyz` domain, the calibrated Random Forest detector immediately flags it as **MALICIOUS** with a risk score of 88/100, citing brand impersonation outside the registered domain, excessive hyphens, and credential keywords. Below it, our local ExecuTorch Llama model generates a clear explanation and advises verifying directly through the official banking app. Conversely, when we scan an official `.gov.in` portal, it is accurately cleared as **BENIGN**."

### Scene 5: Live Scam SMS Detection Demo (2:20 – 3:00)
- **Visual:** Click **`3. SMS Scam Detector`**. Test **`Preset: KYC Bank Block Scam`**, **`Preset: Lottery / Prize Fraud`**, and **`Preset: Legitimate Banking OTP`**.
- **Narration:**
  > "Moving to Priority 2: our Scam SMS Detector combines word and character n-gram TF-IDF with 12 structural financial coercion indicators. Unlike basic spam filters trained only on the classic UCI SMS Spam Collection, our classifier distinguishes targeted financial KYC/UPI scams from commercial spam, while recognizing legitimate transactional bank OTP messages that include standard *'do not share'* warnings and no external links."

### Scene 6: Passive Network Anomaly Detection Demo (3:00 – 3:35)
- **Visual:** Click **`4. Network Monitor`**. Click **`Run Scapy PCAP Replay (sample_network_traffic.pcap)`** and **`Inspect Custom SYN Flood Flow`**. Point out the explicit mode banner (`replay_demo` vs `live_capture`).
- **Narration:**
  > "For Priority 3, our Network Monitor uses **Scapy** to aggregate packet captures into 16-dimensional flow telemetry analyzed by a calibrated Random Forest and an unsupervised Isolation Forest. Notice how the interface transparently labels recorded PCAP replay mode versus passive live interface capture. Replaying our 126-packet Scapy capture accurately clears normal HTTPS and DNS traffic while flagging the TCP SYN flood, SSH brute-force probe, and 20-port reconnaissance scan."

### Scene 7: Llama + ExecuTorch `.pte` Runtime & Offline Verification (3:35 – 4:15)
- **Visual:** Click **`5. AI Threat Explanation`** and click **`Execute Local Llama (.pte) Inference`**. Then switch to **`7. System Information`** showing the `.pte` artifact verification (`llama_3_2_cyber_advisor.pte`, `3.17 MB`, `324 graph nodes`) and offline mode indicator.
- **Narration:**
  > "In the AI Threat Explanation tab, we can directly test the bounded JSON contract of our local `LlamaForCausalLM` model exported to `llama_3_2_cyber_advisor.pte` (3.17 MB, 324 static ATen graph nodes). Entirely offline, with zero internet access, the runtime generates a schema-validated explanation and remediation in ~149 milliseconds, while the entire multi-model suite occupies just 4.01 megabytes on disk."

### Scene 8: Edge Performance Benchmarks & Conclusion (4:15 – 4:45)
- **Visual:** Click **`8. Edge Benchmarks`** to display the latency table and the 4 embedded evaluation charts (`confusion_matrices.png`, `model_comparison_f1_auc.png`, `pipeline_latency_breakdown.png`, `model_footprint_comparison.png`).
- **Narration:**
  > "Finally, the Edge Benchmarks view presents our unseen test-set confusion matrices, architecture comparisons, and latency breakdowns—explicitly separating measured host telemetry from our ARM64 Raspberry Pi 5 deployment package in `deployment/`. With a 4.01 MB total model footprint, sub-200ms end-to-end latency, and 100% offline privacy, SecureEdge AI delivers practical, trustworthy on-device cybersecurity for ARM edge platforms. Thank you!"
