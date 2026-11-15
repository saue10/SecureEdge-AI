# SecureEdge AI — Dataset Documentation & Governance

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Reproducibility Seed:** `RANDOM_SEED = 42`  
**Preparation Script:** `scripts/download_datasets.py`

---

## 1. Overview of Datasets

| Dataset Modality | File Path | Total Records | Class Balance | Splitting Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **1. Phishing & Benign URLs** | `data/raw/url_dataset.csv` | 1,600 | 800 Benign / 800 Phishing | **Domain-Separated `GroupShuffleSplit`** (75% Train / 25% Test by `registered_domain`, 0 domain overlap) |
| **2. Scam & Spam SMS** | `data/raw/sms_dataset.csv` | 1,200 | 600 Benign / 600 Scam & Spam | Stratified 75% Train (900) / 25% Unseen Test (300) |
| **3. Network Intrusion Flows** | `data/raw/network_flows_dataset.csv` | 1,500 | 750 Benign / 750 Anomaly | Stratified 75% Train (1,125) / 25% Unseen Test (375) |
| **4. Reference Scapy PCAP** | `data/processed/sample_network_traffic.pcap` | 126 Packets (24 Flows) | Benign HTTPS/DNS + SYN Flood, SSH Brute-Force, Port Scan | Held-out Replay Evaluation |

---

## 2. Detailed Dataset Specifications

### 2.1 URL Phishing Dataset (`url_dataset.csv`)
- **Design & Reference Sources:** Modeled on structural distributions from **PhishTank** (OpenDNS/Cisco, CC-BY/Open Data), **OpenPhish** public feed schemas, and **Tranco Top Sites** benign URL structures.
- **Anti-Leakage Guarantee:** Standard random splitting of URL datasets allows the same domain (e.g., `phish-site.xyz/page1` and `phish-site.xyz/page2`) to appear in both training and test sets, inflating accuracy. SecureEdge AI extracts the effective registered domain (`URLFeatureExtractor.extract_registered_domain`) across 1,200 unique domains and uses `GroupShuffleSplit(test_size=0.25, random_state=42)` so **zero registered domains overlap (`domain_overlap = 0`)** between training (900 domains) and test (300 domains).
- **Inclusion of Hard Negatives & Stealth Positives:** Includes 100 hard-negative benign URLs (complex OAuth redirects, `.xyz`/`.top` developer repositories, HTTP intranet login URLs) and 100 stealthy phishing URLs (clean HTTPS `.com`/`.org` domains with short paths).

### 2.2 Scam & Spam SMS Dataset (`sms_dataset.csv`)
- **Reference Source & Licence:** Built upon the canonical **UCI SMS Spam Collection** (Almeida & Hidalgo, 2011; Public Domain / CC-BY 4.0, `https://archive.ics.uci.edu/dataset/228/sms+spam+collection`) augmented with structured Indian and global financial fraud templates (KYC/PAN suspension lures, electricity disconnection threats, UPI cashback traps, customs parcel seizures, and legitimate transactional banking OTPs).
- **Preprocessing:** Normalizes URLs (`__URL_TOKEN__`), currency amounts (`__CURRENCY_TOKEN__`), and phone numbers (`__PHONE_TOKEN__`) for TF-IDF vectorization while extracting 12 explicit structural fraud features.
- **Explicit Limitation Disclosure:** The classic UCI SMS Spam Collection primarily represents commercial/promotional English spam rather than modern UPI/KYC financial fraud. While our augmented corpus and 12 structural indicators detect English-language financial coercion patterns effectively, regional-language (Hindi/Tamil/Telugu/vernacular) transliterated SMS scams require multilingual tokenization in future work.

### 2.3 Network Flow Anomaly Dataset (`network_flows_dataset.csv` & `sample_network_traffic.pcap`)
- **Reference Sources & Licences:** Flow feature schema modeled after **CICIDS2017** (Canadian Institute for Cybersecurity, UNB), **UNSW-NB15** (UNSW Canberra Cyber), and **NSL-KDD**.
- **Format:** 16 flow-level telemetry features (`flow_duration_sec`, `protocol_id`, `dst_port`, `packet_count`, `byte_count`, `packets_per_sec`, `bytes_per_sec`, `mean_packet_size`, `syn_flag_ratio`, `rst_flag_ratio`, `ack_flag_ratio`, `fin_flag_ratio`, `unique_dst_ports_window`, `connection_frequency`, `payload_byte_ratio`, `is_sensitive_admin_port`).
- **Scapy PCAP Verification:** `ScapyFlowCollector.generate_reference_pcap()` constructs a genuine 126-packet `.pcap` binary (`sample_network_traffic.pcap`) parsed via `scapy.all.rdpcap` to verify real packet-to-flow aggregation.
