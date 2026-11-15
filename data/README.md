# SecureEdge AI — Dataset Management & Reproducibility Directory

This directory stores the raw, processed, and PCAP replay datasets for **SecureEdge AI** (Bharat AI-SoC Challenge 2026–27 | PS3).

## Directory Contents

- `raw/url_dataset.csv`: 1,600 URLs (800 benign, 800 phishing) spanning 1,200 unique registered domains (`registered_domain`) with challenging hard-negative benign URLs and stealth phishing cases.
- `raw/sms_dataset.csv`: 1,200 SMS records (600 benign/transactional OTP, 600 scam/spam) modeled on the UCI SMS Spam Collection and modern Indian/global financial fraud vectors (KYC, PAN, UPI, customs, electricity bill, lottery lures).
- `raw/network_flows_dataset.csv`: 1,500 network flow records (750 benign, 750 intrusion/anomaly) across 16 flow-level telemetry features modeled on CICIDS2017 / UNSW-NB15 / NSL-KDD schemas.
- `processed/sample_network_traffic.pcap`: Reference 126-packet Scapy capture containing benign HTTPS/DNS flows and malicious SYN flood, SSH brute-force, and port-scan flows.
- `processed/dataset_manifest.json`: Reproducibility manifest (`RANDOM_SEED = 42`).
- `processed/detection_history.json`: Local audit log of inspected inputs.

## Regenerating All Datasets

```bash
python scripts/download_datasets.py
```

For full documentation of sources, licenses, preprocessing, splitting strategies, and limitations, see [`docs/DATASETS.md`](../docs/DATASETS.md).
