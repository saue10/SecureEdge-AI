"""Lightweight ARM64 / Android Termux FAST TRIAGE Smoke Test & Latency Benchmark.

Runs without torch/transformers to verify physical ARM64 execution of:
- HardenedURLDetector
- HardenedSMSDetector
- ContextAwareNetworkDetector
- CalibratedThreatEngine (FAST TRIAGE)
If prebuilt .joblib artifacts were saved with a different scikit-learn version,
automatically retrains the 3 lightweight Phase 3 models locally from data/raw/*.csv.
Saves measured hardware & latency results to results/arm64_android_smoke_test.json.
"""

import csv
import json
import os
import platform
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import psutil
from sklearn.model_selection import GroupShuffleSplit, train_test_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.hardened import HardenedSMSDetector
from src.threat_engine.calibrated_policy import CalibratedThreatEngine
from src.url_detection.features import URLFeatureExtractor
from src.url_detection.hardened import HardenedURLDetector


def _retrain_phase3_models_locally() -> tuple[HardenedURLDetector, HardenedSMSDetector, ContextAwareNetworkDetector]:
    """Fit Phase 3 hardened models locally on the target Python/scikit-learn version."""
    print("[ARM64] Retraining lightweight Phase 3 models locally for current scikit-learn version...")

    # 1. SMS
    with open(PROJECT_ROOT / "data" / "raw" / "sms_dataset.csv", encoding="utf-8") as f:
        sms_rows = list(csv.DictReader(f))
    seen = set()
    dedup = []
    for r in sms_rows:
        norm = " ".join(r["text"].lower().split())
        if norm not in seen:
            seen.add(norm)
            dedup.append((r["text"], int(r["label"])))
    tr_x, va_x, tr_y, va_y = train_test_split(
        [x[0] for x in dedup], np.array([x[1] for x in dedup], dtype=int),
        test_size=0.20, stratify=np.array([x[1] for x in dedup], dtype=int), random_state=42,
    )
    sms_det = HardenedSMSDetector(model_path=PROJECT_ROOT / "models" / "sms" / "sms_hardened_pipeline.joblib")
    sms_det.fit(tr_x, tr_y, va_x, va_y, save_path=sms_det.model_path)

    # 2. URL
    with open(PROJECT_ROOT / "data" / "raw" / "url_dataset.csv", encoding="utf-8") as f:
        url_rows = list(csv.DictReader(f))
    urls = [r["url"] for r in url_rows]
    url_y = np.array([int(r["label"]) for r in url_rows], dtype=int)
    groups = np.array([URLFeatureExtractor.extract_registered_domain(u) for u in urls])
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    tr_i, va_i = next(gss.split(urls, url_y, groups))
    url_det = HardenedURLDetector(model_path=PROJECT_ROOT / "models" / "url" / "url_hardened_pipeline.joblib")
    url_det.fit([urls[i] for i in tr_i], url_y[tr_i], [urls[i] for i in va_i], url_y[va_i], save_path=url_det.model_path)

    # 3. Network
    with open(PROJECT_ROOT / "data" / "raw" / "network_flows_dataset.csv", encoding="utf-8") as f:
        net_rows = list(csv.DictReader(f))
    unseen = {"benign_ssh_session", "benign_microservice_burst", "data_exfiltration_anomaly", "stealth_low_slow_probe"}
    known = [r for r in net_rows if r["attack_type"] not in unseen]
    known_y = np.array([int(r["label"]) for r in known], dtype=int)
    ntr, nva = train_test_split(np.arange(len(known)), test_size=0.20, stratify=known_y, random_state=42)
    net_det = ContextAwareNetworkDetector()
    net_det.fit([known[i] for i in ntr], known_y[ntr], [known[i] for i in nva], known_y[nva])
    net_path = PROJECT_ROOT / "models" / "network" / "network_context_aware.joblib"
    net_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(net_det, net_path)
    print("[ARM64] Local Phase 3 models saved.")
    return url_det, sms_det, net_det


def main() -> None:
    net_path = PROJECT_ROOT / "models" / "network" / "network_context_aware.joblib"
    try:
        url_det = HardenedURLDetector(PROJECT_ROOT / "models" / "url" / "url_hardened_pipeline.joblib")
        sms_det = HardenedSMSDetector(PROJECT_ROOT / "models" / "sms" / "sms_hardened_pipeline.joblib")
        net_det = joblib.load(net_path)
        if url_det.classifier is None or sms_det.classifier is None or not getattr(net_det, "is_fitted", False):
            raise RuntimeError("Incompatible or missing local model bundle")
    except Exception as exc:
        print(f"[ARM64] Prebuilt pickle incompatible ({exc}); retraining locally...")
        url_det, sms_det, net_det = _retrain_phase3_models_locally()

    engine = CalibratedThreatEngine(
        url_detector=url_det,
        sms_detector=sms_det,
        network_detector=net_det,
        llama_advisor=None,
    )

    test_url = "https://раypal-security.com/account/login"
    test_sms = "Aapka SBI khata aaj raat band ho jayega, turant eKYC verify karo http://sbi-kyc-update99.xyz"
    test_burst = {
        "src_ip": "192.168.1.15",
        "dst_ip": "192.168.1.20",
        "flow_duration_sec": 0.30,
        "packet_count": 48,
        "byte_count": 10560,
        "packets_per_sec": 160.0,
        "bytes_per_sec": 35200.0,
        "syn_flag_ratio": 0.14,
        "rst_flag_ratio": 0.04,
        "ack_flag_ratio": 0.78,
        "fin_flag_ratio": 0.12,
        "unique_dst_ports_window": 5,
        "connection_frequency": 12,
        "payload_byte_ratio": 0.58,
    }

    url_res = engine.assess_url(test_url, mode="fast_triage")
    sms_res = engine.assess_sms(test_sms, mode="fast_triage")
    net_res = engine.assess_network_flow(test_burst, mode="fast_triage")

    url_lats, sms_lats, net_lats = [], [], []
    for _ in range(10):
        url_lats.append(engine.assess_url(test_url, mode="fast_triage").total_latency_ms)
        sms_lats.append(engine.assess_sms(test_sms, mode="fast_triage").total_latency_ms)
        net_lats.append(engine.assess_network_flow(test_burst, mode="fast_triage").total_latency_ms)

    vm = psutil.virtual_memory()
    proc = psutil.Process(os.getpid())
    arch = platform.machine()
    out = {
        "device": {
            "machine": arch,
            "is_arm64": arch.lower() in {"aarch64", "arm64"},
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "ram_total_gb": round(vm.total / (1024**3), 2),
            "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
        },
        "mode": "fast_triage (zero torch/LLM)",
        "verdicts": {
            "url_homograph": {"state": url_res.decision_state, "risk_score": url_res.risk_score},
            "sms_hinglish": {"state": sms_res.decision_state, "risk_score": sms_res.risk_score},
            "network_microservice_burst": {"state": net_res.decision_state, "risk_score": net_res.risk_score},
        },
        "latency_ms": {
            "url_p50": round(float(np.percentile(url_lats, 50)), 3),
            "url_p95": round(float(np.percentile(url_lats, 95)), 3),
            "sms_p50": round(float(np.percentile(sms_lats, 50)), 3),
            "sms_p95": round(float(np.percentile(sms_lats, 95)), 3),
            "net_p50": round(float(np.percentile(net_lats, 50)), 3),
            "net_p95": round(float(np.percentile(net_lats, 95)), 3),
        },
    }

    out_path = PROJECT_ROOT / "results" / "arm64_android_smoke_test.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
