"""Lightweight ARM64 / Android Termux FAST TRIAGE Smoke Test & Latency Benchmark.

Runs without torch/transformers to verify physical ARM64 execution of:
- HardenedURLDetector
- HardenedSMSDetector
- ContextAwareNetworkDetector
- CalibratedThreatEngine (FAST TRIAGE)
- IncidentCorrelationEngine
Saves measured hardware & latency results to results/arm64_android_smoke_test.json.
"""

import json
import os
import platform
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.hardened import HardenedSMSDetector
from src.threat_engine.calibrated_policy import CalibratedThreatEngine
from src.url_detection.hardened import HardenedURLDetector


def main() -> None:
    net_path = PROJECT_ROOT / "models" / "network" / "network_context_aware.joblib"
    net_det = joblib.load(net_path) if net_path.exists() else ContextAwareNetworkDetector()

    engine = CalibratedThreatEngine(
        url_detector=HardenedURLDetector(PROJECT_ROOT / "models" / "url" / "url_hardened_pipeline.joblib"),
        sms_detector=HardenedSMSDetector(PROJECT_ROOT / "models" / "sms" / "sms_hardened_pipeline.joblib"),
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

    # Warmup
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
