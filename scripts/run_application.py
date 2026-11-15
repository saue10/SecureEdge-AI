"""
Unified Application Launcher for SecureEdge AI (Bharat AI-SoC Challenge PS3).
Supports:
- Web Dashboard Server mode: python scripts/run_application.py --host 127.0.0.1 --port 8501
- CLI Smoke-Test / Interactive Check mode: python scripts/run_application.py --cli-demo
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import run_server
from src.common.logger import get_logger
from src.network_detection.collector import ScapyFlowCollector
from src.threat_engine.engine import UnifiedThreatEngine

logger = get_logger("SecureEdge.Launcher")


def run_cli_demo() -> None:
    """Execute a complete offline CLI demonstration across URL, SMS, Network, and Llama ExecuTorch."""
    engine = UnifiedThreatEngine()
    print("=" * 80)
    print("SECUREEDGE AI — ON-DEVICE CYBERSECURITY ASSISTANT (OFFLINE CLI DEMO)")
    print("=" * 80)

    url_sample = "http://sbi.secure-login.verify-update.auth-gateway-99.xyz/kyc-update/confirm.html"
    url_rep = engine.analyze_url(url_sample, explain=True)
    print("\n[1] URL PHISHING DETECTOR + LLAMA EXECUTORCH:")
    print(json.dumps(url_rep.detector_result.to_spec_dict(), indent=2))
    print("Llama Output:", json.dumps(url_rep.llama_output.to_spec_dict(), indent=2))

    sms_sample = "URGENT: Your HDFC account will be blocked today as your PAN card & KYC is expired! Click http://hdfc-kyc-update.xyz/login immediately."
    sms_rep = engine.analyze_sms(sms_sample, explain=True)
    print("\n[2] SMS SCAM DETECTOR + LLAMA EXECUTORCH:")
    print(json.dumps(sms_rep.detector_result.to_spec_dict(), indent=2))
    print("Llama Output:", json.dumps(sms_rep.llama_output.to_spec_dict(), indent=2))

    flows = ScapyFlowCollector.load_flows_from_pcap()
    net_rep = engine.analyze_network_flow(flows[2], explain=True, execution_mode="replay_demo")
    print("\n[3] NETWORK ANOMALY DETECTOR (SCAPY PCAP REPLAY) + LLAMA EXECUTORCH:")
    print(json.dumps(net_rep.detector_result.to_spec_dict(), indent=2))
    print("Llama Output:", json.dumps(net_rep.llama_output.to_spec_dict(), indent=2))
    print("=" * 80)


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch SecureEdge AI Application")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8501, help="Bind port (default: 8501)")
    parser.add_argument("--cli-demo", action="store_true", help="Run full offline CLI demonstration and exit")
    args = parser.parse_args()

    if args.cli_demo:
        run_cli_demo()
    else:
        run_server(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
