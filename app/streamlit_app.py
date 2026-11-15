"""
Streamlit entry point for SecureEdge AI (compatible when streamlit is installed).
Also see app/main.py for the zero-external-dependency Flask dashboard.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.network_detection.collector import ScapyFlowCollector
from src.threat_engine.engine import UnifiedThreatEngine


def run_streamlit_ui() -> None:
    import streamlit as st  # type: ignore

    st.set_page_config(page_title="SECUREEDGE AI", layout="wide")
    engine = UnifiedThreatEngine()

    st.title("🛡️ SECUREEDGE AI — On-Device Cybersecurity Assistant")
    st.caption("Your Security. Your Device. Your Privacy. | Bharat AI-SoC Challenge 2026–27 (PS3)")

    tabs = st.tabs(
        [
            "1. Dashboard",
            "2. URL Scanner",
            "3. SMS Detector",
            "4. Network Monitor",
            "5. AI Explanation",
            "6. History",
        ]
    )

    with tabs[0]:
        history = engine.get_history()
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Scans", len(history))
        c2.metric("Threats Flagged", sum(1 for r in history if r.get("classification") != "benign"))
        c3.metric("ExecuTorch .pte", "Verified" if engine.llama_advisor.runtime.verify_pte_artifact().get("verified") else "Missing")

    with tabs[1]:
        url = st.text_input("Inspect URL", "http://sbi.secure-login.verify-update.auth-gateway.xyz/kyc-update")
        if st.button("Scan URL"):
            st.json(engine.analyze_url(url).model_dump())

    with tabs[2]:
        sms = st.text_area("Inspect SMS", "URGENT: Your KYC is expired! Click http://kyc-update.xyz immediately.")
        if st.button("Scan SMS"):
            st.json(engine.analyze_sms(sms).model_dump())

    with tabs[3]:
        if st.button("Run Scapy PCAP Replay"):
            flows = ScapyFlowCollector.load_flows_from_pcap()
            for fl in flows:
                st.json(engine.analyze_network_flow(fl).model_dump())


if __name__ == "__main__":
    run_streamlit_ui()
