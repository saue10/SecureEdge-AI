"""Unit tests for Phase 2 Adaptive Network Detector and Adaptive Threat Intelligence Engine."""

import sys
import unittest
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import RAW_DATA_DIR
from src.network_detection.adaptive import AdaptiveNetworkDetector
from src.threat_engine.adaptive_engine import AdaptiveThreatIntelligenceEngine


class TestAdaptiveThreatEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        df = pd.read_csv(RAW_DATA_DIR / "network_flows_dataset.csv").head(400)
        cls.adaptive = AdaptiveNetworkDetector(supervised_threshold=0.60, anomaly_threshold=0.0, random_state=42)
        cls.adaptive.fit(df.to_dict(orient="records"), df["label"].to_numpy())
        cls.engine = AdaptiveThreatIntelligenceEngine(adaptive_network=cls.adaptive)

    def test_insufficient_evidence_states(self) -> None:
        v = self.adaptive.predict({})
        self.assertEqual(v.state, "insufficient_evidence")
        rep_url = self.engine.assess_url("", mode="fast_triage")
        self.assertEqual(rep_url.decision_state, "insufficient_evidence")
        rep_sms = self.engine.assess_sms("   ", mode="fast_triage")
        self.assertEqual(rep_sms.decision_state, "insufficient_evidence")

    def test_fast_triage_runs_without_llm(self) -> None:
        rep = self.engine.assess_url("http://198.51.100.42:8080/sbi/login.php", mode="fast_triage")
        self.assertFalse(rep.llm_used)
        self.assertEqual(rep.operating_mode, "fast_triage")
        self.assertEqual(rep.decision_state, "confirmed_malicious")
        self.assertGreaterEqual(rep.risk_score, 60)

    def test_deep_analysis_graceful_fallback_when_llm_unavailable(self) -> None:
        class BrokenAdvisor:
            def explain(self, _inp):
                raise RuntimeError("Simulated offline LLM unavailable")

        broken_engine = AdaptiveThreatIntelligenceEngine(
            adaptive_network=self.adaptive,
            llama_advisor=BrokenAdvisor(),
        )
        rep = broken_engine.assess_url(
            "http://hdfcbank.secure-login.verify-update.auth-gateway-101.xyz/kyc-update/confirm-otp.html",
            mode="deep_analysis",
        )
        self.assertFalse(rep.llm_used)
        self.assertIn("Fallback-Deterministic", rep.llm_backend)
        self.assertEqual(rep.decision_state, "confirmed_malicious")

    def test_evidence_deduplication_and_probability_separation(self) -> None:
        deduped = self.engine._deduplicate_evidence(["High risk URL", "  high   risk url  ", "Raw IP host"])
        self.assertEqual(len(deduped), 2)

        flow = {
            "flow_duration_sec": 0.3,
            "packet_count": 400,
            "byte_count": 24000,
            "packets_per_sec": 1333.0,
            "bytes_per_sec": 80000.0,
            "syn_flag_ratio": 0.95,
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": 0.05,
            "fin_flag_ratio": 0.0,
            "unique_dst_ports_window": 2,
            "connection_frequency": 140,
            "payload_byte_ratio": 0.04,
        }
        rep = self.engine.assess_network_flow(flow, mode="fast_triage")
        self.assertIsNotNone(rep.anomaly_score)
        self.assertIn(rep.decision_state, ("confirmed_malicious", "suspicious_unknown"))


if __name__ == "__main__":
    unittest.main()
