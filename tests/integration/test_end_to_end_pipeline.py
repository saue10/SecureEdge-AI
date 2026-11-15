"""
Integration tests for SecureEdge AI verifying:
1. URL -> Detector -> Unified Threat Engine -> Llama (.pte) -> Explanation
2. SMS -> Detector -> Unified Threat Engine -> Llama (.pte) -> Explanation
3. Network -> Scapy Collector -> Feature Extractor -> Detector -> Unified Threat Engine -> Llama (.pte) -> Explanation
4. Offline Mode & Web Dashboard API Endpoints (/, /api/status, /api/scan/url, /api/scan/sms, /api/scan/network, /api/explain, /api/benchmarks)
"""

import unittest

from app.main import app
from src.network_detection.collector import ScapyFlowCollector
from src.threat_engine.engine import UnifiedThreatEngine


class TestEndToEndPipelineIntegration(unittest.TestCase):
    """End-to-end integration tests across all 3 threat modalities, Llama ExecuTorch, and Web API."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = UnifiedThreatEngine()
        cls.client = app.test_client()

    def test_e2e_url_to_llama_pipeline(self) -> None:
        url = "http://hdfcbank.secure-login.verify-update.auth-gateway-101.xyz/kyc-update/confirm-otp.html"
        report = self.engine.analyze_url(url, explain=True, persist_history=False)

        self.assertEqual(report.detector_result.source, "url")
        self.assertEqual(report.detector_result.classification, "malicious")
        self.assertEqual(report.detector_result.threat_type, "phishing")
        self.assertEqual(report.llama_output.risk_level, report.detector_result.risk_level)
        self.assertTrue(report.llama_output.pte_artifact_verified)
        self.assertGreater(len(report.llama_output.explanation), 25)
        self.assertGreater(len(report.llama_output.recommendation), 25)

    def test_e2e_sms_to_llama_pipeline(self) -> None:
        sms = (
            "FINAL NOTICE: Income Tax refund of Rs. 45,000 is pending for your A/c XX4321. "
            "Verify bank PIN and credentials at http://incometax-refund-claim.top/verify"
        )
        report = self.engine.analyze_sms(sms, explain=True, persist_history=False)

        self.assertEqual(report.detector_result.source, "sms")
        self.assertEqual(report.detector_result.classification, "malicious")
        self.assertEqual(report.detector_result.threat_type, "scam")
        self.assertEqual(report.llama_output.risk_level, report.detector_result.risk_level)
        self.assertTrue(report.llama_output.pte_artifact_verified)

    def test_e2e_network_pcap_to_llama_pipeline(self) -> None:
        flows = ScapyFlowCollector.load_flows_from_pcap()
        self.assertGreaterEqual(len(flows), 4)

        # Flow 0 is benign HTTPS; Flow 2 is malicious SYN flood
        benign_rep = self.engine.analyze_network_flow(
            flows[0], explain=True, execution_mode="replay_demo", persist_history=False
        )
        self.assertEqual(benign_rep.detector_result.classification, "benign")

        mal_rep = self.engine.analyze_network_flow(
            flows[2], explain=True, execution_mode="replay_demo", persist_history=False
        )
        self.assertEqual(mal_rep.detector_result.classification, "malicious")
        self.assertEqual(mal_rep.detector_result.threat_type, "network_anomaly")
        self.assertEqual(mal_rep.execution_mode, "replay_demo")
        self.assertTrue(mal_rep.llama_output.pte_artifact_verified)

    def test_web_dashboard_and_rest_api_integration(self) -> None:
        # 1. Dashboard HTML root
        r_home = self.client.get("/")
        self.assertEqual(r_home.status_code, 200)
        self.assertIn(b"SECUREEDGE AI", r_home.data)

        # 2. System Status API
        r_status = self.client.get("/api/status")
        self.assertEqual(r_status.status_code, 200)
        status_json = r_status.get_json()
        self.assertTrue(status_json["system"]["models_status"]["llama_executorch"]["pte_verified"])

        # 3. URL Scan API
        r_url = self.client.post(
            "/api/scan/url",
            json={"url": "http://198.51.100.99:8080/sbi/login-verify/index.html", "explain": True},
        )
        self.assertEqual(r_url.status_code, 200)
        self.assertEqual(r_url.get_json()["detector_result"]["classification"], "malicious")

        # 4. SMS Scan API
        r_sms = self.client.post(
            "/api/scan/sms",
            json={"sms_text": "Your OTP for login is 123456. Do not share this OTP with anyone.", "explain": True},
        )
        self.assertEqual(r_sms.status_code, 200)
        self.assertEqual(r_sms.get_json()["detector_result"]["classification"], "benign")

        # 5. Network Replay API
        r_net = self.client.post("/api/scan/network", json={"mode": "replay_demo"})
        self.assertEqual(r_net.status_code, 200)
        self.assertEqual(r_net.get_json()["status"], "ok")
        self.assertGreaterEqual(len(r_net.get_json()["reports"]), 4)

        # 6. Direct Llama Explain API
        r_exp = self.client.post(
            "/api/explain",
            json={
                "threat_type": "phishing",
                "risk_level": "high",
                "confidence": 0.94,
                "evidence": ["Suspicious URL structure", "Credential-related path"],
            },
        )
        self.assertEqual(r_exp.status_code, 200)
        self.assertEqual(r_exp.get_json()["structured_output"]["risk_level"], "high")

        # 7. Benchmarks API
        r_bench = self.client.get("/api/benchmarks")
        self.assertEqual(r_bench.status_code, 200)
        self.assertIn("edge_benchmarks", r_bench.get_json())


if __name__ == "__main__":
    unittest.main()
