"""Phase 4 Productization, Correlation, Export & Security Test Suite (Task 9)."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from app.main import app, calibrated_engine, incident_engine
from src.threat_engine.incidents import IncidentCorrelationEngine, redact_sensitive_text


class _FailingAdvisor:
    def explain(self, _inp):
        raise RuntimeError("Simulated offline LLM unavailable")


class TestPhase4Productization(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = app.test_client()

    def test_01_incident_creation_and_defensible_correlation_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "incidents.json"
            corr = IncidentCorrelationEngine(storage_path=store)

            # 1. Scam SMS containing http://sbi-kyc-update99.xyz/verify
            inc1 = corr.record_observation(
                source="sms",
                raw_input="URGENT KYC http://sbi-kyc-update99.xyz/verify call +91 9811223344",
                assessment={
                    "decision_state": "confirmed_malicious",
                    "risk_level": "high",
                    "risk_score": 82,
                    "supervised_probability": 0.82,
                    "deduplicated_evidence": ["Embedded phishing URL"],
                    "recommendation": "Block immediately.",
                },
                detector_name="sms-hardened-v3",
            )

            # 2. Network flow to the EXACT same registered domain correlates into inc1
            inc2 = corr.record_observation(
                source="network",
                raw_input="192.168.1.33 -> 45.77.12.88",
                assessment={
                    "decision_state": "confirmed_malicious",
                    "risk_level": "critical",
                    "risk_score": 91,
                    "supervised_probability": 0.91,
                    "anomaly_score": -0.18,
                    "deduplicated_evidence": ["High outbound payload transfer"],
                    "recommendation": "Quarantine host.",
                },
                detector_name="network-context-aware-v3",
                flow={"src_ip": "192.168.1.33", "dst_ip": "45.77.12.88", "dst_domain": "sbi-kyc-update99.xyz"},
            )
            self.assertEqual(inc1.incident_id, inc2.incident_id)
            self.assertEqual(len(inc2.observations), 2)
            self.assertEqual(inc2.severity, "critical")
            self.assertEqual(inc2.correlated_entities[0]["relation_type"], "exact_registered_domain")

            # 3. Similar-looking but DIFFERENT domain must NOT correlate
            inc3 = corr.record_observation(
                source="url",
                raw_input="http://sbi-kyc-update98.xyz/verify",
                assessment={
                    "decision_state": "confirmed_malicious",
                    "risk_level": "high",
                    "risk_score": 80,
                    "supervised_probability": 0.80,
                    "deduplicated_evidence": ["Brand impersonation"],
                    "recommendation": "Block URL.",
                },
                detector_name="url-hardened-v3",
            )
            self.assertNotEqual(inc1.incident_id, inc3.incident_id)

    def test_02_sensitive_redaction_and_json_markdown_exports(self) -> None:
        sample = "482910 is your OTP. Call +91 9811223344. Visit https://evil.xyz/a?token=secret123 from 192.168.1.33"
        redacted = redact_sensitive_text(sample)
        self.assertNotIn("9811223344", redacted)
        self.assertNotIn("secret123", redacted)
        self.assertNotIn("192.168.1.33", redacted)
        self.assertIn("192.168.*.*", redacted)

        with tempfile.TemporaryDirectory() as tmp:
            corr = IncidentCorrelationEngine(storage_path=Path(tmp) / "inc.json")
            inc = corr.record_observation(
                source="sms",
                raw_input=sample,
                assessment={
                    "decision_state": "confirmed_malicious",
                    "risk_level": "high",
                    "risk_score": 85,
                    "supervised_probability": 0.85,
                    "deduplicated_evidence": ["Call +91 9811223344"],
                    "recommendation": "Do not respond.",
                },
                detector_name="sms-hardened-v3",
            )
            j_str = corr.export_json(inc.incident_id, redact=True)
            m_str = corr.export_markdown(inc.incident_id, redact=True)
            self.assertIsNotNone(j_str)
            self.assertIsNotNone(m_str)
            self.assertNotIn("9811223344", j_str)
            self.assertNotIn("9811223344", m_str)
            self.assertIn("Evaluation & Environment Limitations", m_str)

    def test_03_dashboard_navigation_and_security_headers(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        for section_id in [
            "tab-overview", "tab-url", "tab-sms", "tab-network", "tab-pcap",
            "tab-demo", "tab-incidents", "tab-incident-detail", "tab-benchmarks", "tab-system",
        ]:
            self.assertIn(section_id, html)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_04_pcap_upload_validation_and_limits(self) -> None:
        # Bad extension
        r_ext = self.client.post(
            "/api/v2/pcap/upload",
            data={"file": (io.BytesIO(b"\xd4\xc3\xb2\xa1test"), "malware.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r_ext.status_code, 400)

        # Bad magic bytes
        r_magic = self.client.post(
            "/api/v2/pcap/upload",
            data={"file": (io.BytesIO(b"NOT_A_PCAP_FILE"), "test.pcap")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r_magic.status_code, 400)

        # Oversized (> 2 MB)
        r_big = self.client.post(
            "/api/v2/pcap/upload",
            data={"file": (io.BytesIO(b"\xd4\xc3\xb2\xa1" + b"0" * (2 * 1024 * 1024 + 100)), "big.pcap")},
            content_type="multipart/form-data",
        )
        self.assertEqual(r_big.status_code, 413)

        # Bundled sample PCAP replay
        r_sample = self.client.post("/api/v2/pcap/sample", json={"mode": "fast_triage"})
        self.assertEqual(r_sample.status_code, 200)
        self.assertGreaterEqual(r_sample.get_json()["flow_count"], 1)

    def test_05_offline_demo_scenarios_and_input_limits(self) -> None:
        r_list = self.client.get("/api/v2/demo/scenarios")
        self.assertEqual(r_list.status_code, 200)
        scenarios = r_list.get_json()["scenarios"]
        self.assertGreaterEqual(len(scenarios), 10)
        self.assertTrue(all(s["synthetic_demo"] is True for s in scenarios))

        # Run a synthetic demo in default FAST TRIAGE
        r_run = self.client.post("/api/v2/demo/run", json={"scenario_id": "demo_03_idn_homograph"})
        self.assertEqual(r_run.status_code, 200)
        assess = r_run.get_json()["assessment"]
        self.assertEqual(assess["operating_mode"], "fast_triage")
        self.assertFalse(assess["llm_used"])
        self.assertEqual(assess["decision_state"], "confirmed_malicious")

        # Input length limit enforcement
        r_long = self.client.post("/api/v2/analyze/url", json={"url": "https://example.com/" + "a" * 2100})
        self.assertEqual(r_long.status_code, 400)

    def test_06_deep_analysis_llm_unavailable_fallback(self) -> None:
        orig = calibrated_engine._llama_advisor
        calibrated_engine._llama_advisor = _FailingAdvisor()
        try:
            r = self.client.post(
                "/api/v2/analyze/sms",
                json={"sms_text": "U R G E N T: SBI k y c expired http://sbi-kyc-update99.xyz", "mode": "deep_analysis"},
            )
            self.assertEqual(r.status_code, 200)
            assess = r.get_json()["assessment"]
            self.assertFalse(assess["llm_used"])
            self.assertIn("Fallback-Deterministic", assess["llm_backend"])
            self.assertEqual(assess["decision_state"], "confirmed_malicious")
        finally:
            calibrated_engine._llama_advisor = orig

    def test_07_v2_benchmarks_and_export_endpoints(self) -> None:
        r_b = self.client.get("/api/v2/benchmarks")
        self.assertEqual(r_b.status_code, 200)
        data = r_b.get_json()
        self.assertIn("Synthetic", data["metadata"]["dataset_provenance"])

        r_url = self.client.post("/api/v2/analyze/url", json={"url": "https://docs.python.org/3/library/urllib.html"})
        inc_id = r_url.get_json()["incident"]["incident_id"]
        r_exp = self.client.get(f"/api/v2/incidents/{inc_id}/export?format=markdown&redact=true")
        self.assertEqual(r_exp.status_code, 200)
        self.assertIn("attachment;", r_exp.headers.get("Content-Disposition", ""))

    def test_08_security_path_traversal_and_e2e_workflow(self) -> None:
        # Path traversal blocked
        r_trav = self.client.get("/api/figures/..%2F..%2FREADME.md")
        self.assertEqual(r_trav.status_code, 404)

        # Status endpoint works without forcing eager LLM load
        r_st = self.client.get("/api/status")
        self.assertEqual(r_st.status_code, 200)

        # E2E multi-stage correlation through Flask API + redacted JSON export
        r_sms = self.client.post(
            "/api/v2/analyze/sms",
            json={"sms_text": "URGENT KYC http://sbi-kyc-e2e77.xyz/verify call +91 9811223344"},
        )
        self.assertEqual(r_sms.status_code, 200)
        inc_id = r_sms.get_json()["incident"]["incident_id"]

        r_net = self.client.post(
            "/api/v2/analyze/network",
            json={
                "flow": {
                    "src_ip": "192.168.1.44",
                    "dst_ip": "45.77.12.88",
                    "dst_domain": "sbi-kyc-e2e77.xyz",
                    "flow_duration_sec": 4.5,
                    "packet_count": 650,
                    "byte_count": 845000,
                    "syn_flag_ratio": 0.01,
                    "ack_flag_ratio": 0.99,
                    "rst_flag_ratio": 0.0,
                    "unique_dst_ports_window": 1,
                    "connection_frequency": 3,
                    "payload_byte_ratio": 0.95,
                }
            },
        )
        self.assertEqual(r_net.status_code, 200)
        self.assertEqual(r_net.get_json()["incident"]["incident_id"], inc_id)

        r_json = self.client.get(f"/api/v2/incidents/{inc_id}/export?format=json&redact=true")
        self.assertEqual(r_json.status_code, 200)
        exported = json.loads(r_json.get_data(as_text=True))
        self.assertNotIn("9811223344", json.dumps(exported))
        self.assertGreaterEqual(len(exported["observations"]), 2)


if __name__ == "__main__":
    unittest.main()
