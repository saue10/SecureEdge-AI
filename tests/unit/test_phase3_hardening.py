"""Phase 3 Regression & Hardening Test Suite (Priority 7)."""

import unittest
from typing import List, Optional, Tuple

import numpy as np

from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.hardened import HardenedSMSDetector, HardenedSMSPreprocessor
from src.threat_engine.calibrated_policy import CalibratedThreatEngine
from src.url_detection.hardened import HardenedURLDetector, SafeRedirectInspector


class _DowngradingMockAdvisor:
    """Mock LLM advisor that attempts to return low risk even for confirmed high-risk detections."""

    def explain(self, inp):
        class _Out:
            explanation = "Mock explanation."
            recommendation = "Mock recommendation."
            runtime_backend = "Mock-LLM"
        return _Out()


class TestPhase3Hardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Train lightweight in-memory instances on minimal clean samples so tests run fast & self-contained
        cls.sms = HardenedSMSDetector(model_path=None)
        cls.sms.classifier = None  # Force deterministic + feature path or fit tiny corpus
        train_sms = [
            "URGENT: Your SBI KYC is expired, click http://sbi-kyc.xyz to verify",
            "Congratulations! You won Rs 50000 lottery prize, call +91 9811223344",
            "Aapka HDFC khata band ho jayega turant verify karo http://hdfc-verify.top",
            "482910 is your OTP for login. Do not share this OTP with anyone.",
            "HDFC Bank: A/c XX4821 debited for Rs.500.00 via UPI. Avl Bal Rs.12000.00.",
            "Bhai kal subah 10 baje office milte hain.",
            "Your order #ORD1234 has been dispatched and will arrive tomorrow.",
        ] * 4
        train_sms_y = np.array([1, 1, 1, 0, 0, 0, 0] * 4)
        cls.sms.fit(train_sms, train_sms_y)

        cls.url = HardenedURLDetector(model_path=None)
        cls.url.classifier = None
        train_urls = [
            "http://paypal-login-verify.xyz/auth",
            "http://sbi-kyc-update.top/login",
            "https://www.paypal.com/in/home",
            "https://docs.python.org/3/library/urllib.html",
        ] * 5
        train_urls_y = np.array([1, 1, 0, 0] * 5)
        cls.url.fit(train_urls, train_urls_y)

        cls.net = ContextAwareNetworkDetector()
        benign_flow = {
            "src_ip": "192.168.1.15",
            "flow_duration_sec": 0.4,
            "packet_count": 30,
            "byte_count": 6000,
            "packets_per_sec": 75.0,
            "bytes_per_sec": 15000.0,
            "syn_flag_ratio": 0.15,
            "rst_flag_ratio": 0.05,
            "ack_flag_ratio": 0.75,
            "fin_flag_ratio": 0.10,
            "unique_dst_ports_window": 4,
            "connection_frequency": 10,
            "payload_byte_ratio": 0.60,
        }
        syn_flood = {
            "src_ip": "10.0.10.99",
            "flow_duration_sec": 0.3,
            "packet_count": 300,
            "byte_count": 16200,
            "packets_per_sec": 1000.0,
            "bytes_per_sec": 54000.0,
            "syn_flag_ratio": 0.92,
            "rst_flag_ratio": 0.03,
            "ack_flag_ratio": 0.05,
            "fin_flag_ratio": 0.0,
            "unique_dst_ports_window": 1,
            "connection_frequency": 150,
            "payload_byte_ratio": 0.01,
        }
        cls.net.fit([benign_flow] * 12 + [syn_flood] * 12, np.array([0] * 12 + [1] * 12))
        cls.engine = CalibratedThreatEngine(
            url_detector=cls.url,
            sms_detector=cls.sms,
            network_detector=cls.net,
            llama_advisor=_DowngradingMockAdvisor(),
        )

    def test_01_sms_unicode_and_zero_width_obfuscation(self) -> None:
        zw_msg = "U\u200bR\u200bG\u200bE\u200bN\u200bT: SBI k\u200by\u200bc expired! Cl\u200bick http://sbi-kyc.xyz"
        homo_msg = "FІNAL NОTІCE: Yоur Рaytm wаllet susреnded, vеrify kус at http://paytm-kyc.xyz"
        for msg in (zw_msg, homo_msg):
            res = self.sms.predict(msg)
            self.assertIn(res.classification, {"malicious", "suspicious"})
            self.assertGreaterEqual(res.risk_score, 55)

    def test_02_sms_leetspeak_spaced_and_repeated_chars(self) -> None:
        leet = "UR63NT SBI 4lert: P4N kyc upd4t3 r3quir3d or b4nk 4cc0unt bl0ck3d http://sbi-fix.top"
        spaced = "U R G E N T: Your HDFC k y c is e x p i r e d, b l o c k e d today http://hdfc-fix.xyz"
        repeated = "UUUURRRGGGEEENT!! SBI kkkkyyyyccc suspppenndedd!! Click http://sbi-kyc.icu"
        for msg in (leet, spaced, repeated):
            res = self.sms.predict(msg)
            self.assertIn(res.classification, {"malicious", "suspicious"})

    def test_03_sms_hinglish_scam_vs_benign_preservation(self) -> None:
        hinglish_scam = "Aapka SBI khata aaj raat band ho jayega, turant eKYC verify karo http://sbi-kyc.xyz"
        self.assertIn(self.sms.predict(hinglish_scam).classification, {"malicious", "suspicious"})

        legit_otp = "491820 is your OTP for HDFC login. Do not share this OTP with anyone."
        legit_bank = "HDFC Bank: A/c XX4821 debited for Rs.450.00 via UPI Ref 612301. Avl Bal Rs.15400.00."
        hinglish_personal = "Bhai kal subah 10 baje milte hain cafeteria mein, laptop le aana."
        for benign in (legit_otp, legit_bank, hinglish_personal):
            res = self.sms.predict(benign)
            self.assertEqual(res.classification, "benign", f"False positive on benign SMS: {benign}")

    def test_04_url_unicode_homograph_and_benign_idn(self) -> None:
        homograph = "https://раypal-security.com/account/login"
        res_bad = self.url.predict(homograph)
        self.assertEqual(res_bad.classification, "malicious")
        self.assertGreaterEqual(res_bad.features["confusable_char_count"], 1.0)

        benign_idn = "https://münchen.de/articles/guide-1?lang=en"
        res_ok = self.url.predict(benign_idn)
        self.assertEqual(res_ok.classification, "benign")

    def test_05_url_punycode_impersonation_vs_benign(self) -> None:
        bad_puny = "https://xn--pypal-4ve.com/verify/session"
        res_bad = self.url.predict(bad_puny)
        self.assertEqual(res_bad.classification, "malicious")

        benign_puny = "https://xn--mnchen-3ya.de/info"
        res_ok = self.url.predict(benign_puny)
        self.assertEqual(res_ok.classification, "benign")

    def test_06_url_shorteners_and_encoded_redirects(self) -> None:
        phish_short = "https://bit.ly/sbi-kyc-verify?redirect=https%3A%2F%2Fevil-login.xyz%2Fauth"
        res = self.url.predict(phish_short)
        self.assertIn(res.classification, {"malicious", "suspicious"})
        self.assertEqual(res.features["is_shortener"], 1.0)
        self.assertEqual(res.features["encoded_redirect_param"], 1.0)

        bare_short = "https://bit.ly/docs001"
        assess = self.engine.assess_url(bare_short, mode="fast_triage")
        self.assertEqual(assess.decision_state, "suspicious_unknown")

    def test_07_redirect_inspector_ssrf_safety(self) -> None:
        inspector = SafeRedirectInspector(
            resolver=lambda host: ["127.0.0.1"] if host == "rebind.test" else ["93.184.216.34"],
            requester=lambda url, timeout: (302, "http://169.254.169.254/latest/meta-data/"),
        )
        # Opt-in required by default
        disabled = inspector.inspect("https://example.com", allow_network=False)
        self.assertIsNotNone(disabled.error)

        # Blocks private/loopback/metadata/scheme SSRF
        self.assertFalse(inspector.validate_target("file:///etc/passwd")[0])
        self.assertFalse(inspector.validate_target("http://127.0.0.1:8080/admin")[0])
        self.assertFalse(inspector.validate_target("http://169.254.169.254/latest/meta-data/")[0])
        self.assertFalse(inspector.validate_target("http://rebind.test/")[0])

        # Blocks redirect hop targeting cloud metadata IP
        hop_report = inspector.inspect("https://example.com/start", allow_network=True)
        self.assertTrue(hop_report.ssrf_blocked)

    def test_08_network_benign_microservice_burst_not_malicious(self) -> None:
        burst_flow = {
            "src_ip": "192.168.1.15",
            "flow_duration_sec": 0.25,
            "packet_count": 45,
            "byte_count": 9500,
            "packets_per_sec": 180.0,
            "bytes_per_sec": 38000.0,
            "syn_flag_ratio": 0.16,
            "rst_flag_ratio": 0.05,
            "ack_flag_ratio": 0.72,
            "fin_flag_ratio": 0.12,
            "unique_dst_ports_window": 6,
            "connection_frequency": 16,
            "payload_byte_ratio": 0.62,
        }
        verdict = self.net.predict(burst_flow)
        self.assertNotEqual(verdict.state, "confirmed_malicious")
        self.assertEqual(verdict.state, "normal")

    def test_09_network_long_lived_ssh_normal(self) -> None:
        ssh_flow = {
            "src_ip": "192.168.1.102",
            "flow_duration_sec": 45.0,
            "packet_count": 120,
            "byte_count": 18000,
            "packets_per_sec": 2.67,
            "bytes_per_sec": 400.0,
            "syn_flag_ratio": 0.02,
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": 0.96,
            "fin_flag_ratio": 0.02,
            "unique_dst_ports_window": 1,
            "connection_frequency": 1,
            "payload_byte_ratio": 0.55,
        }
        verdict = self.net.predict(ssh_flow)
        self.assertEqual(verdict.state, "normal")

    def test_10_abstention_and_confidence_separation(self) -> None:
        empty_sms = self.engine.assess_sms("ok", mode="fast_triage")
        self.assertEqual(empty_sms.decision_state, "insufficient_evidence")
        self.assertTrue(empty_sms.abstained)

        bad_url = self.engine.assess_url("x", mode="fast_triage")
        self.assertEqual(bad_url.decision_state, "insufficient_evidence")
        self.assertTrue(bad_url.abstained)

        incomplete_flow = self.engine.assess_network_flow({"flow_duration_sec": 0.0, "packet_count": 0}, mode="fast_triage")
        self.assertEqual(incomplete_flow.decision_state, "insufficient_evidence")
        self.assertTrue(incomplete_flow.abstained)

        # Separate probability from anomaly_score
        valid_flow = self.engine.assess_network_flow(
            {
                "src_ip": "10.0.10.99",
                "flow_duration_sec": 0.3,
                "packet_count": 300,
                "byte_count": 16200,
                "syn_flag_ratio": 0.92,
                "ack_flag_ratio": 0.05,
                "rst_flag_ratio": 0.03,
                "unique_dst_ports_window": 1,
                "connection_frequency": 150,
                "payload_byte_ratio": 0.01,
            },
            mode="fast_triage",
        )
        self.assertIsNotNone(valid_flow.anomaly_score)
        self.assertEqual(valid_flow.decision_state, "confirmed_malicious")

    def test_11_fast_triage_zero_llm_and_deep_risk_guardrail(self) -> None:
        fast = self.engine.assess_url("https://раypal-security.com/login", mode="fast_triage")
        self.assertFalse(fast.llm_used)
        self.assertEqual(fast.llm_backend, "None (FAST TRIAGE)")
        self.assertIn(fast.risk_level, {"high", "critical"})

        deep = self.engine.assess_url("https://раypal-security.com/login", mode="deep_analysis")
        self.assertTrue(deep.llm_used)
        self.assertEqual(deep.risk_level, fast.risk_level)


if __name__ == "__main__":
    unittest.main()
