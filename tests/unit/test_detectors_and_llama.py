"""
Unit tests for SecureEdge AI covering:
- URL feature extraction & prediction
- SMS preprocessing & prediction
- Network flow extraction & Scapy PCAP parsing
- Threat aggregation & risk scoring
- Llama input validation & output schema parsing
- Edge cases (empty inputs, invalid URLs, very long messages, malformed data, missing models)
"""

from pathlib import Path
import unittest

from pydantic import ValidationError

from src.common.schemas import DetectorResult, LlamaExplanationInput, LlamaExplanationOutput
from src.llama.advisor import LlamaCyberAdvisor
from src.llama.tokenizer import CyberLlamaTokenizer
from src.network_detection.collector import ScapyFlowCollector
from src.network_detection.detector import NetworkAnomalyDetector
from src.network_detection.features import NetworkFlowFeatureExtractor
from src.sms_detection.detector import ScamSMSDetector
from src.sms_detection.features import SMSFeatureExtractor
from src.url_detection.detector import PhishingURLDetector
from src.url_detection.features import URLFeatureExtractor


class TestURLDetectionUnit(unittest.TestCase):
    """Unit tests for URL feature extraction, prediction, and edge cases."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = PhishingURLDetector()

    def test_url_feature_extraction_phishing_indicators(self) -> None:
        url = "http://198.51.100.44:8080/sbi/login-verify/account.exe?token=123"
        feats, evidence = URLFeatureExtractor.extract_features_and_evidence(url)
        self.assertEqual(feats["has_ip_address"], 1.0)
        self.assertEqual(feats["has_https"], 0.0)
        self.assertEqual(feats["has_non_standard_port"], 1.0)
        self.assertEqual(feats["has_executable_extension"], 1.0)
        self.assertGreaterEqual(feats["suspicious_keyword_count"], 2.0)
        self.assertTrue(any("IP address" in ev for ev in evidence))

    def test_url_registered_domain_extraction(self) -> None:
        self.assertEqual(
            URLFeatureExtractor.extract_registered_domain("https://portal.sbi.co.in/login"),
            "sbi.co.in",
        )
        self.assertEqual(
            URLFeatureExtractor.extract_registered_domain("https://docs.github.com/en"),
            "github.com",
        )

    def test_url_prediction_malicious_and_benign(self) -> None:
        phish_res = self.detector.predict(
            "http://paypal.secure-login.verify-update.auth-gateway-99.xyz/login/verify.php"
        )
        self.assertEqual(phish_res.source, "url")
        self.assertEqual(phish_res.classification, "malicious")
        self.assertEqual(phish_res.threat_type, "phishing")
        self.assertGreaterEqual(phish_res.risk_score, 60)

        benign_res = self.detector.predict("https://www.india.gov.in/citizens/services")
        self.assertEqual(benign_res.classification, "benign")
        self.assertEqual(benign_res.threat_type, "benign")
        self.assertLess(benign_res.risk_score, 35)

    def test_url_edge_cases_empty_and_malformed(self) -> None:
        empty_res = self.detector.predict("   ")
        self.assertEqual(empty_res.classification, "benign")
        self.assertEqual(empty_res.risk_score, 0)

        malformed_res = self.detector.predict("http://[::1:bad_ipv6/login")
        self.assertIn(malformed_res.classification, ("benign", "suspicious", "malicious"))

        missing_model_detector = PhishingURLDetector(model_path=Path("/nonexistent/model.joblib"))
        fallback_res = missing_model_detector.predict("http://198.51.100.5/paypal/login-verify")
        self.assertEqual(fallback_res.model_version, "heuristic-fallback-v1.0")
        self.assertFalse(fallback_res.is_calibrated)
        self.assertGreaterEqual(fallback_res.risk_score, 60)


class TestSMSDetectionUnit(unittest.TestCase):
    """Unit tests for SMS text cleaning, structural fraud extraction, and prediction."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = ScamSMSDetector()

    def test_sms_cleaning_meta_tokens(self) -> None:
        raw = "URGENT: Claim Rs. 5000 at http://scam-link.xyz or call +91 9876543210!"
        cleaned = SMSFeatureExtractor.clean_text(raw)
        self.assertIn("__url_token__", cleaned)
        self.assertIn("__currency_token__", cleaned)
        self.assertIn("__phone_token__", cleaned)

    def test_sms_prediction_scam_vs_legit_otp(self) -> None:
        scam_msg = (
            "URGENT: Your SBI bank account will be blocked today as your PAN & KYC is expired! "
            "Click http://sbi-kyc-update.xyz/login immediately to verify."
        )
        scam_res = self.detector.predict(scam_msg)
        self.assertEqual(scam_res.classification, "malicious")
        self.assertEqual(scam_res.threat_type, "scam")
        self.assertGreaterEqual(scam_res.risk_score, 60)

        otp_msg = "Your OTP for HDFC NetBanking login is 839201. Do not share this OTP with anyone."
        otp_res = self.detector.predict(otp_msg)
        self.assertEqual(otp_res.classification, "benign")
        self.assertLess(otp_res.risk_score, 35)

    def test_sms_edge_cases_empty_and_very_long(self) -> None:
        empty_res = self.detector.predict("")
        self.assertEqual(empty_res.risk_score, 0)
        self.assertEqual(empty_res.classification, "benign")

        very_long_msg = ("Hello team, here are the meeting notes from today's lecture. " * 250)
        long_res = self.detector.predict(very_long_msg)
        self.assertEqual(long_res.classification, "benign")


class TestNetworkDetectionUnit(unittest.TestCase):
    """Unit tests for Scapy flow extraction, anomaly classification, and malformed flow handling."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.detector = NetworkAnomalyDetector()

    def test_scapy_pcap_flow_extraction(self) -> None:
        flows = ScapyFlowCollector.load_flows_from_pcap()
        self.assertGreaterEqual(len(flows), 4)
        for fl in flows:
            self.assertIn("dst_port", fl)
            self.assertIn("packets_per_sec", fl)
            self.assertIn("syn_flag_ratio", fl)

    def test_network_syn_flood_and_benign_https(self) -> None:
        syn_flood = {
            "src_ip": "10.0.0.99",
            "dst_ip": "192.168.1.10",
            "dst_port": 80,
            "protocol_id": 6,
            "flow_duration_sec": 0.15,
            "packet_count": 200,
            "byte_count": 10800,
            "packets_per_sec": 1333.3,
            "bytes_per_sec": 72000.0,
            "syn_flag_ratio": 0.96,
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": 0.04,
            "fin_flag_ratio": 0.0,
            "unique_dst_ports_window": 2,
            "connection_frequency": 90,
            "payload_byte_ratio": 0.0,
        }
        res_mal = self.detector.predict(syn_flood)
        self.assertEqual(res_mal.classification, "malicious")
        self.assertEqual(res_mal.threat_type, "network_anomaly")
        self.assertGreaterEqual(res_mal.risk_score, 60)

        benign_https = {
            "src_ip": "192.168.1.10",
            "dst_ip": "142.250.190.46",
            "dst_port": 443,
            "protocol_id": 6,
            "flow_duration_sec": 4.5,
            "packet_count": 32,
            "byte_count": 24000,
            "packets_per_sec": 7.1,
            "bytes_per_sec": 5333.3,
            "syn_flag_ratio": 0.03,
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": 0.94,
            "fin_flag_ratio": 0.03,
            "unique_dst_ports_window": 1,
            "connection_frequency": 1,
            "payload_byte_ratio": 0.82,
        }
        res_ben = self.detector.predict(benign_https)
        self.assertEqual(res_ben.classification, "benign")

    def test_network_empty_flow_handling(self) -> None:
        res_empty = self.detector.predict({})
        self.assertEqual(res_empty.classification, "benign")
        self.assertEqual(res_empty.risk_score, 0)


class TestLlamaExecuTorchUnit(unittest.TestCase):
    """Unit tests for CyberLlamaTokenizer, LlamaExplanationInput/Output schemas, and .pte runtime."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tokenizer = CyberLlamaTokenizer()
        cls.advisor = LlamaCyberAdvisor()

    def test_tokenizer_encode_decode_roundtrip(self) -> None:
        text = "phishing url structure credential verify password"
        ids = self.tokenizer.encode(text, add_bos=True, add_eos=True)
        self.assertEqual(ids[0], self.tokenizer.bos_token_id)
        self.assertEqual(ids[-1], self.tokenizer.eos_token_id)
        decoded = self.tokenizer.decode(ids, skip_special_tokens=True)
        self.assertEqual(decoded, text)

    def test_llama_input_validation_and_output_grounding(self) -> None:
        inp = LlamaExplanationInput(
            threat_type="phishing",
            risk_level="high",
            confidence=0.94,
            evidence=["Suspicious URL structure", "Credential-related path"],
        )
        out = self.advisor.explain(inp)
        self.assertIsInstance(out, LlamaExplanationOutput)
        self.assertEqual(out.risk_level, "high")
        self.assertTrue(out.pte_artifact_verified)
        self.assertIn("Suspicious URL structure", out.explanation)

        # Invalid confidence (> 1.0) must raise ValidationError
        with self.assertRaises(ValidationError):
            LlamaExplanationInput(
                threat_type="phishing",
                risk_level="high",
                confidence=1.5,
                evidence=["Invalid confidence"],
            )


if __name__ == "__main__":
    unittest.main()
