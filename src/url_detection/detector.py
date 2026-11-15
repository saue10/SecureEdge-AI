"""Phishing URL Detector inference pipeline and model persistence."""

import time
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np

from src.common.config import URL_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import DetectorResult
from src.url_detection.features import URLFeatureExtractor

logger = get_logger("SecureEdge.URLDetector")


class PhishingURLDetector:
    """On-device Phishing URL Detector combining ML classification with forensic evidence rules."""

    DEFAULT_MODEL_PATH = URL_MODEL_DIR / "url_detector_pipeline.joblib"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.pipeline: Any = None
        self.model_version: str = "url-rf-calibrated-v1.0"
        self.is_calibrated: bool = True
        self.metadata: Dict[str, Any] = {}
        self._load_model_if_exists()

    def _load_model_if_exists(self) -> bool:
        """Load trained scikit-learn pipeline artifact if present on disk."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                if isinstance(bundle, dict) and "pipeline" in bundle:
                    self.pipeline = bundle["pipeline"]
                    self.model_version = bundle.get("model_version", self.model_version)
                    self.is_calibrated = bundle.get("is_calibrated", True)
                    self.metadata = bundle.get("metadata", {})
                else:
                    self.pipeline = bundle
                logger.info("Loaded URL detector model (%s) from %s", self.model_version, self.model_path)
                return True
            except Exception as exc:
                logger.error("Failed to load URL detector model from %s: %s", self.model_path, exc)
                self.pipeline = None
        return False

    def predict(self, raw_url: str) -> DetectorResult:
        """Analyze a URL and return a standardized DetectorResult."""
        t0 = time.perf_counter()

        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return DetectorResult(
                source="url",
                threat_type="benign",
                classification="benign",
                confidence=1.0,
                risk_score=0,
                evidence=["Empty or blank URL input provided; no threat indicators present."],
                model_version=self.model_version,
                inference_latency_ms=round(latency_ms, 3),
                features={},
                raw_input_summary="<empty>",
                is_calibrated=self.is_calibrated,
            )

        features_dict, evidence = URLFeatureExtractor.extract_features_and_evidence(raw_url)
        feature_vec = np.array([[features_dict[k] for k in URLFeatureExtractor.feature_names]], dtype=np.float64)

        # Heuristic structural risk baseline (ensures deterministic guardrail if model missing or borderline)
        heuristic_score = self._compute_structural_risk(features_dict)

        if self.pipeline is not None:
            probs = self.pipeline.predict_proba(feature_vec)[0]
            phish_prob = float(probs[1])
            # Combine calibrated ML probability with high-confidence structural indicators
            blended_prob = 0.82 * phish_prob + 0.18 * (heuristic_score / 100.0)
            if heuristic_score >= 70.0 and features_dict["trusted_tld"] == 0:
                blended_prob = max(blended_prob, heuristic_score / 100.0)
            # If trusted TLD (.gov.in, .edu, .ac.in) and no IP/at/brand impersonation, dampen false positives
            if (
                features_dict["trusted_tld"] > 0
                and features_dict["has_ip_address"] == 0
                and features_dict["num_Rule_at"] == 0
                and features_dict["brand_in_subdomain_or_path"] == 0
            ):
                blended_prob *= 0.35
        else:
            blended_prob = heuristic_score / 100.0

        blended_prob = max(0.0, min(1.0, blended_prob))
        risk_score = int(round(blended_prob * 100))

        if risk_score >= 60:
            classification = "malicious"
            threat_type = "phishing"
            confidence = blended_prob
        elif risk_score >= 35:
            classification = "suspicious"
            threat_type = "phishing"
            confidence = blended_prob
        else:
            classification = "benign"
            threat_type = "benign"
            confidence = 1.0 - blended_prob

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return DetectorResult(
            source="url",
            threat_type=threat_type,
            classification=classification,
            confidence=round(float(confidence), 4),
            risk_score=risk_score,
            evidence=evidence,
            model_version=self.model_version if self.pipeline is not None else "heuristic-fallback-v1.0",
            inference_latency_ms=round(latency_ms, 3),
            features=features_dict,
            raw_input_summary=raw_url.strip()[:120],
            is_calibrated=self.is_calibrated if self.pipeline is not None else False,
        )

    @staticmethod
    def _compute_structural_risk(f: Dict[str, float]) -> float:
        """Calculate deterministic structural risk points in [0, 100] from extracted lexical indicators."""
        score = 0.0
        if f["has_ip_address"] > 0:
            score += 45.0
        if f["brand_in_subdomain_or_path"] > 0:
            score += 35.0
        if f["num_Rule_at"] > 0:
            score += 30.0
        if f["has_punycode"] > 0:
            score += 30.0
        if f["suspicious_tld"] > 0:
            score += 22.0
        if f["has_executable_extension"] > 0:
            score += 35.0
        if f["num_hyphens"] >= 2:
            score += min(20.0, f["num_hyphens"] * 6.0)
        if f["subdomain_count"] >= 2:
            score += min(18.0, f["subdomain_count"] * 6.0)
        if f["suspicious_keyword_count"] >= 1:
            score += min(28.0, f["suspicious_keyword_count"] * 9.0)
        if f["has_non_standard_port"] > 0:
            score += 18.0
        if f["is_shortener"] > 0:
            score += 20.0
        if f["url_length"] > 85:
            score += 10.0
        if f["has_https"] == 0:
            score += 8.0
        if f["trusted_tld"] > 0 and f["has_ip_address"] == 0 and f["brand_in_subdomain_or_path"] == 0:
            score = max(0.0, score - 30.0)
        return min(100.0, score)
