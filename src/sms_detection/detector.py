"""Scam and Spam SMS Detector inference pipeline."""

import time
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

from src.common.config import SMS_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import DetectorResult
from src.sms_detection.features import SMSFeatureExtractor

logger = get_logger("SecureEdge.SMSDetector")


class ScamSMSDetector:
    """On-device SMS Scam & Spam Classifier combining TF-IDF n-grams and structural fraud features."""

    DEFAULT_MODEL_PATH = SMS_MODEL_DIR / "sms_detector_pipeline.joblib"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.word_vectorizer: Any = None
        self.char_vectorizer: Any = None
        self.scaler: Any = None
        self.classifier: Any = None
        self.model_version: str = "sms-hybrid-calibrated-v1.0"
        self.is_calibrated: bool = True
        self.metadata: Dict[str, Any] = {}
        self._load_model_if_exists()

    def _load_model_if_exists(self) -> bool:
        """Load trained TF-IDF + structural classifier bundle if present on disk."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.word_vectorizer = bundle["word_vectorizer"]
                self.char_vectorizer = bundle["char_vectorizer"]
                self.scaler = bundle["scaler"]
                self.classifier = bundle["classifier"]
                self.model_version = bundle.get("model_version", self.model_version)
                self.is_calibrated = bundle.get("is_calibrated", True)
                self.metadata = bundle.get("metadata", {})
                logger.info("Loaded SMS detector model (%s) from %s", self.model_version, self.model_path)
                return True
            except Exception as exc:
                logger.error("Failed to load SMS detector model from %s: %s", self.model_path, exc)
                self.classifier = None
        return False

    def predict(self, raw_text: str) -> DetectorResult:
        """Classify an SMS message and return a standardized DetectorResult."""
        t0 = time.perf_counter()

        if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return DetectorResult(
                source="sms",
                threat_type="benign",
                classification="benign",
                confidence=1.0,
                risk_score=0,
                evidence=["Empty or blank SMS input provided; no threat indicators present."],
                model_version=self.model_version,
                inference_latency_ms=round(latency_ms, 3),
                features={},
                raw_input_summary="<empty>",
                is_calibrated=self.is_calibrated,
            )

        struct_feats, evidence = SMSFeatureExtractor.extract_structural_features_and_evidence(raw_text)
        cleaned_text = SMSFeatureExtractor.clean_text(raw_text)
        heuristic_score = self._compute_heuristic_risk(struct_feats)

        if self.classifier is not None and self.word_vectorizer is not None:
            X_word = self.word_vectorizer.transform([cleaned_text])
            X_char = self.char_vectorizer.transform([cleaned_text])
            struct_vec = np.array(
                [[struct_feats[k] for k in SMSFeatureExtractor.structural_feature_names]],
                dtype=np.float64,
            )
            X_struct = csr_matrix(self.scaler.transform(struct_vec))
            X_combined = hstack([X_word, X_char, X_struct])
            ml_prob = float(self.classifier.predict_proba(X_combined)[0][1])
            blended_prob = 0.78 * ml_prob + 0.22 * (heuristic_score / 100.0)
            if struct_feats["is_otp_legit_pattern"] > 0 and struct_feats["has_url"] == 0:
                blended_prob *= 0.25
            if (
                struct_feats["has_url"] == 0
                and struct_feats["has_phone_number"] == 0
                and struct_feats["has_currency_amount"] == 0
                and struct_feats["financial_scam_match_count"] == 0
                and struct_feats["urgency_match_count"] == 0
            ):
                blended_prob = min(blended_prob, 0.20)
        else:
            blended_prob = heuristic_score / 100.0

        blended_prob = max(0.0, min(1.0, blended_prob))
        risk_score = int(round(blended_prob * 100))

        # Distinguish targeted financial/credential scam vs ordinary commercial spam vs benign
        is_financial_or_phish = (
            struct_feats["financial_scam_match_count"] >= 1
            or (struct_feats["has_url"] > 0 and struct_feats["credential_coercion_match_count"] >= 1)
            or (struct_feats["urgency_match_count"] >= 1 and struct_feats["credential_coercion_match_count"] >= 1)
        )

        if risk_score >= 60:
            classification = "malicious"
            threat_type = "scam" if is_financial_or_phish else "spam"
            confidence = blended_prob
        elif risk_score >= 35:
            classification = "suspicious"
            threat_type = "scam" if is_financial_or_phish else "spam"
            confidence = blended_prob
        else:
            classification = "benign"
            threat_type = "benign"
            confidence = 1.0 - blended_prob

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return DetectorResult(
            source="sms",
            threat_type=threat_type,
            classification=classification,
            confidence=round(float(confidence), 4),
            risk_score=risk_score,
            evidence=evidence,
            model_version=self.model_version if self.classifier is not None else "sms-heuristic-fallback-v1.0",
            inference_latency_ms=round(latency_ms, 3),
            features=struct_feats,
            raw_input_summary=raw_text.strip()[:120],
            is_calibrated=self.is_calibrated if self.classifier is not None else False,
        )

    @staticmethod
    def _compute_heuristic_risk(f: Dict[str, float]) -> float:
        """Compute deterministic structural scam risk score in [0, 100]."""
        if f["is_otp_legit_pattern"] > 0 and f["has_url"] == 0:
            return 5.0
        score = 0.0
        if f["has_url"] > 0:
            score += 28.0
        if f["urgency_match_count"] > 0:
            score += min(25.0, f["urgency_match_count"] * 14.0)
        if f["financial_scam_match_count"] > 0:
            score += min(32.0, f["financial_scam_match_count"] * 16.0)
        if f["credential_coercion_match_count"] > 0:
            score += min(20.0, f["credential_coercion_match_count"] * 10.0)
        if f["has_currency_amount"] > 0:
            score += 15.0
        if f["has_phone_number"] > 0 and (f["urgency_match_count"] > 0 or f["financial_scam_match_count"] > 0 or f["has_currency_amount"] > 0):
            score += 15.0
        if f["uppercase_ratio"] > 0.35 and f["char_length"] > 25:
            score += 10.0
        return min(100.0, score)
