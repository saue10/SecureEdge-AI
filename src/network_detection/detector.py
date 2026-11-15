"""Network Anomaly Detector inference pipeline."""

import time
from pathlib import Path
from typing import Any, Dict, Optional
import joblib
import numpy as np

from src.common.config import NETWORK_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import DetectorResult
from src.network_detection.features import NetworkFlowFeatureExtractor

logger = get_logger("SecureEdge.NetworkDetector")


class NetworkAnomalyDetector:
    """On-device Network Flow Anomaly & Intrusion Detector."""

    DEFAULT_MODEL_PATH = NETWORK_MODEL_DIR / "network_detector_pipeline.joblib"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.pipeline: Any = None
        self.isolation_forest: Any = None
        self.model_version: str = "net-rf-isoforest-v1.0"
        self.is_calibrated: bool = True
        self.metadata: Dict[str, Any] = {}
        self._load_model_if_exists()

    def _load_model_if_exists(self) -> bool:
        """Load trained network anomaly classifier bundle if present on disk."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.pipeline = bundle.get("pipeline")
                self.isolation_forest = bundle.get("isolation_forest")
                self.model_version = bundle.get("model_version", self.model_version)
                self.is_calibrated = bundle.get("is_calibrated", True)
                self.metadata = bundle.get("metadata", {})
                logger.info("Loaded Network detector model (%s) from %s", self.model_version, self.model_path)
                return True
            except Exception as exc:
                logger.error("Failed to load Network detector model from %s: %s", self.model_path, exc)
                self.pipeline = None
        return False

    def predict(self, flow: Dict[str, Any]) -> DetectorResult:
        """Analyze a network flow dictionary and return a standardized DetectorResult."""
        t0 = time.perf_counter()

        if not flow or not isinstance(flow, dict):
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return DetectorResult(
                source="network",
                threat_type="benign",
                classification="benign",
                confidence=1.0,
                risk_score=0,
                evidence=["Empty or invalid network flow record provided."],
                model_version=self.model_version,
                inference_latency_ms=round(latency_ms, 3),
                features={},
                raw_input_summary="<empty_flow>",
                is_calibrated=self.is_calibrated,
            )

        features_dict, evidence, subtype = NetworkFlowFeatureExtractor.extract_features_and_evidence(flow)
        feature_vec = np.array(
            [[features_dict[k] for k in NetworkFlowFeatureExtractor.feature_names]], dtype=np.float64
        )

        heuristic_score = self._compute_heuristic_risk(features_dict, subtype)

        if self.pipeline is not None:
            supervised_prob = float(self.pipeline.predict_proba(feature_vec)[0][1])
            iso_anomaly_boost = 0.0
            if self.isolation_forest is not None:
                # IsolationForest decision_function < 0 indicates out-of-distribution anomaly
                iso_score = float(self.isolation_forest.decision_function(feature_vec)[0])
                if iso_score < 0:
                    iso_anomaly_boost = min(0.25, abs(iso_score) * 0.5)
            blended_prob = min(1.0, 0.78 * supervised_prob + 0.22 * (heuristic_score / 100.0) + iso_anomaly_boost)
        else:
            blended_prob = heuristic_score / 100.0

        blended_prob = max(0.0, min(1.0, blended_prob))
        risk_score = int(round(blended_prob * 100))

        if risk_score >= 60:
            classification = "malicious"
            threat_type = "network_anomaly"
            confidence = blended_prob
        elif risk_score >= 35:
            classification = "suspicious"
            threat_type = "network_anomaly"
            confidence = blended_prob
        else:
            classification = "benign"
            threat_type = "benign"
            confidence = 1.0 - blended_prob

        src_ip = flow.get("src_ip", "0.0.0.0")
        dst_ip = flow.get("dst_ip", "0.0.0.0")
        dst_port = int(features_dict["dst_port"])
        summary = f"{src_ip} -> {dst_ip}:{dst_port} (pkts={int(features_dict['packet_count'])}, subtype={subtype})"

        latency_ms = (time.perf_counter() - t0) * 1000.0
        return DetectorResult(
            source="network",
            threat_type=threat_type,
            classification=classification,
            confidence=round(float(confidence), 4),
            risk_score=risk_score,
            evidence=evidence,
            model_version=self.model_version if self.pipeline is not None else "net-heuristic-fallback-v1.0",
            inference_latency_ms=round(latency_ms, 3),
            features=features_dict,
            raw_input_summary=summary,
            is_calibrated=self.is_calibrated if self.pipeline is not None else False,
        )

    @staticmethod
    def _compute_heuristic_risk(f: Dict[str, float], subtype: str) -> float:
        """Compute deterministic flow anomaly risk score in [0, 100]."""
        score = 0.0
        if subtype == "syn_flood_dos":
            score += 85.0
        elif subtype == "port_scan":
            score += 80.0
        elif subtype == "c2_backdoor_channel":
            score += 88.0
        elif subtype == "brute_force_probe":
            score += 75.0
        elif subtype == "data_exfiltration_anomaly":
            score += 72.0
        elif subtype == "rejected_probe":
            score += 55.0

        if f["unique_dst_ports_window"] >= 10:
            score += min(30.0, f["unique_dst_ports_window"] * 1.5)
        if f["syn_flag_ratio"] >= 0.7 and f["ack_flag_ratio"] <= 0.2:
            score += 25.0
        if f["rst_flag_ratio"] >= 0.5:
            score += 20.0
        if f["is_sensitive_admin_port"] > 0 and f["connection_frequency"] >= 8:
            score += 25.0
        return min(100.0, score)
