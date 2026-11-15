"""
Adaptive Network Threat Detection (Phase 2 — Phase B).
Combines scale-invariant behavioral flow features with:
1. Supervised HistGradientBoostingClassifier (known attack patterns)
2. Unsupervised IsolationForest (novelty / unseen-scenario anomaly detection)
Outputs four explicit operational states:
- confirmed_malicious
- suspicious_unknown
- normal
- insufficient_evidence
Strictly separates supervised_prob from anomaly_score and avoids brittle port/protocol shortcuts.
"""

import math
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import RobustScaler

AdaptiveStateType = Literal[
    "confirmed_malicious",
    "suspicious_unknown",
    "normal",
    "insufficient_evidence",
]

ADAPTIVE_FEATURE_NAMES: List[str] = [
    "log_duration",
    "log_packets_per_sec",
    "log_bytes_per_sec",
    "bytes_per_packet",
    "syn_ack_imbalance",
    "rst_flag_ratio",
    "fin_flag_ratio",
    "log_unique_dst_ports",
    "log_connection_frequency",
    "payload_byte_ratio",
    "port_diversity_rate",
    "outbound_transfer_intensity",
]


@dataclass
class AdaptiveNetworkVerdict:
    state: AdaptiveStateType
    supervised_prob: float
    anomaly_score: float
    risk_score: int
    reasoning: List[str]
    evidence: List[str]
    latency_ms: float
    features: Dict[str, float]


class AdaptiveNetworkDetector:
    """Hybrid supervised + unsupervised adaptive network flow detector."""

    def __init__(
        self,
        supervised_threshold: float = 0.60,
        anomaly_threshold: float = 0.0,
        random_state: int = 42,
    ) -> None:
        self.supervised_threshold = supervised_threshold
        self.anomaly_threshold = anomaly_threshold
        self.random_state = random_state

        self.scaler = RobustScaler()
        self.supervised_model = HistGradientBoostingClassifier(
            max_iter=120,
            max_depth=6,
            random_state=random_state,
        )
        self.anomaly_model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=random_state,
        )
        self.is_fitted = False

    @staticmethod
    def extract_behavioral_features(flow: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, float], List[str]]:
        """Extract scale-invariant behavioral features and deduplicated forensic evidence."""
        dur = max(float(flow.get("flow_duration_sec", 0.0) or 0.0), 0.0)
        pkt_cnt = max(float(flow.get("packet_count", 0.0) or 0.0), 0.0)
        byte_cnt = max(float(flow.get("byte_count", 0.0) or 0.0), 0.0)
        pps = max(float(flow.get("packets_per_sec", pkt_cnt / max(dur, 0.01)) or 0.0), 0.0)
        bps = max(float(flow.get("bytes_per_sec", byte_cnt / max(dur, 0.01)) or 0.0), 0.0)
        syn_r = min(max(float(flow.get("syn_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        rst_r = min(max(float(flow.get("rst_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        ack_r = min(max(float(flow.get("ack_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        fin_r = min(max(float(flow.get("fin_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        uniq_ports = max(float(flow.get("unique_dst_ports_window", 1.0) or 1.0), 1.0)
        conn_freq = max(float(flow.get("connection_frequency", 1.0) or 1.0), 1.0)
        payload_r = min(max(float(flow.get("payload_byte_ratio", 0.0) or 0.0), 0.0), 1.0)

        bpp = byte_cnt / max(pkt_cnt, 1.0)
        syn_ack_imb = max(0.0, syn_r - ack_r)
        port_div_rate = uniq_ports / max(dur, 0.1)
        outbound_intensity = math.log1p(bps * payload_r)

        feat_dict = {
            "log_duration": math.log1p(dur),
            "log_packets_per_sec": math.log1p(pps),
            "log_bytes_per_sec": math.log1p(bps),
            "bytes_per_packet": bpp,
            "syn_ack_imbalance": syn_ack_imb,
            "rst_flag_ratio": rst_r,
            "fin_flag_ratio": fin_r,
            "log_unique_dst_ports": math.log1p(uniq_ports),
            "log_connection_frequency": math.log1p(conn_freq),
            "payload_byte_ratio": payload_r,
            "port_diversity_rate": port_div_rate,
            "outbound_transfer_intensity": outbound_intensity,
        }
        vec = np.array([feat_dict[k] for k in ADAPTIVE_FEATURE_NAMES], dtype=np.float32)

        # Deduplicated behavioral evidence (avoids double-counting correlated throughput fields)
        evidence: List[str] = []
        if syn_ack_imb >= 0.55 and conn_freq >= 20:
            evidence.append(
                f"Unacknowledged SYN flood/burst pattern (SYN-ACK imbalance={syn_ack_imb:.2f}, conn_freq={conn_freq:.0f})"
            )
        elif uniq_ports >= 5 and conn_freq >= 5:
            evidence.append(
                f"Multi-port scanning diversity ({uniq_ports:.0f} destination ports, rate={port_div_rate:.1f}/s)"
            )
        if bps >= 150000 and payload_r >= 0.75:
            evidence.append(
                f"High-volume outbound payload transfer ({bps/1024:.1f} KB/s, payload_ratio={payload_r:.2f})"
            )
        if rst_r >= 0.45:
            evidence.append(f"Elevated failed-connection RST ratio ({rst_r:.2f})")
        if dur >= 4.0 and pps <= 10.0 and (syn_r >= 0.15 or uniq_ports >= 3):
            evidence.append(
                f"Low-and-slow probing profile (duration={dur:.1f}s, {pps:.1f} pkt/s, {uniq_ports:.0f} ports)"
            )

        return vec, feat_dict, evidence

    def fit(self, flows: List[Dict[str, Any]], labels: np.ndarray) -> "AdaptiveNetworkDetector":
        """Fit supervised classifier on all training flows and IsolationForest strictly on benign flows."""
        X = np.array([self.extract_behavioral_features(f)[0] for f in flows], dtype=np.float32)
        y = np.asarray(labels, dtype=int)

        X_scaled = self.scaler.fit_transform(X)
        self.supervised_model.fit(X_scaled, y)

        benign_mask = y == 0
        if np.any(benign_mask):
            self.anomaly_model.fit(X_scaled[benign_mask])
        else:
            self.anomaly_model.fit(X_scaled)
        self.is_fitted = True
        return self

    def predict(self, flow: Optional[Dict[str, Any]]) -> AdaptiveNetworkVerdict:
        t0 = time.perf_counter()
        if not flow or float(flow.get("packet_count", 0) or 0) <= 0:
            return AdaptiveNetworkVerdict(
                state="insufficient_evidence",
                supervised_prob=0.0,
                anomaly_score=0.0,
                risk_score=0,
                reasoning=["Flow record is empty or contains zero packets; insufficient telemetry for classification."],
                evidence=["Insufficient packet telemetry (packet_count=0)"],
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                features={},
            )

        vec, feat_dict, evidence = self.extract_behavioral_features(flow)
        if not self.is_fitted:
            raise RuntimeError("AdaptiveNetworkDetector must be fitted before calling predict().")

        X_s = self.scaler.transform(vec.reshape(1, -1))
        sup_prob = float(self.supervised_model.predict_proba(X_s)[0, 1])
        # Negate sklearn decision_function so higher => more anomalous (> 0 means outlier)
        anom_score = float(-self.anomaly_model.decision_function(X_s)[0])

        reasoning: List[str] = []
        if sup_prob >= self.supervised_threshold:
            state: AdaptiveStateType = "confirmed_malicious"
            risk_score = int(round(min(100.0, max(65.0, sup_prob * 100.0))))
            reasoning.append(
                f"Supervised classifier confidence ({sup_prob:.3f} >= {self.supervised_threshold:.2f}) matches known intrusion signature."
            )
        elif anom_score > self.anomaly_threshold or sup_prob >= 0.40:
            state = "suspicious_unknown"
            # Bounded suspicious score in [40, 74] — never forced into confirmed malicious
            anom_contrib = min(1.0, max(0.0, anom_score * 2.5 + 0.45))
            risk_score = int(round(min(74.0, max(40.0, max(sup_prob, anom_contrib) * 70.0))))
            reasoning.append(
                f"Supervised probability is below confirmed threshold ({sup_prob:.3f}), "
                f"but IsolationForest anomaly score ({anom_score:.3f} > {self.anomaly_threshold:.2f}) indicates unusual/unseen flow behavior."
            )
        else:
            state = "normal"
            risk_score = int(round(min(30.0, sup_prob * 100.0)))
            reasoning.append(
                f"Both supervised probability ({sup_prob:.3f}) and anomaly score ({anom_score:.3f}) remain within normal baseline bounds."
            )

        if not evidence:
            evidence.append(
                "No high-risk behavioral heuristics triggered; flow falls within normal baseline or subtle statistical deviation"
                if state != "normal"
                else "Normal baseline flow telemetry observed"
            )

        return AdaptiveNetworkVerdict(
            state=state,
            supervised_prob=round(sup_prob, 4),
            anomaly_score=round(anom_score, 4),
            risk_score=risk_score,
            reasoning=reasoning,
            evidence=evidence,
            latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            features=feat_dict,
        )
