"""Context-Aware Network False-Positive Reduction & Baseline Modeling (Phase 3 — Priority 3).

Implements:
- Per-host and global robust baselines (Median & Median Absolute Deviation)
- Burst-vs-sustained and interactive-session differentiation
- Multi-signal anomaly confirmation (anomaly score alone never confirms malicious)
- Confidence-aware abstention for incomplete or ambiguous telemetry
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import RobustScaler

from src.network_detection.adaptive import ADAPTIVE_FEATURE_NAMES, AdaptiveNetworkDetector, AdaptiveStateType

CONTEXT_EXTRA_FEATURES: List[str] = [
    "ack_flag_ratio",
    "burst_benign_balance",
    "sustained_exfil_score",
    "stealth_probe_score",
    "host_robust_z_max",
]

CONTEXT_FEATURE_NAMES: List[str] = ADAPTIVE_FEATURE_NAMES + CONTEXT_EXTRA_FEATURES

BASELINE_DIMS: List[str] = [
    "log_packets_per_sec",
    "log_bytes_per_sec",
    "bytes_per_packet",
    "log_connection_frequency",
    "log_unique_dst_ports",
    "payload_byte_ratio",
    "ack_flag_ratio",
]


@dataclass
class ContextNetworkVerdict:
    state: AdaptiveStateType
    supervised_prob: float
    anomaly_score: float
    host_robust_z: float
    risk_score: int
    reasoning: List[str]
    evidence: List[str]
    latency_ms: float
    features: Dict[str, float]


class HostBehaviorBaseline:
    """Per-host and global robust behavioral baseline using Median and MAD."""

    def __init__(self, min_host_samples: int = 5) -> None:
        self.min_host_samples = min_host_samples
        self.global_stats: Dict[str, Tuple[float, float]] = {}
        self.host_stats: Dict[str, Dict[str, Tuple[float, float]]] = {}

    @staticmethod
    def _median_mad(values: np.ndarray) -> Tuple[float, float]:
        med = float(np.median(values))
        mad = float(np.median(np.abs(values - med))) * 1.4826
        return med, max(mad, 0.15)

    def fit(self, flows: List[Dict[str, Any]], feat_dicts: List[Dict[str, float]]) -> "HostBehaviorBaseline":
        """Fit global and per-source-IP robust baselines from benign flows."""
        global_vecs: Dict[str, List[float]] = defaultdict(list)
        host_vecs: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))

        for flow, fd in zip(flows, feat_dicts):
            src_ip = str(flow.get("src_ip", "") or "").strip()
            for dim in BASELINE_DIMS:
                val = float(fd[dim])
                global_vecs[dim].append(val)
                if src_ip:
                    host_vecs[src_ip][dim].append(val)

        for dim, vals in global_vecs.items():
            self.global_stats[dim] = self._median_mad(np.array(vals, dtype=np.float64))

        for ip, dims_map in host_vecs.items():
            if len(dims_map[BASELINE_DIMS[0]]) >= self.min_host_samples:
                self.host_stats[ip] = {
                    dim: self._median_mad(np.array(vals, dtype=np.float64))
                    for dim, vals in dims_map.items()
                }
        return self

    def compute_robust_z(self, src_ip: str, feat_dict: Dict[str, float]) -> Tuple[float, str]:
        """Compute max robust MAD z-score against host baseline (if known) or global baseline."""
        stats = self.host_stats.get(src_ip.strip(), self.global_stats)
        scope = "host" if src_ip.strip() in self.host_stats else "global"
        if not stats:
            return 0.0, "none"
        z_scores = []
        for dim, (med, mad) in stats.items():
            val = float(feat_dict.get(dim, med))
            z_scores.append(abs(val - med) / mad)
        return float(max(z_scores)) if z_scores else 0.0, scope


class ContextAwareNetworkDetector:
    """False-positive-reduced network flow detector with host MAD baselines & multi-signal confirmation."""

    def __init__(
        self,
        confirmed_threshold: float = 0.68,
        suspicious_threshold: float = 0.42,
        anomaly_threshold: float = -0.05,
        random_state: int = 42,
    ) -> None:
        self.confirmed_threshold = confirmed_threshold
        self.suspicious_threshold = suspicious_threshold
        self.anomaly_threshold = anomaly_threshold
        self.random_state = random_state

        self.baseline = HostBehaviorBaseline()
        self.scaler = RobustScaler()
        self.supervised_model: Any = HistGradientBoostingClassifier(
            max_iter=120,
            max_depth=5,
            learning_rate=0.08,
            random_state=random_state,
        )
        self.anomaly_model = IsolationForest(
            n_estimators=150,
            contamination=0.03,
            random_state=random_state,
        )
        self.is_fitted = False
        self.is_calibrated = False

    @staticmethod
    def _extract_raw_signals(flow: Dict[str, Any]) -> Tuple[Dict[str, float], List[str], Dict[str, bool]]:
        """Extract behavioral features, deduplicated evidence, and attack-specific signal flags."""
        _, base_dict, base_ev = AdaptiveNetworkDetector.extract_behavioral_features(flow)

        dur = max(float(flow.get("flow_duration_sec", 0.0) or 0.0), 0.0)
        pkt_cnt = max(float(flow.get("packet_count", 0.0) or 0.0), 0.0)
        byte_cnt = max(float(flow.get("byte_count", 0.0) or 0.0), 0.0)
        pps = max(float(flow.get("packets_per_sec", pkt_cnt / max(dur, 0.01)) or 0.0), 0.0)
        bps = max(float(flow.get("bytes_per_sec", byte_cnt / max(dur, 0.01)) or 0.0), 0.0)
        syn_r = min(max(float(flow.get("syn_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        rst_r = min(max(float(flow.get("rst_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        ack_r = min(max(float(flow.get("ack_flag_ratio", 0.0) or 0.0), 0.0), 1.0)
        uniq_ports = max(float(flow.get("unique_dst_ports_window", 1.0) or 1.0), 1.0)
        conn_freq = max(float(flow.get("connection_frequency", 1.0) or 1.0), 1.0)
        payload_r = min(max(float(flow.get("payload_byte_ratio", 0.0) or 0.0), 0.0), 1.0)
        bpp = byte_cnt / max(pkt_cnt, 1.0)
        syn_ack_imb = base_dict["syn_ack_imbalance"]

        # Bidirectional flow health: high when ACK ratio is healthy and SYN-ACK imbalance / RST are low
        burst_benign_balance = ack_r * (1.0 - syn_ack_imb) * (1.0 - rst_r)

        # Sustained one-way bulk exfiltration score (high payload ratio + large BPP + high BPS, distinct from small-packet RPC bursts)
        sustained_exfil_score = 0.0
        if payload_r >= 0.85 and bps >= 60000.0 and bpp >= 650.0 and ack_r >= 0.85:
            sustained_exfil_score = min(1.0, (payload_r - 0.80) * 5.0 * min(1.0, bpp / 1000.0))

        # Low-and-slow multi-port stealth probe score (excludes single-port SSH sessions)
        stealth_probe_score = 0.0
        if dur >= 3.0 and pps <= 15.0 and uniq_ports >= 3 and (syn_r >= 0.12 or rst_r >= 0.10):
            stealth_probe_score = min(1.0, (uniq_ports / 8.0) * 0.6 + (syn_r + rst_r) * 0.6)

        feat_dict = {
            **base_dict,
            "ack_flag_ratio": ack_r,
            "burst_benign_balance": round(burst_benign_balance, 4),
            "sustained_exfil_score": round(sustained_exfil_score, 4),
            "stealth_probe_score": round(stealth_probe_score, 4),
            "host_robust_z_max": 0.0,
        }

        signals = {
            "syn_flood": (syn_ack_imb >= 0.50 and conn_freq >= 15.0 and ack_r < 0.25),
            "port_scan": (uniq_ports >= 15.0 and (syn_ack_imb >= 0.30 or rst_r >= 0.35)),
            "high_rst_abuse": (rst_r >= 0.45 and ack_r < 0.45),
            "sustained_exfil": (sustained_exfil_score >= 0.45),
            "stealth_probe": (stealth_probe_score >= 0.35),
            "benign_burst_profile": (
                pps >= 20.0
                and conn_freq >= 2.0
                and ack_r >= 0.35
                and syn_ack_imb < 0.25
                and rst_r < 0.35
                and uniq_ports < 20.0
                and sustained_exfil_score < 0.45
            ),
            "benign_interactive_session": (
                dur >= 10.0
                and uniq_ports <= 2.0
                and syn_r < 0.10
                and ack_r >= 0.80
                and rst_r < 0.10
                and sustained_exfil_score < 0.45
            ),
        }

        return feat_dict, base_ev, signals

    def fit(
        self,
        train_flows: List[Dict[str, Any]],
        train_labels: np.ndarray,
        val_flows: Optional[List[Dict[str, Any]]] = None,
        val_labels: Optional[np.ndarray] = None,
    ) -> "ContextAwareNetworkDetector":
        """Fit per-host/global benign baselines, IsolationForest on benign flows, and calibrated classifier."""
        y_train = np.asarray(train_labels, dtype=int)
        raw_dicts = [self._extract_raw_signals(f)[0] for f in train_flows]

        # Fit host & global baselines strictly on benign training flows
        benign_flows = [f for f, lbl in zip(train_flows, y_train) if lbl == 0]
        benign_dicts = [d for d, lbl in zip(raw_dicts, y_train) if lbl == 0]
        self.baseline.fit(benign_flows, benign_dicts)

        for f, d in zip(train_flows, raw_dicts):
            z_max, _ = self.baseline.compute_robust_z(str(f.get("src_ip", "") or ""), d)
            d["host_robust_z_max"] = round(z_max, 4)

        X_train = np.array([[d[k] for k in CONTEXT_FEATURE_NAMES] for d in raw_dicts], dtype=np.float64)
        X_train_scaled = self.scaler.fit_transform(X_train)

        base_clf = HistGradientBoostingClassifier(
            max_iter=120,
            max_depth=5,
            learning_rate=0.08,
            random_state=self.random_state,
        )
        base_clf.fit(X_train_scaled, y_train)

        if val_flows is not None and val_labels is not None and len(val_flows) >= 20:
            val_dicts = []
            for f in val_flows:
                d, _, _ = self._extract_raw_signals(f)
                z_max, _ = self.baseline.compute_robust_z(str(f.get("src_ip", "") or ""), d)
                d["host_robust_z_max"] = round(z_max, 4)
                val_dicts.append(d)
            X_val = np.array([[d[k] for k in CONTEXT_FEATURE_NAMES] for d in val_dicts], dtype=np.float64)
            X_val_scaled = self.scaler.transform(X_val)
            try:
                from sklearn.frozen import FrozenEstimator
                cal = CalibratedClassifierCV(FrozenEstimator(base_clf), method="sigmoid")
            except ImportError:
                cal = CalibratedClassifierCV(base_clf, cv="prefit", method="sigmoid")
            cal.fit(X_val_scaled, np.asarray(val_labels, dtype=int))
            self.supervised_model = cal
            self.is_calibrated = True
        else:
            self.supervised_model = base_clf
            self.is_calibrated = False

        X_benign = X_train_scaled[y_train == 0]
        if len(X_benign) > 0:
            self.anomaly_model.fit(X_benign)

        self.is_fitted = True
        return self

    def predict(self, flow: Dict[str, Any]) -> ContextNetworkVerdict:
        """Classify a flow with host MAD context, multi-signal confirmation, and abstention."""
        t0 = time.perf_counter()
        dur = float(flow.get("flow_duration_sec", 0.0) or 0.0)
        pkt_cnt = float(flow.get("packet_count", 0.0) or 0.0)

        if not flow or dur <= 0.0 or pkt_cnt <= 0.0:
            return ContextNetworkVerdict(
                state="insufficient_evidence",
                supervised_prob=0.0,
                anomaly_score=0.0,
                host_robust_z=0.0,
                risk_score=10,
                reasoning=["Incomplete flow telemetry (missing duration or packet count); abstaining safely."],
                evidence=["Incomplete flow telemetry"],
                latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                features={},
            )

        feat_dict, evidence, signals = self._extract_raw_signals(flow)
        src_ip = str(flow.get("src_ip", "") or "")
        z_max, z_scope = self.baseline.compute_robust_z(src_ip, feat_dict)
        feat_dict["host_robust_z_max"] = round(z_max, 4)

        vec = np.array([[feat_dict[k] for k in CONTEXT_FEATURE_NAMES]], dtype=np.float64)
        if self.is_fitted:
            X_scaled = self.scaler.transform(vec)
            sup_prob = float(self.supervised_model.predict_proba(X_scaled)[0][1])
            anom_score = float(self.anomaly_model.decision_function(X_scaled)[0])
        else:
            sup_prob = 0.0
            anom_score = 0.0

        attack_signal_count = sum(
            1
            for k in ("syn_flood", "port_scan", "high_rst_abuse", "sustained_exfil", "stealth_probe")
            if signals[k]
        )

        reasoning: List[str] = [
            f"Calibrated supervised malicious probability: {sup_prob:.3f} (threshold={self.confirmed_threshold:.2f}).",
            f"Unsupervised IsolationForest score: {anom_score:.3f}; {z_scope} MAD robust z-score: {z_max:.2f}.",
            f"Attack-specific corroborating signals: {attack_signal_count}.",
        ]

        # Multi-signal decision policy with explicit false-positive reduction guardrails
        if attack_signal_count >= 1 and sup_prob >= self.confirmed_threshold:
            state: AdaptiveStateType = "confirmed_malicious"
            risk_score = max(70, int(round(sup_prob * 100)))
            reasoning.append("Confirmed malicious: calibrated probability and attack-specific telemetry agree.")
        elif signals["sustained_exfil"] or signals["syn_flood"] or signals["port_scan"]:
            # High-confidence attack-specific telemetry even when flow rate differs from training distribution
            if sup_prob >= 0.45 or attack_signal_count >= 2:
                state = "confirmed_malicious"
                risk_score = max(72, int(round(max(sup_prob, 0.72) * 100)))
                reasoning.append("Confirmed malicious via multi-signal attack-specific telemetry.")
            else:
                state = "suspicious_unknown"
                risk_score = 52
                reasoning.append("Attack-specific signal observed without high supervised confidence -> suspicious_unknown.")
        elif signals["stealth_probe"] and (anom_score < self.anomaly_threshold or sup_prob >= 0.35):
            state = "suspicious_unknown"
            risk_score = max(48, int(round(max(sup_prob, 0.48) * 100)))
            reasoning.append("Low-and-slow multi-port probing indicator corroborated by anomaly/probability -> suspicious_unknown.")
        elif (signals["benign_burst_profile"] or signals["benign_interactive_session"]) and attack_signal_count == 0:
            # Critical FP-reduction guardrail: healthy bidirectional bursts or single-port interactive sessions
            # are never marked confirmed_malicious solely due to volume or out-of-distribution rate.
            if z_max >= 12.0 and anom_score < -0.15 and sup_prob >= 0.75:
                state = "insufficient_evidence"
                risk_score = 30
                reasoning.append(
                    "Extreme host baseline deviation on bidirectional flow without attack signatures -> abstaining (insufficient_evidence)."
                )
            else:
                state = "normal"
                risk_score = min(25, int(round(sup_prob * 30)))
                reasoning.append(
                    "Bidirectional handshake/ACK health intact and zero attack-specific signals -> normal."
                )
        elif sup_prob >= self.suspicious_threshold and attack_signal_count == 0:
            # Ambiguous probability without attack-specific corroboration -> abstain instead of false-positiving
            state = "insufficient_evidence"
            risk_score = int(round(sup_prob * 60))
            reasoning.append("Elevated probability without attack-specific behavioral corroboration -> insufficient_evidence.")
        elif anom_score < self.anomaly_threshold and z_max >= 4.0 and feat_dict["burst_benign_balance"] < 0.30:
            state = "suspicious_unknown"
            risk_score = 45
            reasoning.append("Out-of-distribution flow with degraded handshake balance -> suspicious_unknown.")
        else:
            state = "normal"
            risk_score = min(28, int(round(sup_prob * 40)))
            reasoning.append("Within normal behavioral bounds.")

        if not evidence:
            evidence = [f"Flow behavioral profile evaluated ({z_scope} MAD z={z_max:.2f}, ack_ratio={feat_dict['ack_flag_ratio']:.2f})"]

        return ContextNetworkVerdict(
            state=state,
            supervised_prob=round(sup_prob, 4),
            anomaly_score=round(anom_score, 4),
            host_robust_z=round(z_max, 4),
            risk_score=min(100, max(0, risk_score)),
            reasoning=reasoning,
            evidence=evidence,
            latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            features=feat_dict,
        )
