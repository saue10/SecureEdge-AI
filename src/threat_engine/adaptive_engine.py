"""
Unified Threat Intelligence Engine (Phase 2 — Phases D & E).
Provides explicit FAST TRIAGE (zero LLM dependency) and DEEP ANALYSIS modes,
separates supervised probability from unsupervised anomaly score, deduplicates
correlated indicators, and preserves detector-locked risk guardrails.
"""

import time
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from src.common.logger import get_logger
from src.common.schemas import DetectorResult, LlamaExplanationInput, RiskLevelType
from src.network_detection.adaptive import AdaptiveNetworkDetector, AdaptiveStateType
from src.sms_detection.detector import ScamSMSDetector
from src.url_detection.detector import PhishingURLDetector

logger = get_logger("SecureEdge.AdaptiveThreatEngine")

OperatingMode = Literal["fast_triage", "deep_analysis"]


class AdaptiveThreatAssessment(BaseModel):
    """Structured threat intelligence assessment with explicit policy reasoning."""

    source: Literal["url", "sms", "network"]
    operating_mode: OperatingMode
    decision_state: AdaptiveStateType
    risk_level: RiskLevelType
    risk_score: int = Field(..., ge=0, le=100)
    supervised_probability: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: Optional[float] = None
    calibrated_threshold: float
    deduplicated_evidence: List[str]
    policy_reasoning: List[str]
    explanation: str
    recommendation: str
    llm_used: bool = False
    llm_backend: str = "None (FAST TRIAGE)"
    total_latency_ms: float = 0.0


class AdaptiveThreatIntelligenceEngine:
    """
    Phase 2 Threat Intelligence Engine supporting FAST TRIAGE (no LLM) and DEEP ANALYSIS.
    """

    def __init__(
        self,
        url_detector: Optional[PhishingURLDetector] = None,
        sms_detector: Optional[ScamSMSDetector] = None,
        adaptive_network: Optional[AdaptiveNetworkDetector] = None,
        llama_advisor: Optional[Any] = None,
    ) -> None:
        self.url_detector = url_detector or PhishingURLDetector()
        self.sms_detector = sms_detector or ScamSMSDetector()
        self.adaptive_network = adaptive_network
        self._llama_advisor = llama_advisor

    @staticmethod
    def _deduplicate_evidence(items: List[str]) -> List[str]:
        """Remove exact and semantically redundant evidence strings without double-counting."""
        seen = set()
        out: List[str] = []
        for item in items:
            norm = " ".join(str(item).lower().split())
            if norm and norm not in seen:
                seen.add(norm)
                out.append(str(item).strip())
        return out[:6]

    @staticmethod
    def _risk_level_from_score(score: int) -> RiskLevelType:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        return "low"

    @staticmethod
    def _deterministic_advisory(source: str, state: AdaptiveStateType, evidence: List[str]) -> tuple[str, str]:
        ev_str = "; ".join(evidence[:3])
        if state == "insufficient_evidence":
            return (
                f"Insufficient {source} telemetry to classify safely ({ev_str}).",
                "Collect complete input/packet telemetry before permitting automated trust.",
            )
        if state == "confirmed_malicious":
            return (
                f"Confirmed malicious {source} threat detected. Verified indicators: {ev_str}.",
                "Block or quarantine immediately; do not open links, share OTPs/PINs, or permit outbound traffic.",
            )
        if state == "suspicious_unknown":
            return (
                f"Suspicious or previously unseen {source} behavior detected (requires review). Indicators: {ev_str}.",
                "Treat with caution, isolate or verify through an independent trusted channel before proceeding.",
            )
        return (
            f"No malicious {source} indicators triggered ({ev_str}).",
            "No immediate threat action required; continue standard security hygiene.",
        )

    def _run_llm_if_requested(
        self,
        mode: OperatingMode,
        source: str,
        state: AdaptiveStateType,
        risk_level: RiskLevelType,
        confidence: float,
        evidence: List[str],
    ) -> tuple[str, str, bool, str]:
        base_exp, base_rec = self._deterministic_advisory(source, state, evidence)
        if mode == "fast_triage":
            return base_exp, base_rec, False, "None (FAST TRIAGE)"

        try:
            if self._llama_advisor is None:
                from src.llama.advisor import LlamaCyberAdvisor

                self._llama_advisor = LlamaCyberAdvisor()

            threat_map = {"url": "phishing", "sms": "scam", "network": "network_anomaly"}
            t_type = "benign" if state == "normal" else threat_map.get(source, "benign")
            inp = LlamaExplanationInput(
                threat_type=t_type,
                risk_level=risk_level,
                confidence=min(1.0, max(0.0, confidence)),
                evidence=evidence[:5],
            )
            out = self._llama_advisor.explain(inp)
            # Detector-controlled guardrail: risk_level cannot be overridden
            return out.explanation, out.recommendation, True, out.runtime_backend
        except Exception as exc:
            logger.warning("LLM unavailable during DEEP ANALYSIS (%s); using deterministic advisory.", exc)
            return base_exp, base_rec, False, f"Fallback-Deterministic ({type(exc).__name__})"

    def assess_url(self, url: str, mode: OperatingMode = "fast_triage") -> AdaptiveThreatAssessment:
        t0 = time.perf_counter()
        if not url or not str(url).strip():
            exp, rec, used, bk = self._run_llm_if_requested(mode, "url", "insufficient_evidence", "low", 0.0, ["Empty URL input"])
            return AdaptiveThreatAssessment(
                source="url",
                operating_mode=mode,
                decision_state="insufficient_evidence",
                risk_level="low",
                risk_score=0,
                supervised_probability=0.0,
                calibrated_threshold=0.50,
                deduplicated_evidence=["Empty URL input"],
                policy_reasoning=["Empty URL string cannot be evaluated."],
                explanation=exp,
                recommendation=rec,
                llm_used=used,
                llm_backend=bk,
                total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        res: DetectorResult = self.url_detector.predict(url)
        state: AdaptiveStateType = (
            "confirmed_malicious"
            if res.classification == "malicious"
            else ("suspicious_unknown" if res.classification == "suspicious" else "normal")
        )
        ev = self._deduplicate_evidence(res.evidence)
        exp, rec, used, bk = self._run_llm_if_requested(mode, "url", state, res.risk_level, res.confidence, ev)
        return AdaptiveThreatAssessment(
            source="url",
            operating_mode=mode,
            decision_state=state,
            risk_level=res.risk_level,
            risk_score=res.risk_score,
            supervised_probability=round(float(res.confidence), 4),
            calibrated_threshold=0.57,
            deduplicated_evidence=ev,
            policy_reasoning=[f"URL detector classification='{res.classification}' with calibrated score={res.risk_score}/100."],
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def assess_sms(self, sms_text: str, mode: OperatingMode = "fast_triage") -> AdaptiveThreatAssessment:
        t0 = time.perf_counter()
        if not sms_text or not str(sms_text).strip():
            exp, rec, used, bk = self._run_llm_if_requested(mode, "sms", "insufficient_evidence", "low", 0.0, ["Empty SMS input"])
            return AdaptiveThreatAssessment(
                source="sms",
                operating_mode=mode,
                decision_state="insufficient_evidence",
                risk_level="low",
                risk_score=0,
                supervised_probability=0.0,
                calibrated_threshold=0.25,
                deduplicated_evidence=["Empty SMS input"],
                policy_reasoning=["Empty SMS body cannot be evaluated."],
                explanation=exp,
                recommendation=rec,
                llm_used=used,
                llm_backend=bk,
                total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        res: DetectorResult = self.sms_detector.predict(sms_text)
        state: AdaptiveStateType = (
            "confirmed_malicious"
            if res.classification == "malicious"
            else ("suspicious_unknown" if res.classification == "suspicious" else "normal")
        )
        ev = self._deduplicate_evidence(res.evidence)
        exp, rec, used, bk = self._run_llm_if_requested(mode, "sms", state, res.risk_level, res.confidence, ev)
        return AdaptiveThreatAssessment(
            source="sms",
            operating_mode=mode,
            decision_state=state,
            risk_level=res.risk_level,
            risk_score=res.risk_score,
            supervised_probability=round(float(res.confidence), 4),
            calibrated_threshold=0.25,
            deduplicated_evidence=ev,
            policy_reasoning=[f"SMS detector classification='{res.classification}' with calibrated score={res.risk_score}/100."],
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def assess_network_flow(self, flow: Optional[Dict[str, Any]], mode: OperatingMode = "fast_triage") -> AdaptiveThreatAssessment:
        t0 = time.perf_counter()
        if self.adaptive_network is None or not self.adaptive_network.is_fitted:
            raise RuntimeError("AdaptiveThreatIntelligenceEngine requires a fitted AdaptiveNetworkDetector.")

        verdict = self.adaptive_network.predict(flow)
        ev = self._deduplicate_evidence(verdict.evidence)
        rlevel = self._risk_level_from_score(verdict.risk_score)
        conf = max(verdict.supervised_prob, min(1.0, max(0.0, 0.5 + verdict.anomaly_score)))
        exp, rec, used, bk = self._run_llm_if_requested(mode, "network", verdict.state, rlevel, conf, ev)

        return AdaptiveThreatAssessment(
            source="network",
            operating_mode=mode,
            decision_state=verdict.state,
            risk_level=rlevel,
            risk_score=verdict.risk_score,
            supervised_probability=verdict.supervised_prob,
            anomaly_score=verdict.anomaly_score,
            calibrated_threshold=self.adaptive_network.supervised_threshold,
            deduplicated_evidence=ev,
            policy_reasoning=verdict.reasoning,
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )
