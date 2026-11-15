"""Calibrated Decision & Abstention Policy Engine (Phase 3 — Priority 4).

Implements a unified, documented decision policy across URL, SMS, and Network modalities:
- confirmed_malicious
- suspicious_unknown
- normal
- insufficient_evidence
Separates calibrated supervised probability from anomaly score, avoids arbitrary score
averaging or double-counting, supports confidence-aware abstention, and enforces
detector-locked risk guardrails over optional LLM explanations.
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from src.common.logger import get_logger
from src.common.schemas import LlamaExplanationInput, RiskLevelType
from src.network_detection.adaptive import AdaptiveStateType
from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.hardened import HardenedSMSDetector
from src.url_detection.hardened import HardenedURLDetector

logger = get_logger("SecureEdge.CalibratedPolicy")

OperatingMode = Literal["fast_triage", "deep_analysis"]


@dataclass(frozen=True)
class PolicyThresholds:
    """Documented Phase 3 decision thresholds selected on validation splits."""

    confirmed_prob_min: float = 0.65
    suspicious_prob_min: float = 0.40
    abstention_low: float = 0.32
    abstention_high: float = 0.54
    min_sms_chars: int = 4
    min_url_chars: int = 4
    anomaly_z_suspicious: float = 4.0


class CalibratedThreatAssessment(BaseModel):
    """Structured Phase 3 threat assessment with explicit calibration and abstention fields."""

    source: Literal["url", "sms", "network"]
    operating_mode: OperatingMode
    decision_state: AdaptiveStateType
    risk_level: RiskLevelType
    risk_score: int = Field(..., ge=0, le=100)
    supervised_probability: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: Optional[float] = None
    host_robust_z: Optional[float] = None
    is_calibrated: bool = True
    abstained: bool = False
    deduplicated_evidence: List[str]
    policy_reasoning: List[str]
    explanation: str
    recommendation: str
    llm_used: bool = False
    llm_backend: str = "None (FAST TRIAGE)"
    total_latency_ms: float = 0.0


class CalibratedDecisionPolicy:
    """Pure, deterministic decision policy separating probability, anomaly, and abstention."""

    def __init__(self, thresholds: Optional[PolicyThresholds] = None) -> None:
        self.thresholds = thresholds or PolicyThresholds()

    @staticmethod
    def deduplicate_evidence(items: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for item in items:
            norm = " ".join(str(item).lower().split())
            if norm and norm not in seen:
                seen.add(norm)
                out.append(str(item).strip())
        return out[:6]

    @staticmethod
    def risk_level_from_state_and_score(state: AdaptiveStateType, score: int) -> RiskLevelType:
        if state == "confirmed_malicious":
            return "critical" if score >= 80 else "high"
        if state == "suspicious_unknown":
            return "medium"
        return "low"

    def decide_text_or_url(
        self,
        source: Literal["url", "sms"],
        prob: float,
        corroborating_signals: int,
        ambiguous_shortener_only: bool = False,
    ) -> Tuple[AdaptiveStateType, int, bool, List[str]]:
        """Map calibrated probability + independent signal count to 4 operational states."""
        t = self.thresholds
        reasoning = [
            f"Calibrated {source} malicious probability={prob:.3f}, independent_signals={corroborating_signals}."
        ]

        if ambiguous_shortener_only:
            reasoning.append("Input is a bare URL shortener without further lexical context -> suspicious_unknown.")
            return "suspicious_unknown", max(42, int(round(prob * 100))), False, reasoning

        if prob >= t.confirmed_prob_min and corroborating_signals >= 1:
            reasoning.append(f"Probability >= {t.confirmed_prob_min:.2f} with corroborating forensic signal -> confirmed_malicious.")
            return "confirmed_malicious", int(round(prob * 100)), False, reasoning

        if prob >= t.confirmed_prob_min and corroborating_signals == 0:
            # High model score alone without explainable indicator -> downgrade to suspicious_unknown
            reasoning.append("Elevated model probability without independent forensic signal -> suspicious_unknown.")
            return "suspicious_unknown", min(59, int(round(prob * 85))), False, reasoning

        if t.abstention_low <= prob < t.abstention_high and corroborating_signals == 0:
            reasoning.append(
                f"Probability in abstention band [{t.abstention_low:.2f}, {t.abstention_high:.2f}) "
                "with zero corroborating indicators -> insufficient_evidence."
            )
            return "insufficient_evidence", int(round(prob * 100)), True, reasoning

        if prob >= t.suspicious_prob_min:
            reasoning.append(f"Moderate probability >= {t.suspicious_prob_min:.2f} -> suspicious_unknown.")
            return "suspicious_unknown", int(round(prob * 100)), False, reasoning

        reasoning.append("Low calibrated risk and no unmitigated threat indicators -> normal.")
        return "normal", int(round(prob * 100)), False, reasoning


class CalibratedThreatEngine:
    """Phase 3 Unified Threat Engine integrating hardened detectors and CalibratedDecisionPolicy."""

    def __init__(
        self,
        url_detector: Optional[HardenedURLDetector] = None,
        sms_detector: Optional[HardenedSMSDetector] = None,
        network_detector: Optional[ContextAwareNetworkDetector] = None,
        policy: Optional[CalibratedDecisionPolicy] = None,
        llama_advisor: Optional[Any] = None,
    ) -> None:
        self.url_detector = url_detector or HardenedURLDetector()
        self.sms_detector = sms_detector or HardenedSMSDetector()
        self.network_detector = network_detector
        self.policy = policy or CalibratedDecisionPolicy()
        self._llama_advisor = llama_advisor

    @staticmethod
    def _deterministic_advisory(source: str, state: AdaptiveStateType, evidence: List[str]) -> Tuple[str, str]:
        ev_str = "; ".join(evidence[:3]) if evidence else "no additional details"
        if state == "insufficient_evidence":
            return (
                f"Abstaining on {source} input due to insufficient or ambiguous evidence ({ev_str}).",
                "Collect complete telemetry or verify independently before trusting or blocking.",
            )
        if state == "confirmed_malicious":
            return (
                f"Confirmed malicious {source} threat. Forensic indicators: {ev_str}.",
                "Block or quarantine immediately; do not open links, share OTPs/PINs, or allow outbound transfers.",
            )
        if state == "suspicious_unknown":
            return (
                f"Suspicious or anomalous {source} activity requiring caution ({ev_str}).",
                "Hold for verification or inspect via isolated channel before proceeding.",
            )
        return (
            f"No malicious {source} indicators detected ({ev_str}).",
            "No immediate action required.",
        )

    def _run_llm_if_requested(
        self,
        mode: OperatingMode,
        source: str,
        state: AdaptiveStateType,
        locked_risk_level: RiskLevelType,
        confidence: float,
        evidence: List[str],
    ) -> Tuple[str, str, bool, str]:
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
                risk_level=locked_risk_level,
                confidence=min(1.0, max(0.0, confidence)),
                evidence=evidence[:5] if evidence else ["Automated detector assessment"],
            )
            out = self._llama_advisor.explain(inp)
            # Detector-controlled guardrail: locked_risk_level cannot be downgraded by LLM output
            return out.explanation, out.recommendation, True, out.runtime_backend
        except Exception as exc:
            logger.warning("LLM unavailable during DEEP ANALYSIS (%s); using deterministic advisory.", exc)
            return base_exp, base_rec, False, f"Fallback-Deterministic ({type(exc).__name__})"

    def assess_sms(self, text: str, mode: OperatingMode = "fast_triage") -> CalibratedThreatAssessment:
        t0 = time.perf_counter()
        cleaned = (text or "").strip()
        if len(cleaned) < self.policy.thresholds.min_sms_chars:
            ev = ["SMS input is empty or too short for reliable classification"]
            exp, rec, used, bk = self._run_llm_if_requested(mode, "sms", "insufficient_evidence", "low", 0.0, ev)
            return CalibratedThreatAssessment(
                source="sms",
                operating_mode=mode,
                decision_state="insufficient_evidence",
                risk_level="low",
                risk_score=0,
                supervised_probability=0.0,
                is_calibrated=self.sms_detector.is_calibrated,
                abstained=True,
                deduplicated_evidence=ev,
                policy_reasoning=["Input length below minimum threshold -> abstaining (insufficient_evidence)."],
                explanation=exp,
                recommendation=rec,
                llm_used=used,
                llm_backend=bk,
                total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        prob, feats, evidence = self.sms_detector.predict_proba_and_features(cleaned)
        signals = int(
            (feats.get("has_url", 0) > 0)
            + (feats.get("urgency_match_count", 0) > 0)
            + (feats.get("financial_scam_match_count", 0) > 0)
            + (feats.get("hinglish_scam_match_count", 0) > 0)
            + (feats.get("confusable_char_count", 0) > 0)
            + (feats.get("spaced_obfuscation_count", 0) > 0)
            + (feats.get("leetspeak_token_count", 0) > 0)
            + (feats.get("zero_width_count", 0) > 0)
        )
        state, risk_score, abstained, reasoning = self.policy.decide_text_or_url("sms", prob, signals)
        locked_level = self.policy.risk_level_from_state_and_score(state, risk_score)
        dedup_ev = self.policy.deduplicate_evidence(evidence)
        exp, rec, used, bk = self._run_llm_if_requested(mode, "sms", state, locked_level, prob, dedup_ev)

        return CalibratedThreatAssessment(
            source="sms",
            operating_mode=mode,
            decision_state=state,
            risk_level=locked_level,
            risk_score=risk_score,
            supervised_probability=round(prob, 4),
            is_calibrated=self.sms_detector.is_calibrated,
            abstained=abstained,
            deduplicated_evidence=dedup_ev,
            policy_reasoning=reasoning,
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def assess_url(self, url: str, mode: OperatingMode = "fast_triage") -> CalibratedThreatAssessment:
        t0 = time.perf_counter()
        cleaned = (url or "").strip()
        if len(cleaned) < self.policy.thresholds.min_url_chars or ("." not in cleaned and "localhost" not in cleaned):
            ev = ["URL input is empty or lacks a valid domain structure"]
            exp, rec, used, bk = self._run_llm_if_requested(mode, "url", "insufficient_evidence", "low", 0.0, ev)
            return CalibratedThreatAssessment(
                source="url",
                operating_mode=mode,
                decision_state="insufficient_evidence",
                risk_level="low",
                risk_score=0,
                supervised_probability=0.0,
                is_calibrated=self.url_detector.is_calibrated,
                abstained=True,
                deduplicated_evidence=ev,
                policy_reasoning=["Malformed or incomplete URL input -> abstaining (insufficient_evidence)."],
                explanation=exp,
                recommendation=rec,
                llm_used=used,
                llm_backend=bk,
                total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        prob, feats, evidence = self.url_detector.predict_proba_and_features(cleaned)
        signals = int(
            (feats.get("confusable_char_count", 0) > 0)
            + (feats.get("has_mixed_scripts", 0) > 0)
            + (feats.get("punycode_brand_impersonation", 0) > 0)
            + (feats.get("brand_impersonation_regdomain", 0) > 0)
            + (feats.get("brand_in_hostname", 0) > 0)
            + (feats.get("has_ip_address", 0) > 0)
            + (feats.get("encoded_redirect_param", 0) > 0)
            + (feats.get("excessive_subdomains", 0) > 0)
            + (feats.get("path_mixed_case_obfuscation", 0) > 0)
            + (feats.get("suspicious_tld", 0) > 0)
            + (feats.get("suspicious_keyword_count", 0) > 0)
            + (feats.get("is_shortener", 0) > 0)
        )
        shortener_only = (
            feats.get("is_shortener", 0) > 0
            and feats.get("encoded_redirect_param", 0) == 0
            and feats.get("brand_in_hostname", 0) == 0
            and prob < self.policy.thresholds.confirmed_prob_min
        )
        state, risk_score, abstained, reasoning = self.policy.decide_text_or_url(
            "url", prob, signals, ambiguous_shortener_only=shortener_only
        )
        locked_level = self.policy.risk_level_from_state_and_score(state, risk_score)
        dedup_ev = self.policy.deduplicate_evidence(evidence)
        exp, rec, used, bk = self._run_llm_if_requested(mode, "url", state, locked_level, prob, dedup_ev)

        return CalibratedThreatAssessment(
            source="url",
            operating_mode=mode,
            decision_state=state,
            risk_level=locked_level,
            risk_score=risk_score,
            supervised_probability=round(prob, 4),
            is_calibrated=self.url_detector.is_calibrated,
            abstained=abstained,
            deduplicated_evidence=dedup_ev,
            policy_reasoning=reasoning,
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )

    def assess_network_flow(self, flow: Dict[str, Any], mode: OperatingMode = "fast_triage") -> CalibratedThreatAssessment:
        t0 = time.perf_counter()
        if self.network_detector is None or not self.network_detector.is_fitted:
            raise RuntimeError("ContextAwareNetworkDetector must be fitted before assessing flows.")

        verdict = self.network_detector.predict(flow)
        locked_level = self.policy.risk_level_from_state_and_score(verdict.state, verdict.risk_score)
        dedup_ev = self.policy.deduplicate_evidence(verdict.evidence)
        exp, rec, used, bk = self._run_llm_if_requested(
            mode, "network", verdict.state, locked_level, verdict.supervised_prob, dedup_ev
        )

        return CalibratedThreatAssessment(
            source="network",
            operating_mode=mode,
            decision_state=verdict.state,
            risk_level=locked_level,
            risk_score=verdict.risk_score,
            supervised_probability=verdict.supervised_prob,
            anomaly_score=verdict.anomaly_score,
            host_robust_z=verdict.host_robust_z,
            is_calibrated=self.network_detector.is_calibrated,
            abstained=(verdict.state == "insufficient_evidence"),
            deduplicated_evidence=dedup_ev,
            policy_reasoning=verdict.reasoning,
            explanation=exp,
            recommendation=rec,
            llm_used=used,
            llm_backend=bk,
            total_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )
