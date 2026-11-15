"""Unified Threat Engine orchestrating URL, SMS, and Network detectors with Local Llama + ExecuTorch Advisor."""

import json
import platform
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from src.common.config import HISTORY_DB_PATH, HOST_ARCH, HOST_OS
from src.common.logger import get_logger
from src.common.schemas import (
    DetectorResult,
    LlamaExplanationInput,
    LlamaExplanationOutput,
    UnifiedThreatReport,
)
from src.network_detection.detector import NetworkAnomalyDetector
from src.sms_detection.detector import ScamSMSDetector
from src.url_detection.detector import PhishingURLDetector

logger = get_logger("SecureEdge.ThreatEngine")


class UnifiedThreatEngine:
    """
    Central security orchestration engine for SecureEdge AI.
    Separates specialized ML threat detection from bounded local Llama + ExecuTorch explanation.
    """

    def __init__(
        self,
        url_detector: Optional[PhishingURLDetector] = None,
        sms_detector: Optional[ScamSMSDetector] = None,
        network_detector: Optional[NetworkAnomalyDetector] = None,
        llama_advisor: Optional[Any] = None,
        history_path: Optional[Path] = None,
    ) -> None:
        self.url_detector = url_detector or PhishingURLDetector()
        self.sms_detector = sms_detector or ScamSMSDetector()
        self.network_detector = network_detector or NetworkAnomalyDetector()
        self._llama_advisor = llama_advisor
        self.history_path = Path(history_path) if history_path else HISTORY_DB_PATH
        self.hardware_platform = f"{HOST_ARCH}-{HOST_OS}"

    @property
    def llama_advisor(self) -> Any:
        """Lazy-load the Llama + ExecuTorch advisor to keep startup fast and modular."""
        if self._llama_advisor is None:
            from src.llama.advisor import LlamaCyberAdvisor

            self._llama_advisor = LlamaCyberAdvisor()
        return self._llama_advisor

    def reload_models(self) -> None:
        """Reload all detector models and the Llama ExecuTorch runtime from disk."""
        self.url_detector._load_model_if_exists()
        self.sms_detector._load_model_if_exists()
        self.network_detector._load_model_if_exists()
        if self._llama_advisor is not None:
            self._llama_advisor.reload()

    def analyze_url(
        self,
        url: str,
        explain: bool = True,
        persist_history: bool = True,
    ) -> UnifiedThreatReport:
        """Run end-to-end URL Phishing Detection -> Threat Assessment -> Llama Explanation."""
        t0 = time.perf_counter()
        detector_res = self.url_detector.predict(url)
        return self._finalize_report(detector_res, t0, explain=explain, mode="live_inference", persist=persist_history)

    def analyze_sms(
        self,
        sms_text: str,
        explain: bool = True,
        persist_history: bool = True,
    ) -> UnifiedThreatReport:
        """Run end-to-end SMS Scam/Spam Detection -> Threat Assessment -> Llama Explanation."""
        t0 = time.perf_counter()
        detector_res = self.sms_detector.predict(sms_text)
        return self._finalize_report(detector_res, t0, explain=explain, mode="live_inference", persist=persist_history)

    def analyze_network_flow(
        self,
        flow: Dict[str, Any],
        explain: bool = True,
        execution_mode: Literal["live_inference", "replay_demo"] = "replay_demo",
        persist_history: bool = True,
    ) -> UnifiedThreatReport:
        """Run end-to-end Network Flow Anomaly Detection -> Threat Assessment -> Llama Explanation."""
        t0 = time.perf_counter()
        detector_res = self.network_detector.predict(flow)
        return self._finalize_report(detector_res, t0, explain=explain, mode=execution_mode, persist=persist_history)

    def _finalize_report(
        self,
        detector_res: DetectorResult,
        start_time: float,
        explain: bool,
        mode: Literal["live_inference", "replay_demo"],
        persist: bool,
    ) -> UnifiedThreatReport:
        """Construct LlamaExplanationInput, query Llama + ExecuTorch advisor, validate, and log."""
        llama_in = LlamaExplanationInput(
            threat_type=detector_res.threat_type,
            risk_level=detector_res.risk_level,
            confidence=detector_res.confidence,
            evidence=detector_res.evidence[:5],
        )

        if explain:
            llama_out = self.llama_advisor.explain(llama_in)
        else:
            llama_out = LlamaExplanationOutput(
                explanation=f"Automated detector classified {detector_res.source} input as {detector_res.classification} ({detector_res.threat_type}).",
                recommendation="Enable AI Threat Explanation for detailed remediation guidance.",
                risk_level=detector_res.risk_level,
                runtime_backend="Skipped",
                pte_artifact_verified=False,
                generation_latency_ms=0.0,
            )

        # Enforce strict architectural rule: LLAMA MUST NOT override the detector's risk_level
        if llama_out.risk_level != detector_res.risk_level:
            logger.warning(
                "Overriding mismatched LLM risk_level (%s -> %s) to preserve detector authority.",
                llama_out.risk_level,
                detector_res.risk_level,
            )
            llama_out.risk_level = detector_res.risk_level

        total_ms = (time.perf_counter() - start_time) * 1000.0
        report = UnifiedThreatReport(
            detector_result=detector_res,
            llama_input=llama_in,
            llama_output=llama_out,
            total_pipeline_latency_ms=round(total_ms, 3),
            execution_mode=mode,
            hardware_platform=self.hardware_platform,
        )

        if persist:
            self._append_history(report)

        return report

    def _append_history(self, report: UnifiedThreatReport) -> None:
        """Persist scan report to local JSON history file for dashboard analytics."""
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            records: List[Dict[str, Any]] = []
            if self.history_path.exists():
                try:
                    records = json.loads(self.history_path.read_text(encoding="utf-8"))
                except Exception:
                    records = []

            entry = {
                "timestamp": report.detector_result.timestamp,
                "source": report.detector_result.source,
                "threat_type": report.detector_result.threat_type,
                "classification": report.detector_result.classification,
                "confidence": report.detector_result.confidence,
                "risk_score": report.detector_result.risk_score,
                "risk_level": report.detector_result.risk_level,
                "evidence": report.detector_result.evidence,
                "raw_input_summary": report.detector_result.raw_input_summary,
                "model_version": report.detector_result.model_version,
                "detector_latency_ms": report.detector_result.inference_latency_ms,
                "llama_latency_ms": report.llama_output.generation_latency_ms,
                "total_latency_ms": report.total_pipeline_latency_ms,
                "explanation": report.llama_output.explanation,
                "recommendation": report.llama_output.recommendation,
                "runtime_backend": report.llama_output.runtime_backend,
                "execution_mode": report.execution_mode,
                "hardware_platform": report.hardware_platform,
            }
            records.append(entry)
            # Keep most recent 500 records
            records = records[-500:]
            self.history_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to persist detection history: %s", exc)

    def get_history(self) -> List[Dict[str, Any]]:
        """Load persisted detection history records."""
        if not self.history_path.exists():
            return []
        try:
            return json.loads(self.history_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def clear_history(self) -> None:
        """Clear persisted detection history."""
        if self.history_path.exists():
            self.history_path.write_text("[]", encoding="utf-8")
