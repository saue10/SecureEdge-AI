"""Standardized Pydantic schemas for SecureEdge AI detectors, threat engine, and Llama advisor."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


SourceType = Literal["url", "sms", "network"]
ThreatType = Literal["phishing", "scam", "spam", "network_anomaly", "benign"]
ClassificationType = Literal["benign", "suspicious", "malicious"]
RiskLevelType = Literal["low", "medium", "high", "critical"]


class DetectorResult(BaseModel):
    """Standardized output schema produced by every specialized detector and Unified Threat Engine."""

    source: SourceType = Field(..., description="Input modality: url | sms | network")
    threat_type: ThreatType = Field(
        ..., description="Detected threat category: phishing | scam | spam | network_anomaly | benign"
    )
    classification: ClassificationType = Field(
        ..., description="Severity tier: benign | suspicious | malicious"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Model classification confidence score in [0.0, 1.0]"
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Normalized risk score in [0, 100]"
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Human-readable forensic evidence strings extracted by the specialized detector",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp of the detection event",
    )
    model_version: str = Field(
        default="1.0.0", description="Version identifier of the specialized detector model"
    )
    inference_latency_ms: float = Field(
        default=0.0, ge=0.0, description="Inference execution latency in milliseconds"
    )
    features: Dict[str, Any] = Field(
        default_factory=dict, description="Extracted feature dictionary for auditability"
    )
    raw_input_summary: str = Field(
        default="", description="Sanitized summary of the inspected input"
    )
    is_calibrated: bool = Field(
        default=True, description="Whether confidence score underwent probability calibration"
    )

    @property
    def risk_level(self) -> RiskLevelType:
        """Map numeric risk_score (0-100) to categorical risk level."""
        if self.risk_score >= 80:
            return "critical"
        if self.risk_score >= 60:
            return "high"
        if self.risk_score >= 35:
            return "medium"
        return "low"

    def to_spec_dict(self) -> Dict[str, Any]:
        """Return the exact canonical PS3 Unified Threat Engine schema dictionary."""
        return {
            "source": self.source,
            "threat_type": self.threat_type,
            "classification": self.classification,
            "confidence": round(float(self.confidence), 4),
            "risk_score": int(self.risk_score),
            "evidence": list(self.evidence),
            "timestamp": self.timestamp,
            "model_version": self.model_version,
        }


class LlamaExplanationInput(BaseModel):
    """Structured input passed from the Unified Threat Engine to the local Llama model."""

    threat_type: str = Field(..., description="Detected threat type (phishing, scam, network_anomaly, benign)")
    risk_level: RiskLevelType = Field(..., description="Categorical risk level (low, medium, high, critical)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detector confidence score")
    evidence: List[str] = Field(..., description="Bounded list of detector-generated evidence items")

    @field_validator("evidence")
    @classmethod
    def validate_non_empty_evidence(cls, v: List[str]) -> List[str]:
        cleaned = [str(item).strip() for item in v if str(item).strip()]
        return cleaned if cleaned else ["No anomalous indicators triggered"]


class LlamaExplanationOutput(BaseModel):
    """Validated structured output returned by the local Llama + ExecuTorch advisor."""

    explanation: str = Field(
        ..., min_length=10, description="Clear, non-expert explanation of the detector findings"
    )
    recommendation: str = Field(
        ..., min_length=10, description="Actionable, safe remediation steps for the user"
    )
    risk_level: RiskLevelType = Field(
        ..., description="Risk level matching the detector assessment (cannot override detector)"
    )
    runtime_backend: str = Field(
        default="ExecuTorch-CPU", description="Runtime backend used for inference"
    )
    pte_artifact_verified: bool = Field(
        default=False, description="Whether the .pte ExecuTorch artifact is verified on disk"
    )
    generation_latency_ms: float = Field(
        default=0.0, ge=0.0, description="End-to-end LLM advisory latency in milliseconds"
    )

    def to_spec_dict(self) -> Dict[str, Any]:
        """Return the exact canonical PS3 Llama output dictionary."""
        return {
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "risk_level": self.risk_level,
        }


class UnifiedThreatReport(BaseModel):
    """Complete end-to-end report combining specialized detector output and Llama explanation."""

    detector_result: DetectorResult
    llama_input: LlamaExplanationInput
    llama_output: LlamaExplanationOutput
    total_pipeline_latency_ms: float = Field(default=0.0, ge=0.0)
    execution_mode: Literal["live_inference", "replay_demo"] = Field(default="live_inference")
    hardware_platform: str = Field(default="x86_64-Windows-Host")
