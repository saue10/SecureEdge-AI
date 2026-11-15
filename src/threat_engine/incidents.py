"""Incident Correlation Engine & Safe Report Export (Phase 4 — Tasks 3 & 4).

Provides:
- Unified IncidentRecord & IncidentObservation schemas
- Deterministic, LLM-independent correlation based strictly on defensible entity matches
  (exact URL, exact registered domain, or exact IP address)
- Bounded local retention (MAX_INCIDENTS = 200)
- PII/network redaction and JSON / Markdown incident report export
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from src.common.config import DATA_DIR
from src.common.logger import get_logger
from src.url_detection.features import URLFeatureExtractor

logger = get_logger("SecureEdge.Incidents")

MAX_INCIDENTS = 200
DEFAULT_INCIDENTS_PATH = DATA_DIR / "processed" / "incidents_history.json"

URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
PHONE_REDACT_RE = re.compile(r"(?:\+?\d{1,3}[-\s]?)?\b\d{10}\b")
OTP_REDACT_RE = re.compile(r"\b(\d{4,8})\b(?=\s+(?:is\s+your\s+otp|otp|verification\s+code))", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b")
QUERY_SECRET_RE = re.compile(r"([?&](?:token|key|auth|session|id|u|code|otp)=)([^&\s]+)", re.IGNORECASE)

SeverityType = Literal["low", "medium", "high", "critical"]


def redact_sensitive_text(text: str) -> str:
    """Mask phone numbers, OTP codes, URL query token values, and last two IPv4 octets."""
    if not text:
        return ""
    out = PHONE_REDACT_RE.sub("[PHONE_REDACTED]", text)
    out = OTP_REDACT_RE.sub("[OTP_REDACTED]", out)
    out = QUERY_SECRET_RE.sub(r"\1[REDACTED]", out)
    out = IPV4_RE.sub(r"\1.*.*", out)
    return out


def extract_defensible_entities(
    source: str,
    raw_input: str,
    flow: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[str]]:
    """Extract exact URLs, registered domains, and IP addresses for defensible correlation."""
    urls: Set[str] = set()
    domains: Set[str] = set()
    ips: Set[str] = set()

    if source == "url" and raw_input:
        norm = URLFeatureExtractor.normalize_url(raw_input)
        if norm:
            urls.add(norm.lower())
            reg = URLFeatureExtractor.extract_registered_domain(norm)
            if reg not in {"empty", "invalid"}:
                domains.add(reg.lower())
            host = (urlparse(norm).hostname or "").lower()
            if host and URLFeatureExtractor._is_ip_address(host):
                ips.add(host)

    elif source == "sms" and raw_input:
        for u in URL_EXTRACT_RE.findall(raw_input):
            norm = URLFeatureExtractor.normalize_url(u)
            if norm:
                urls.add(norm.lower())
                reg = URLFeatureExtractor.extract_registered_domain(norm)
                if reg not in {"empty", "invalid"}:
                    domains.add(reg.lower())

    elif source == "network" and flow:
        src_ip = str(flow.get("src_ip", "") or "").strip()
        dst_ip = str(flow.get("dst_ip", "") or "").strip()
        dst_domain = str(flow.get("dst_domain", "") or "").strip().lower()
        if src_ip:
            ips.add(src_ip)
        if dst_ip:
            ips.add(dst_ip)
        if dst_domain:
            reg = URLFeatureExtractor.extract_registered_domain(dst_domain)
            if reg not in {"empty", "invalid"}:
                domains.add(reg.lower())

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
    }


class IncidentObservation(BaseModel):
    """Single detector observation attached to an IncidentRecord."""

    observation_id: str
    source: Literal["url", "sms", "network"]
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decision_state: str
    risk_level: SeverityType
    risk_score: int = Field(..., ge=0, le=100)
    supervised_probability: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: Optional[float] = None
    detector_name: str
    operating_mode: str = "fast_triage"
    llm_used: bool = False
    llm_backend: str = "None (FAST TRIAGE)"
    evidence: List[str] = Field(default_factory=list)
    recommended_action: str
    raw_summary: str
    entities: Dict[str, List[str]] = Field(default_factory=dict)


class IncidentRecord(BaseModel):
    """Unified cybersecurity incident aggregating correlated observations."""

    incident_id: str
    title: str
    created_at: str
    updated_at: str
    severity: SeverityType
    decision_state: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    limitations: List[str]
    observations: List[IncidentObservation] = Field(default_factory=list)
    correlated_entities: List[Dict[str, str]] = Field(default_factory=list)
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    recommended_action: str


class IncidentCorrelationEngine:
    """Deterministic, LLM-independent incident correlation and report exporter."""

    SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self, storage_path: Optional[Path] = None, max_incidents: int = MAX_INCIDENTS) -> None:
        self.storage_path = Path(storage_path) if storage_path else DEFAULT_INCIDENTS_PATH
        self.max_incidents = max_incidents
        self._incidents: List[IncidentRecord] = []
        self._load()

    def _load(self) -> None:
        if self.storage_path.exists():
            try:
                raw = json.loads(self.storage_path.read_text(encoding="utf-8"))
                self._incidents = [IncidentRecord(**item) for item in raw][-self.max_incidents :]
            except Exception as exc:
                logger.warning("Failed to load incidents history (%s); starting empty.", exc)
                self._incidents = []

    def _save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [inc.model_dump() for inc in self._incidents[-self.max_incidents :]]
        self.storage_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def list_incidents(self) -> List[IncidentRecord]:
        return list(reversed(self._incidents))

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        for inc in self._incidents:
            if inc.incident_id == incident_id:
                return inc
        return None

    def clear(self) -> None:
        self._incidents = []
        self._save()

    @staticmethod
    def _find_defensible_match(
        existing: IncidentRecord,
        new_entities: Dict[str, List[str]],
    ) -> Optional[Tuple[str, str]]:
        """Return (entity_type, entity_value) ONLY on exact URL, registered domain, or IP match."""
        ex_urls = {u for o in existing.observations for u in o.entities.get("urls", [])}
        ex_domains = {d for o in existing.observations for d in o.entities.get("domains", [])}
        ex_ips = {ip for o in existing.observations for ip in o.entities.get("ips", [])}

        for u in new_entities.get("urls", []):
            if u in ex_urls:
                return ("exact_url", u)
        for d in new_entities.get("domains", []):
            if d in ex_domains:
                return ("exact_registered_domain", d)
        for ip in new_entities.get("ips", []):
            # Correlate on non-empty exact IP only if existing incident already has a non-normal state
            if ip in ex_ips and existing.decision_state in {"confirmed_malicious", "suspicious_unknown"}:
                return ("exact_ip_address", ip)
        return None

    def record_observation(
        self,
        source: Literal["url", "sms", "network"],
        raw_input: str,
        assessment: Dict[str, Any],
        detector_name: str,
        flow: Optional[Dict[str, Any]] = None,
    ) -> IncidentRecord:
        """Create or correlate an observation into an IncidentRecord using defensible entity links."""
        now_iso = datetime.now(timezone.utc).isoformat()
        entities = extract_defensible_entities(source, raw_input, flow=flow)
        obs_id = f"OBS-{int(datetime.now(timezone.utc).timestamp() * 1000) % 10000000:07d}-{len(self._incidents)}"

        obs = IncidentObservation(
            observation_id=obs_id,
            source=source,
            timestamp=now_iso,
            decision_state=str(assessment["decision_state"]),
            risk_level=assessment["risk_level"],
            risk_score=int(assessment["risk_score"]),
            supervised_probability=float(assessment["supervised_probability"]),
            anomaly_score=assessment.get("anomaly_score"),
            detector_name=detector_name,
            operating_mode=str(assessment.get("operating_mode", "fast_triage")),
            llm_used=bool(assessment.get("llm_used", False)),
            llm_backend=str(assessment.get("llm_backend", "None (FAST TRIAGE)")),
            evidence=list(assessment.get("deduplicated_evidence", [])),
            recommended_action=str(assessment.get("recommendation", "")),
            raw_summary=raw_input[:160],
            entities=entities,
        )

        # Search recent incidents (latest first) for a defensible entity match
        matched_inc: Optional[IncidentRecord] = None
        match_detail: Optional[Tuple[str, str]] = None
        if obs.decision_state != "normal":
            for inc in reversed(self._incidents[-30:]):
                m = self._find_defensible_match(inc, entities)
                if m is not None:
                    matched_inc = inc
                    match_detail = m
                    break

        limitations = [
            "Evaluated on local CPU-only host (Windows x86_64 prototype); ARM64 hardware execution not verified on this device.",
            "Training/evaluation datasets are synthetic or curated local benchmarks; treat outputs as decision support.",
        ]

        if matched_inc is not None and match_detail is not None:
            matched_inc.observations.append(obs)
            matched_inc.updated_at = now_iso
            if self.SEVERITY_RANK[obs.risk_level] > self.SEVERITY_RANK[matched_inc.severity]:
                matched_inc.severity = obs.risk_level
                matched_inc.decision_state = obs.decision_state
                matched_inc.recommended_action = obs.recommended_action
            matched_inc.confidence = round(max(matched_inc.confidence, obs.supervised_probability), 4)
            corr_entry = {
                "relation_type": match_detail[0],
                "matched_value": match_detail[1],
                "linked_observation": obs.observation_id,
            }
            if corr_entry not in matched_inc.correlated_entities:
                matched_inc.correlated_entities.append(corr_entry)
            matched_inc.timeline.append(
                {
                    "timestamp": now_iso,
                    "event": f"[{source.upper()}] {obs.decision_state} (score={obs.risk_score}) correlated via {match_detail[0]}='{match_detail[1]}'",
                }
            )
            seen_ev = set(matched_inc.evidence)
            for ev in obs.evidence:
                if ev not in seen_ev:
                    matched_inc.evidence.append(ev)
                    seen_ev.add(ev)
            self._save()
            return matched_inc

        # Create new standalone incident
        inc_num = len(self._incidents) + 1
        inc_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{inc_num:04d}"
        title = f"{source.upper()} {obs.decision_state.replace('_', ' ').title()} ({obs.risk_level.upper()})"
        new_inc = IncidentRecord(
            incident_id=inc_id,
            title=title,
            created_at=now_iso,
            updated_at=now_iso,
            severity=obs.risk_level,
            decision_state=obs.decision_state,
            confidence=round(obs.supervised_probability, 4),
            limitations=limitations,
            observations=[obs],
            correlated_entities=[],
            timeline=[
                {
                    "timestamp": now_iso,
                    "event": f"[{source.upper()}] {obs.decision_state} detected by {detector_name} (score={obs.risk_score})",
                }
            ],
            evidence=list(obs.evidence),
            recommended_action=obs.recommended_action,
        )
        self._incidents.append(new_inc)
        if len(self._incidents) > self.max_incidents:
            self._incidents = self._incidents[-self.max_incidents :]
        self._save()
        return new_inc

    def export_json(self, incident_id: str, redact: bool = True) -> Optional[str]:
        inc = self.get_incident(incident_id)
        if inc is None:
            return None
        data = inc.model_dump()
        if redact:
            for obs in data["observations"]:
                obs["raw_summary"] = redact_sensitive_text(obs["raw_summary"])
                obs["evidence"] = [redact_sensitive_text(e) for e in obs["evidence"]]
                if "ips" in obs.get("entities", {}):
                    obs["entities"]["ips"] = [redact_sensitive_text(ip) for ip in obs["entities"]["ips"]]
            data["evidence"] = [redact_sensitive_text(e) for e in data["evidence"]]
            data["timeline"] = [
                {"timestamp": t["timestamp"], "event": redact_sensitive_text(t["event"])}
                for t in data["timeline"]
            ]
            data["correlated_entities"] = [
                {
                    "relation_type": c["relation_type"],
                    "matched_value": redact_sensitive_text(c["matched_value"]),
                    "linked_observation": c["linked_observation"],
                }
                for c in data["correlated_entities"]
            ]
        data["redacted"] = redact
        return json.dumps(data, indent=2)

    def export_markdown(self, incident_id: str, redact: bool = True) -> Optional[str]:
        raw_json = self.export_json(incident_id, redact=redact)
        if raw_json is None:
            return None
        d = json.loads(raw_json)
        lines = [
            f"# SecureEdge AI Incident Report — {d['incident_id']}",
            "",
            "## Executive Summary",
            f"- **Title:** {d['title']}",
            f"- **Severity:** {d['severity'].upper()}",
            f"- **Decision State:** `{d['decision_state']}`",
            f"- **Confidence (Max Calibrated Prob):** {d['confidence']}",
            f"- **Created:** {d['created_at']}",
            f"- **Sensitive Data Redacted:** {'Yes' if redact else 'No'}",
            f"- **Recommended Action:** {d['recommended_action']}",
            "",
            "## Correlated Entities",
        ]
        if d["correlated_entities"]:
            for c in d["correlated_entities"]:
                lines.append(f"- `{c['relation_type']}`: `{c['matched_value']}` (Observation `{c['linked_observation']}`)")
        else:
            lines.append("- Single-observation incident (no cross-modality entity overlap).")

        lines.extend(["", "## Timeline"])
        for t in d["timeline"]:
            lines.append(f"- `{t['timestamp']}` — {t['event']}")

        lines.extend(["", "## Technical Evidence & Detector Metadata"])
        for obs in d["observations"]:
            lines.extend([
                f"### Observation `{obs['observation_id']}` ({obs['source'].upper()})",
                f"- **Detector:** `{obs['detector_name']}`",
                f"- **Operating Mode:** `{obs['operating_mode']}` | **LLM Used:** `{obs['llm_used']}` (`{obs['llm_backend']}`)",
                f"- **Risk Score:** {obs['risk_score']}/100 | **Supervised Prob:** {obs['supervised_probability']} | **Anomaly Score:** {obs['anomaly_score']}",
                f"- **Input Summary:** `{obs['raw_summary']}`",
                "- **Evidence:**",
            ])
            for ev in obs["evidence"]:
                lines.append(f"  - {ev}")

        lines.extend(["", "## Evaluation & Environment Limitations"])
        for lim in d["limitations"]:
            lines.append(f"- {lim}")
        return "\n".join(lines)
