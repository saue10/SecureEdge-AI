"""
SecureEdge AI — Competition-Grade Local Cybersecurity Dashboard Server (Flask + REST API).

Primary unified interface supporting:
1. Security Overview
2. URL Threat Scanner (Hardened Phase 3 + Calibrated Policy)
3. SMS Scam Analyzer (Hardened Phase 3 + Calibrated Policy)
4. Network Traffic Analyzer (Context-Aware Phase 3 + False-Positive Reduction)
5. PCAP Upload & Analysis (Bounded, magic-byte validated, temp-isolated)
6. Unified Threat Intelligence (FAST TRIAGE default; optional DEEP ANALYSIS with fallback)
7. Incident History & Cross-Modality Correlation
8. Incident Detail, Evidence & Redacted JSON/Markdown Report Export
9. Performance & Benchmark Dashboard (Phase 1, 2, 3 verified metrics)
10. System & Offline Status (honest hardware & model provenance)
"""

import json
import os
import platform
import socket
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import cpuinfo
import joblib
import psutil
from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import (
    BENCHMARKS_DIR,
    FIGURES_DIR,
    HOST_ARCH,
    HOST_OS,
    IS_ARM,
    METRICS_DIR,
    NETWORK_MODEL_DIR,
    SMS_MODEL_DIR,
    URL_MODEL_DIR,
)
from src.common.logger import get_logger
from src.common.schemas import LlamaExplanationInput
from src.network_detection.collector import ScapyFlowCollector
from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.hardened import HardenedSMSDetector
from src.threat_engine.calibrated_policy import CalibratedThreatEngine
from src.threat_engine.demo_scenarios import DEMO_SCENARIOS
from src.threat_engine.engine import UnifiedThreatEngine
from src.threat_engine.incidents import IncidentCorrelationEngine
from src.url_detection.hardened import HardenedURLDetector

logger = get_logger("SecureEdge.WebApp")

MAX_URL_LENGTH = 2048
MAX_SMS_LENGTH = 5000
MAX_PCAP_BYTES = 2 * 1024 * 1024  # 2 MB
ALLOWED_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
PCAP_MAGIC_PREFIXES = (
    b"\xd4\xc3\xb2\xa1",  # PCAP little-endian
    b"\xa1\xb2\xc3\xd4",  # PCAP big-endian
    b"\x4d\x3c\xb2\xa1",  # PCAP nanosecond little-endian
    b"\xa1\xb2\x3c\x4d",  # PCAP nanosecond big-endian
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
)

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
    static_folder=str(Path(__file__).resolve().parent / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = MAX_PCAP_BYTES

# Legacy Phase 1/2 engine preserved for backward-compatible v1 API endpoints & tests
engine = UnifiedThreatEngine()


def _load_context_network_detector() -> ContextAwareNetworkDetector:
    model_path = PROJECT_ROOT / "models" / "network" / "network_context_aware.joblib"
    if model_path.exists():
        try:
            det = joblib.load(model_path)
            if isinstance(det, ContextAwareNetworkDetector) and det.is_fitted:
                logger.info("Loaded Phase 3 ContextAwareNetworkDetector from %s", model_path)
                return det
        except Exception as exc:
            logger.warning("Could not load %s (%s); using unfitted fallback.", model_path, exc)
    return ContextAwareNetworkDetector()


calibrated_engine = CalibratedThreatEngine(
    url_detector=HardenedURLDetector(PROJECT_ROOT / "models" / "url" / "url_hardened_pipeline.joblib"),
    sms_detector=HardenedSMSDetector(PROJECT_ROOT / "models" / "sms" / "sms_hardened_pipeline.joblib"),
    network_detector=_load_context_network_detector(),
    llama_advisor=None,
)
incident_engine = IncidentCorrelationEngine()


@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Attach defensive HTTP security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def handle_payload_too_large(_err: Any) -> Any:
    return jsonify({"status": "error", "message": "Upload exceeds 2 MB safety limit."}), 413


@app.errorhandler(404)
def handle_not_found(_err: Any) -> Any:
    return jsonify({"status": "error", "message": "Resource not found."}), 404


@app.errorhandler(500)
def handle_internal_error(_err: Any) -> Any:
    return jsonify({"status": "error", "message": "Internal processing error."}), 500


_CONNECTIVITY_TTL_SEC = 15.0
_CONNECTIVITY_CACHE: Dict[str, Any] = {"ts": 0.0, "value": None}

try:
    _CACHED_CPU_BRAND: str = cpuinfo.get_cpu_info().get("brand_raw", platform.processor())
except Exception:
    _CACHED_CPU_BRAND = platform.processor()

# Prime psutil non-blocking CPU percent baseline at startup
psutil.cpu_percent(interval=None)


def check_internet_connectivity() -> str:
    """Detect whether external internet is reachable or operating in Offline Air-Gapped Mode."""
    now = time.monotonic()
    if _CONNECTIVITY_CACHE["value"] is not None and (now - _CONNECTIVITY_CACHE["ts"]) < _CONNECTIVITY_TTL_SEC:
        return str(_CONNECTIVITY_CACHE["value"])
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=0.5)
        sock.close()
        result = "ONLINE (Local Inference Active — Zero Automatic Remote Fetching)"
    except OSError:
        result = "OFFLINE AIR-GAPPED MODE (100% Local On-Device Execution)"
    _CONNECTIVITY_CACHE["ts"] = now
    _CONNECTIVITY_CACHE["value"] = result
    return result


def get_system_telemetry() -> Dict[str, Any]:
    """Gather genuine live hardware, memory, model, and ExecuTorch runtime status."""
    vm = psutil.virtual_memory()
    proc = psutil.Process()
    cpu_brand = _CACHED_CPU_BRAND
    active_advisor = calibrated_engine._llama_advisor or engine._llama_advisor
    if active_advisor is not None:
        pte_status = active_advisor.runtime.verify_pte_artifact()
        llama_loaded = active_advisor.runtime.is_loaded
        llama_backend = active_advisor.runtime.runtime_backend
        llama_artifact = str(active_advisor.runtime.pte_path.name)
    else:
        pte_file = PROJECT_ROOT / "models" / "llama_executorch" / "smollm2_135m_cyber_advisor.pte"
        pte_exists = pte_file.exists()
        pte_status = {
            "verified": pte_exists,
            "size_mb": round(pte_file.stat().st_size / (1024 * 1024), 3) if pte_exists else 0.0,
            "format": "ExecuTorch-PTE (Lazy-Ready)" if pte_exists else "Missing",
        }
        llama_loaded = False
        llama_backend = "Lazy-Ready (Zero RAM until DEEP ANALYSIS)"
        llama_artifact = pte_file.name

    return {
        "project_name": "SECUREEDGE AI",
        "tagline": "On-Device Calibrated Threat Intelligence — Localhost Only",
        "connectivity_mode": check_internet_connectivity(),
        "os": platform.platform(),
        "architecture": HOST_ARCH,
        "is_arm_hardware": IS_ARM,
        "hardware_mode_label": (
            "Physical/Native ARM64 Edge Target"
            if IS_ARM
            else f"x86_64 Host Prototype ({HOST_ARCH}-{HOST_OS}) — ARM64 Hardware Not Verified On This Device"
        ),
        "cpu_model": cpu_brand,
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_available_gb": round(vm.available / (1024**3), 2),
        "ram_percent": vm.percent,
        "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
        "python_version": platform.python_version(),
        "default_operating_mode": "fast_triage",
        "models_status": {
            "url_detector": {
                "loaded": calibrated_engine.url_detector.classifier is not None,
                "version": calibrated_engine.url_detector.model_version,
                "calibrated": calibrated_engine.url_detector.is_calibrated,
                "artifact": calibrated_engine.url_detector.model_path.name,
            },
            "sms_detector": {
                "loaded": calibrated_engine.sms_detector.classifier is not None,
                "version": calibrated_engine.sms_detector.model_version,
                "calibrated": calibrated_engine.sms_detector.is_calibrated,
                "artifact": calibrated_engine.sms_detector.model_path.name,
            },
            "network_detector": {
                "loaded": bool(calibrated_engine.network_detector and calibrated_engine.network_detector.is_fitted),
                "version": "network-context-aware-v3.0",
                "calibrated": bool(calibrated_engine.network_detector and calibrated_engine.network_detector.is_calibrated),
                "artifact": "network_context_aware.joblib",
            },
            "llama_executorch": {
                "loaded": llama_loaded,
                "runtime_backend": llama_backend,
                "comparison_model_note": "SmolLM2-135M-Instruct comparison static graph (Meta Llama 3.2 ExecuTorch .pte not executed on Windows)",
                "pte_verified": pte_status.get("verified", False),
                "pte_size_mb": pte_status.get("size_mb", 0.0),
                "pte_format": pte_status.get("format", "Unknown"),
                "artifact": llama_artifact,
            },
        },
    }


@app.route("/")
def index() -> str:
    """Render the unified SecureEdge AI cybersecurity dashboard."""
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Phase 4 v2 Product APIs (Hardened Detectors + Calibrated Policy + Incidents)
# ---------------------------------------------------------------------------


def _safe_mode(payload: Dict[str, Any]) -> str:
    mode = str(payload.get("mode", "fast_triage")).strip().lower()
    return "deep_analysis" if mode == "deep_analysis" else "fast_triage"


@app.route("/api/v2/analyze/url", methods=["POST"])
def api_v2_analyze_url() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", "") or "").strip()
    if len(raw_url) > MAX_URL_LENGTH:
        return jsonify({"status": "error", "message": f"URL exceeds {MAX_URL_LENGTH} character limit."}), 400
    mode = _safe_mode(payload)
    assessment = calibrated_engine.assess_url(raw_url, mode=mode).model_dump()
    incident = incident_engine.record_observation(
        source="url",
        raw_input=raw_url,
        assessment=assessment,
        detector_name=calibrated_engine.url_detector.model_version,
    )
    return jsonify({"status": "ok", "assessment": assessment, "incident": incident.model_dump()})


@app.route("/api/v2/analyze/sms", methods=["POST"])
def api_v2_analyze_sms() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_sms = str(payload.get("sms_text", "") or "").strip()
    if len(raw_sms) > MAX_SMS_LENGTH:
        return jsonify({"status": "error", "message": f"SMS exceeds {MAX_SMS_LENGTH} character limit."}), 400
    mode = _safe_mode(payload)
    assessment = calibrated_engine.assess_sms(raw_sms, mode=mode).model_dump()
    incident = incident_engine.record_observation(
        source="sms",
        raw_input=raw_sms,
        assessment=assessment,
        detector_name=calibrated_engine.sms_detector.model_version,
    )
    return jsonify({"status": "ok", "assessment": assessment, "incident": incident.model_dump()})


@app.route("/api/v2/analyze/network", methods=["POST"])
def api_v2_analyze_network() -> Any:
    payload = request.get_json(silent=True) or {}
    mode = _safe_mode(payload)
    flow = payload.get("flow")
    if not isinstance(flow, dict):
        return jsonify({"status": "error", "message": "Missing 'flow' JSON object."}), 400
    if not calibrated_engine.network_detector or not calibrated_engine.network_detector.is_fitted:
        return jsonify({"status": "error", "message": "ContextAwareNetworkDetector is not fitted."}), 503
    assessment = calibrated_engine.assess_network_flow(flow, mode=mode).model_dump()
    summary = f"{flow.get('src_ip', 'unknown')} -> {flow.get('dst_ip', 'unknown')} (dur={flow.get('flow_duration_sec', 0)}s, pkts={flow.get('packet_count', 0)})"
    incident = incident_engine.record_observation(
        source="network",
        raw_input=summary,
        assessment=assessment,
        detector_name="network-context-aware-v3.0",
        flow=flow,
    )
    return jsonify({"status": "ok", "assessment": assessment, "incident": incident.model_dump()})


@app.route("/api/v2/pcap/upload", methods=["POST"])
def api_v2_pcap_upload() -> Any:
    """Safely inspect an uploaded PCAP/PCAPNG file with size, extension, magic-byte, and temp-dir isolation."""
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No PCAP file provided in 'file' field."}), 400
    f = request.files["file"]
    filename = secure_filename(f.filename or "")
    if not filename or Path(filename).suffix.lower() not in ALLOWED_PCAP_EXTS:
        return jsonify({"status": "error", "message": "Invalid file type. Only .pcap, .pcapng, or .cap files are accepted."}), 400

    head = f.stream.read(4)
    f.stream.seek(0)
    if not any(head.startswith(magic) for magic in PCAP_MAGIC_PREFIXES):
        return jsonify({"status": "error", "message": "Invalid PCAP magic bytes."}), 400

    mode = "deep_analysis" if str(request.form.get("mode", "fast_triage")).lower() == "deep_analysis" else "fast_triage"

    with tempfile.TemporaryDirectory() as tmpdir:
        safe_path = Path(tmpdir) / filename
        f.save(str(safe_path))
        flows = ScapyFlowCollector.load_flows_from_pcap(pcap_path=safe_path)

    if not flows:
        return jsonify({"status": "ok", "flow_count": 0, "results": [], "message": "No IP flows parsed from PCAP."})

    results = []
    for fl in flows[:25]:
        assessment = calibrated_engine.assess_network_flow(fl, mode=mode).model_dump()
        summary = f"PCAP({filename}): {fl.get('src_ip', '?')} -> {fl.get('dst_ip', '?')}"
        inc = incident_engine.record_observation(
            source="network",
            raw_input=summary,
            assessment=assessment,
            detector_name="network-context-aware-v3.0",
            flow=fl,
        )
        results.append({"flow": fl, "assessment": assessment, "incident_id": inc.incident_id})

    return jsonify({"status": "ok", "filename": filename, "flow_count": len(results), "results": results})


@app.route("/api/v2/pcap/sample", methods=["POST"])
def api_v2_pcap_sample() -> Any:
    """Replay the bundled sample_network_traffic.pcap safely through Phase 3 ContextAwareNetworkDetector."""
    payload = request.get_json(silent=True) or {}
    mode = _safe_mode(payload)
    flows = ScapyFlowCollector.load_flows_from_pcap()
    results = []
    for fl in flows[:25]:
        assessment = calibrated_engine.assess_network_flow(fl, mode=mode).model_dump()
        summary = f"PCAP(sample_network_traffic.pcap): {fl.get('src_ip', '?')} -> {fl.get('dst_ip', '?')}"
        inc = incident_engine.record_observation(
            source="network",
            raw_input=summary,
            assessment=assessment,
            detector_name="network-context-aware-v3.0",
            flow=fl,
        )
        results.append({"flow": fl, "assessment": assessment, "incident_id": inc.incident_id})
    return jsonify({"status": "ok", "filename": "sample_network_traffic.pcap", "flow_count": len(results), "results": results})


@app.route("/api/v2/incidents", methods=["GET", "DELETE"])
def api_v2_incidents() -> Any:
    if request.method == "DELETE":
        incident_engine.clear()
        return jsonify({"status": "cleared", "incidents": []})
    incidents = [inc.model_dump() for inc in incident_engine.list_incidents()]
    return jsonify({"status": "ok", "count": len(incidents), "incidents": incidents})


@app.route("/api/v2/incidents/<incident_id>", methods=["GET"])
def api_v2_incident_detail(incident_id: str) -> Any:
    inc = incident_engine.get_incident(incident_id)
    if inc is None:
        return jsonify({"status": "error", "message": "Incident not found."}), 404
    return jsonify({"status": "ok", "incident": inc.model_dump()})


@app.route("/api/v2/incidents/<incident_id>/export", methods=["GET"])
def api_v2_incident_export(incident_id: str) -> Any:
    fmt = str(request.args.get("format", "json")).lower()
    redact = str(request.args.get("redact", "true")).lower() != "false"
    safe_id = secure_filename(incident_id)

    if fmt == "markdown":
        content = incident_engine.export_markdown(incident_id, redact=redact)
        if content is None:
            return jsonify({"status": "error", "message": "Incident not found."}), 404
        return Response(
            content,
            mimetype="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={safe_id}_report.md"},
        )

    content = incident_engine.export_json(incident_id, redact=redact)
    if content is None:
        return jsonify({"status": "error", "message": "Incident not found."}), 404
    return Response(
        content,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={safe_id}_report.json"},
    )


@app.route("/api/v2/demo/scenarios", methods=["GET"])
def api_v2_demo_scenarios() -> Any:
    return jsonify({"status": "ok", "scenarios": DEMO_SCENARIOS})


@app.route("/api/v2/demo/run", methods=["POST"])
def api_v2_demo_run() -> Any:
    payload = request.get_json(silent=True) or {}
    scenario_id = str(payload.get("scenario_id", "")).strip()
    mode = _safe_mode(payload)
    match = next((s for s in DEMO_SCENARIOS if s["id"] == scenario_id), None)
    if match is None:
        return jsonify({"status": "error", "message": "Unknown demonstration scenario ID."}), 404

    cat = match["category"]
    sc_payload = match["payload"]
    if cat == "url":
        raw = sc_payload["url"]
        assess = calibrated_engine.assess_url(raw, mode=mode).model_dump()
        inc = incident_engine.record_observation("url", raw, assess, calibrated_engine.url_detector.model_version)
    elif cat == "sms":
        raw = sc_payload["sms_text"]
        assess = calibrated_engine.assess_sms(raw, mode=mode).model_dump()
        inc = incident_engine.record_observation("sms", raw, assess, calibrated_engine.sms_detector.model_version)
    else:
        fl = sc_payload["flow"]
        raw = f"{fl.get('src_ip')} -> {fl.get('dst_ip')} ({match['title']})"
        assess = calibrated_engine.assess_network_flow(fl, mode=mode).model_dump()
        inc = incident_engine.record_observation("network", raw, assess, "network-context-aware-v3.0", flow=fl)

    return jsonify({"status": "ok", "scenario": match, "assessment": assess, "incident": inc.model_dump()})


@app.route("/api/v2/benchmarks", methods=["GET"])
def api_v2_benchmarks() -> Any:
    """Serve verified Phase 1, Phase 2, and Phase 3 evaluation & hardware benchmarks."""
    p3_path = PROJECT_ROOT / "results" / "phase3_hardening" / "phase3_results.json"
    p2_path = PROJECT_ROOT / "results" / "adaptive_threat_intelligence" / "phase2_results.json"
    p1_path = PROJECT_ROOT / "results" / "reliable_evaluation" / "reliable_evaluation_results.json"

    return jsonify(
        {
            "metadata": {
                "evaluation_date": "2026-11-15",
                "dataset_provenance": "Synthetic & curated local benchmarks (NOT real-world field validation)",
                "split_methodology": "SMS: exact-text deduplicated 70/15/15; URL: registered_domain group split 70/15/15; Network: known vs unseen scenario holdout; Validation split used exclusively for calibration",
                "hardware_used": "Windows 11, Intel Core i5-1135G7, ~8 GB RAM, CPU-only PyTorch 2.8.0+cpu",
                "llm_comparison_model": "HuggingFaceTB/SmolLM2-135M-Instruct (torch.export.ExportedProgram) — Meta Llama 3.2 ExecuTorch & ARM64 hardware not verified",
            },
            "phase3": json.loads(p3_path.read_text(encoding="utf-8")) if p3_path.exists() else {},
            "phase2": json.loads(p2_path.read_text(encoding="utf-8")) if p2_path.exists() else {},
            "phase1": json.loads(p1_path.read_text(encoding="utf-8")) if p1_path.exists() else {},
        }
    )


# ---------------------------------------------------------------------------
# Legacy v1 APIs preserved for backward compatibility
# ---------------------------------------------------------------------------


@app.route("/api/status", methods=["GET"])
def api_status() -> Any:
    """Return system status, history summary statistics, and runtime readiness."""
    incidents = incident_engine.list_incidents()
    history = engine.get_history()
    total_scans = len(incidents) if incidents else len(history)
    malicious_count = sum(1 for i in incidents if i.decision_state == "confirmed_malicious")
    suspicious_count = sum(1 for i in incidents if i.decision_state == "suspicious_unknown")
    benign_count = sum(1 for i in incidents if i.decision_state == "normal")
    abstained_count = sum(1 for i in incidents if i.decision_state == "insufficient_evidence")

    return jsonify(
        {
            "system": get_system_telemetry(),
            "summary": {
                "total_scans": total_scans,
                "total_incidents": len(incidents),
                "malicious_detections": malicious_count,
                "suspicious_detections": suspicious_count,
                "benign_detections": benign_count,
                "abstained_detections": abstained_count,
                "threat_detections": malicious_count + suspicious_count,
                "latest_incident": incidents[0].model_dump() if incidents else None,
            },
        }
    )


@app.route("/api/scan/url", methods=["POST"])
def api_scan_url() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", ""))[:MAX_URL_LENGTH].strip()
    explain = bool(payload.get("explain", True))
    report = engine.analyze_url(raw_url, explain=explain, persist_history=True)
    return jsonify(report.model_dump())


@app.route("/api/scan/sms", methods=["POST"])
def api_scan_sms() -> Any:
    payload = request.get_json(silent=True) or {}
    raw_sms = str(payload.get("sms_text", ""))[:MAX_SMS_LENGTH].strip()
    explain = bool(payload.get("explain", True))
    report = engine.analyze_sms(raw_sms, explain=explain, persist_history=True)
    return jsonify(report.model_dump())


@app.route("/api/scan/network", methods=["POST"])
def api_scan_network() -> Any:
    payload = request.get_json(silent=True) or {}
    mode_requested = payload.get("mode", "replay_demo")

    if mode_requested == "live_capture":
        flows, capture_status = ScapyFlowCollector.capture_live_flows(duration_sec=1.5, max_packets=40)
        if not flows:
            return jsonify(
                {
                    "status": "live_capture_unavailable",
                    "capture_status": capture_status,
                    "message": "Passive live packet capture requires Npcap/Administrator privileges; use PCAP Replay or Upload.",
                    "reports": [],
                }
            )
        reports = [
            engine.analyze_network_flow(fl, explain=True, execution_mode="live_inference", persist_history=True).model_dump()
            for fl in flows[:6]
        ]
        return jsonify({"status": "ok", "capture_status": "live_inference", "reports": reports})

    if mode_requested == "custom_flow" and isinstance(payload.get("flow"), dict):
        rep = engine.analyze_network_flow(payload["flow"], explain=True, execution_mode="replay_demo", persist_history=True)
        return jsonify({"status": "ok", "capture_status": "replay_demo", "reports": [rep.model_dump()]})

    pcap_flows = ScapyFlowCollector.load_flows_from_pcap()
    reports = [
        engine.analyze_network_flow(fl, explain=True, execution_mode="replay_demo", persist_history=True).model_dump()
        for fl in pcap_flows
    ]
    return jsonify({"status": "ok", "capture_status": "replay_demo (sample_network_traffic.pcap)", "reports": reports})


@app.route("/api/explain", methods=["POST"])
def api_explain() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        llama_in = LlamaExplanationInput(
            threat_type=str(payload.get("threat_type", "phishing")),
            risk_level=payload.get("risk_level", "high"),
            confidence=float(payload.get("confidence", 0.94)),
            evidence=payload.get("evidence", ["Suspicious URL structure", "Credential-related path"]),
        )
        llama_out = engine.llama_advisor.explain(llama_in)
        return jsonify(
            {
                "status": "ok",
                "structured_input": llama_in.model_dump(),
                "structured_output": llama_out.to_spec_dict(),
                "full_telemetry": llama_out.model_dump(),
                "perf_metrics": engine.llama_advisor.last_performance_metrics,
                "export_metadata": engine.llama_advisor.runtime.metadata,
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/api/history", methods=["GET", "DELETE"])
def api_history() -> Any:
    if request.method == "DELETE":
        engine.clear_history()
        return jsonify({"status": "cleared", "history": []})
    history = engine.get_history()
    return jsonify({"status": "ok", "count": len(history), "history": list(reversed(history))})


@app.route("/api/benchmarks", methods=["GET"])
def api_benchmarks() -> Any:
    metrics_path = METRICS_DIR / "training_and_evaluation_metrics.json"
    bench_path = BENCHMARKS_DIR / "edge_performance_benchmarks.json"
    arm_path = BENCHMARKS_DIR / "arm64_verification_status.json"
    return jsonify(
        {
            "training_metrics": json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {},
            "edge_benchmarks": json.loads(bench_path.read_text(encoding="utf-8")) if bench_path.exists() else {},
            "arm64_verification": json.loads(arm_path.read_text(encoding="utf-8")) if arm_path.exists() else {},
        }
    )


@app.route("/api/figures/<path:filename>", methods=["GET"])
def api_figures(filename: str) -> Any:
    return send_from_directory(str(FIGURES_DIR), filename)


def run_server(host: str = "127.0.0.1", port: int = 8501, debug: bool = False) -> None:
    """Start the local SecureEdge AI Flask server (localhost-only by default)."""
    logger.info("Starting SECUREEDGE AI Dashboard on http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    run_server()
