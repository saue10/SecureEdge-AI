"""
SecureEdge AI — Professional Local Cybersecurity Dashboard Server (Flask + REST API).
Provides all 8 required competition sections with 100% offline capability:
1. Dashboard Overview
2. URL Phishing Scanner
3. SMS Scam Detector
4. Network Monitor (Passive Live Scapy Capture + Labelled PCAP Replay Mode)
5. AI Threat Explanation (Local Llama + ExecuTorch Inspector)
6. Detection History
7. System Information (Real Host & ARM Target Status)
8. Edge Performance Benchmarks
"""

import json
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import cpuinfo
from flask import Flask, jsonify, render_template, request, send_from_directory
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import (
    BENCHMARKS_DIR,
    FIGURES_DIR,
    HOST_ARCH,
    HOST_OS,
    IS_ARM,
    LLAMA_MODEL_DIR,
    METRICS_DIR,
    NETWORK_MODEL_DIR,
    SMS_MODEL_DIR,
    URL_MODEL_DIR,
)
from src.common.logger import get_logger
from src.common.schemas import LlamaExplanationInput
from src.network_detection.collector import ScapyFlowCollector
from src.threat_engine.engine import UnifiedThreatEngine

logger = get_logger("SecureEdge.WebApp")

app = Flask(
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
    static_folder=str(Path(__file__).resolve().parent / "static"),
)

engine = UnifiedThreatEngine()


def check_internet_connectivity() -> str:
    """Detect whether external internet is reachable or if operating in Offline Air-Gapped Mode."""
    try:
        sock = socket.create_connection(("1.1.1.1", 53), timeout=0.6)
        sock.close()
        return "ONLINE (Local Inference Active — Zero Cloud Calls)"
    except OSError:
        return "OFFLINE AIR-GAPPED MODE (100% Local On-Device Execution)"


def get_system_telemetry() -> Dict[str, Any]:
    """Gather genuine live hardware, memory, model, and ExecuTorch runtime status."""
    vm = psutil.virtual_memory()
    proc = psutil.Process()
    cpu_brand = cpuinfo.get_cpu_info().get("brand_raw", platform.processor())
    pte_status = engine.llama_advisor.runtime.verify_pte_artifact()

    return {
        "project_name": "SECUREEDGE AI",
        "tagline": "Your Security. Your Device. Your Privacy.",
        "connectivity_mode": check_internet_connectivity(),
        "os": platform.platform(),
        "architecture": HOST_ARCH,
        "is_arm_hardware": IS_ARM,
        "hardware_mode_label": (
            "Physical/Native ARM64 Edge Target"
            if IS_ARM
            else f"x86_64 Host Prototype ({HOST_ARCH}-{HOST_OS}) — ARM64 Deployment Package Ready"
        ),
        "cpu_model": cpu_brand,
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_available_gb": round(vm.available / (1024**3), 2),
        "ram_percent": vm.percent,
        "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
        "python_version": platform.python_version(),
        "models_status": {
            "url_detector": {
                "loaded": engine.url_detector.pipeline is not None,
                "version": engine.url_detector.model_version,
                "calibrated": engine.url_detector.is_calibrated,
                "artifact": str((URL_MODEL_DIR / "url_detector_pipeline.joblib").name),
            },
            "sms_detector": {
                "loaded": engine.sms_detector.classifier is not None,
                "version": engine.sms_detector.model_version,
                "calibrated": engine.sms_detector.is_calibrated,
                "artifact": str((SMS_MODEL_DIR / "sms_detector_pipeline.joblib").name),
            },
            "network_detector": {
                "loaded": engine.network_detector.pipeline is not None,
                "version": engine.network_detector.model_version,
                "calibrated": engine.network_detector.is_calibrated,
                "artifact": str((NETWORK_MODEL_DIR / "network_detector_pipeline.joblib").name),
            },
            "llama_executorch": {
                "loaded": engine.llama_advisor.runtime.is_loaded,
                "runtime_backend": engine.llama_advisor.runtime.runtime_backend,
                "pte_verified": pte_status.get("verified", False),
                "pte_size_mb": pte_status.get("size_mb", 0.0),
                "pte_format": pte_status.get("format", "Unknown"),
                "artifact": str(engine.llama_advisor.runtime.pte_path.name),
            },
        },
    }


@app.route("/")
def index() -> str:
    """Render the main SecureEdge AI dark cybersecurity dashboard."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def api_status() -> Any:
    """Return system status, history summary statistics, and runtime readiness."""
    history = engine.get_history()
    total_scans = len(history)
    malicious_count = sum(1 for r in history if r.get("classification") == "malicious")
    suspicious_count = sum(1 for r in history if r.get("classification") == "suspicious")
    benign_count = sum(1 for r in history if r.get("classification") == "benign")

    by_source = {"url": 0, "sms": 0, "network": 0}
    by_risk = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for r in history:
        src = r.get("source", "url")
        if src in by_source:
            by_source[src] += 1
        rl = r.get("risk_level", "low")
        if rl in by_risk:
            by_risk[rl] += 1

    return jsonify(
        {
            "system": get_system_telemetry(),
            "summary": {
                "total_scans": total_scans,
                "malicious_detections": malicious_count,
                "suspicious_detections": suspicious_count,
                "benign_detections": benign_count,
                "threat_detections": malicious_count + suspicious_count,
                "by_source": by_source,
                "by_risk_level": by_risk,
                "latest_scan": history[-1] if history else None,
            },
        }
    )


@app.route("/api/scan/url", methods=["POST"])
def api_scan_url() -> Any:
    """Execute real-time Phishing URL Detection + Llama ExecuTorch Explanation."""
    payload = request.get_json(silent=True) or {}
    raw_url = str(payload.get("url", ""))[:4096].strip()
    explain = bool(payload.get("explain", True))

    report = engine.analyze_url(raw_url, explain=explain, persist_history=True)
    return jsonify(report.model_dump())


@app.route("/api/scan/sms", methods=["POST"])
def api_scan_sms() -> Any:
    """Execute real-time Scam/Spam SMS Detection + Llama ExecuTorch Explanation."""
    payload = request.get_json(silent=True) or {}
    raw_sms = str(payload.get("sms_text", ""))[:10000].strip()
    explain = bool(payload.get("explain", True))

    report = engine.analyze_sms(raw_sms, explain=explain, persist_history=True)
    return jsonify(report.model_dump())


@app.route("/api/scan/network", methods=["POST"])
def api_scan_network() -> Any:
    """
    Execute Network Flow Anomaly Detection in either:
    - 'replay_demo': Reads real Scapy packets from sample_network_traffic.pcap or custom flow JSON.
    - 'live_capture': Attempts passive Scapy sniff() on the host interface, clearly reporting if
      Npcap/root privileges are unavailable without faking live traffic.
    """
    payload = request.get_json(silent=True) or {}
    mode_requested = payload.get("mode", "replay_demo")

    if mode_requested == "live_capture":
        flows, capture_status = ScapyFlowCollector.capture_live_flows(duration_sec=1.5, max_packets=40)
        if not flows:
            return jsonify(
                {
                    "status": "live_capture_unavailable",
                    "capture_status": capture_status,
                    "message": (
                        "Passive live packet capture returned no IP packets or requires Npcap/Administrator privileges "
                        "on this host. Use the clearly labelled Scapy PCAP Replay Mode or Custom Flow Inspector."
                    ),
                    "reports": [],
                }
            )
        reports = [
            engine.analyze_network_flow(fl, explain=True, execution_mode="live_inference", persist_history=True).model_dump()
            for fl in flows[:6]
        ]
        return jsonify({"status": "ok", "capture_status": "live_inference", "reports": reports})

    if mode_requested == "custom_flow" and isinstance(payload.get("flow"), dict):
        rep = engine.analyze_network_flow(
            payload["flow"], explain=True, execution_mode="replay_demo", persist_history=True
        )
        return jsonify({"status": "ok", "capture_status": "replay_demo", "reports": [rep.model_dump()]})

    # Default: Replay flows extracted from the reference Scapy PCAP file
    pcap_flows = ScapyFlowCollector.load_flows_from_pcap()
    reports = [
        engine.analyze_network_flow(fl, explain=True, execution_mode="replay_demo", persist_history=True).model_dump()
        for fl in pcap_flows
    ]
    return jsonify(
        {
            "status": "ok",
            "capture_status": "replay_demo (Scapy PCAP: sample_network_traffic.pcap)",
            "reports": reports,
        }
    )


@app.route("/api/explain", methods=["POST"])
def api_explain() -> Any:
    """Direct interface to test the bounded Llama + ExecuTorch Cybersecurity Advisor."""
    payload = request.get_json(silent=True) or {}
    try:
        llama_in = LlamaExplanationInput(
            threat_type=str(payload.get("threat_type", "phishing")),
            risk_level=payload.get("risk_level", "high"),
            confidence=float(payload.get("confidence", 0.94)),
            evidence=payload.get(
                "evidence",
                ["Suspicious URL structure", "Credential-related path", "Unusual hostname characteristics"],
            ),
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
    """Retrieve or clear local detection history."""
    if request.method == "DELETE":
        engine.clear_history()
        return jsonify({"status": "cleared", "history": []})
    history = engine.get_history()
    return jsonify({"status": "ok", "count": len(history), "history": list(reversed(history))})


@app.route("/api/benchmarks", methods=["GET"])
def api_benchmarks() -> Any:
    """Return recorded training metrics, model comparison tables, and edge hardware benchmarks."""
    metrics_path = METRICS_DIR / "training_and_evaluation_metrics.json"
    bench_path = BENCHMARKS_DIR / "edge_performance_benchmarks.json"
    arm_path = BENCHMARKS_DIR / "arm64_verification_status.json"

    metrics_data = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}
    bench_data = json.loads(bench_path.read_text(encoding="utf-8")) if bench_path.exists() else {}
    arm_data = json.loads(arm_path.read_text(encoding="utf-8")) if arm_path.exists() else {}

    return jsonify(
        {
            "training_metrics": metrics_data,
            "edge_benchmarks": bench_data,
            "arm64_verification": arm_data,
        }
    )


@app.route("/api/figures/<path:filename>", methods=["GET"])
def api_figures(filename: str) -> Any:
    """Serve generated evaluation figures from evaluation/figures/."""
    return send_from_directory(str(FIGURES_DIR), filename)


def run_server(host: str = "127.0.0.1", port: int = 8501, debug: bool = False) -> None:
    """Start the local SecureEdge AI Flask server."""
    logger.info("Starting SECUREEDGE AI Dashboard on http://%s:%d", host, port)
    app.run(host=host, port=port, debug=debug, use_reloader=False)


if __name__ == "__main__":
    run_server()
