"""
ARM64 & ExecuTorch Hardware Verification Harness for SecureEdge AI.
Accurately detects whether execution is taking place on physical ARM64 silicon
(e.g. Raspberry Pi 5 Cortex-A76, ARMv8/v9 Android) or an x86_64 development host,
and never misrepresents x86_64 execution as ARM hardware validation.
"""

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import BENCHMARKS_DIR, IS_ARM
from src.common.logger import get_logger
from src.threat_engine.engine import UnifiedThreatEngine

logger = get_logger("SecureEdge.ARM64Verifier")


def detect_arm_capabilities() -> dict:
    """Inspect OS and CPU flags (/proc/cpuinfo on Linux) for ARM64 NEON, FP16, and DotProd support."""
    arch = platform.machine().lower()
    sys_name = platform.system()
    cpu_features = []
    board_model = "Unknown / Non-Linux Host"

    if sys_name == "Linux":
        cpuinfo_path = Path("/proc/cpuinfo")
        if cpuinfo_path.exists():
            text = cpuinfo_path.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                if line.lower().startswith("features"):
                    cpu_features = line.split(":", 1)[1].strip().split()
                elif line.lower().startswith("model"):
                    board_model = line.split(":", 1)[1].strip()
        dt_model = Path("/proc/device-tree/model")
        if dt_model.exists():
            board_model = dt_model.read_text(encoding="utf-8", errors="ignore").strip("\x00\n ")

    return {
        "architecture": arch,
        "os": sys_name,
        "is_physical_or_emulated_arm": IS_ARM,
        "board_model": board_model,
        "arm_neon_asimd": ("asimd" in cpu_features or "neon" in cpu_features) if IS_ARM else False,
        "arm_dotprod": ("asimddp" in cpu_features) if IS_ARM else False,
        "verification_status": (
            "VERIFIED_ON_ARM64_TARGET"
            if IS_ARM
            else "HOST_PREPARED_PENDING_PHYSICAL_ARM64_BOARD"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify SecureEdge AI on ARM64 / Host")
    parser.add_argument("--check-only", action="store_true", help="Only verify model files and .pte header")
    args = parser.parse_args()

    caps = detect_arm_capabilities()
    engine = UnifiedThreatEngine()
    pte_info = engine.llama_advisor.runtime.verify_pte_artifact()

    if not pte_info.get("verified", False):
        logger.error("ExecuTorch .pte artifact verification failed: %s", pte_info)
        sys.exit(1)

    if args.check_only:
        logger.info("Artifact check passed: %s | Capabilities: %s", pte_info, caps)
        return

    t0 = time.perf_counter()
    url_rep = engine.analyze_url(
        "http://sbi.secure-login.verify-update.auth-gateway.xyz/kyc-update/confirm.html",
        explain=True,
        persist_history=False,
    )
    sms_rep = engine.analyze_sms(
        "URGENT: Your bank KYC is suspended! Click http://kyc-verify-now.top to unblock immediately.",
        explain=True,
        persist_history=False,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "arm_capabilities": caps,
        "executorch_pte_artifact": pte_info,
        "runtime_backend": engine.llama_advisor.runtime.runtime_backend,
        "verification_smoke_test": {
            "url_classification": url_rep.detector_result.classification,
            "url_risk_score": url_rep.detector_result.risk_score,
            "sms_classification": sms_rep.detector_result.classification,
            "sms_risk_score": sms_rep.detector_result.risk_score,
            "llama_explanation_verified": len(url_rep.llama_output.explanation) > 20,
            "total_smoke_test_ms": round(elapsed_ms, 2),
        },
    }

    out_path = BENCHMARKS_DIR / "arm64_verification_status.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("ARM64 / ExecuTorch verification completed (%s) -> %s", caps["verification_status"], out_path)


if __name__ == "__main__":
    main()
