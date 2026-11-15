#!/usr/bin/env bash
# ==============================================================================
# SecureEdge AI — ARM64 Android (Termux / Proot-Distro) Setup Script
# Bharat AI-SoC Challenge 2026-27 | Problem Statement 3 (PS3)
# ==============================================================================
set -euo pipefail

echo "[SecureEdge AI] Preparing ARM64 Android Edge Environment..."
echo "Architecture: $(uname -m)"

pkg update -y
pkg install -y python clang cmake libpcap git rust ninja

python -m venv .venv_android
source .venv_android/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python deployment/arm64/verify_arm64_executorch.py
echo "Launch local web UI on Android browser (http://127.0.0.1:8501):"
echo "  python scripts/run_application.py --host 127.0.0.1 --port 8501"
