#!/usr/bin/env bash
# ==============================================================================
# SecureEdge AI — Lightweight ARM64 Android Termux Setup (FAST TRIAGE)
# Uses Termux prebuilt numpy/scipy to avoid slow source builds on phone.
# ==============================================================================
set -euo pipefail

echo "[1/5] Architecture: $(uname -m)"
pkg update -y
pkg install -y python git python-numpy python-scipy libpcap

echo "[2/5] Creating virtual environment reusing Termux numpy/scipy..."
python -m venv .venv_android --system-site-packages
source .venv_android/bin/activate

echo "[3/5] Installing lightweight FAST TRIAGE dependencies..."
pip install --upgrade pip
pip install -r requirements-arm-lite.txt

echo "[4/5] Running ARM64 smoke test..."
python scripts/arm_smoke_test.py

echo "[5/5] Ready! Start the offline dashboard with:"
echo "  python scripts/run_application.py --host 127.0.0.1 --port 8501"
