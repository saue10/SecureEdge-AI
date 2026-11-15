#!/usr/bin/env bash
# ==============================================================================
# SecureEdge AI — Raspberry Pi 5 (ARM64 Cortex-A76) Automated Setup Script
# Bharat AI-SoC Challenge 2026-27 | Problem Statement 3 (PS3)
# ==============================================================================
set -euo pipefail

echo "[SecureEdge AI] Detecting ARM64 Architecture and Board..."
ARCH=$(uname -m)
echo "Architecture: ${ARCH}"
if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "arm64" ]]; then
    echo "WARNING: Current machine (${ARCH}) is not an aarch64 board."
    echo "Proceeding in cross-platform dependency setup mode."
fi

if [[ -f /proc/device-tree/model ]]; then
    echo "Hardware Board: $(tr -d '\0' < /proc/device-tree/model)"
fi

echo "[1/5] Installing system packages (libpcap for Scapy, Python 3 venv, build tools)..."
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip python3-dev libpcap-dev tcpdump cmake build-essential

echo "[2/5] Creating isolated virtual environment (.venv_arm64)..."
python3 -m venv .venv_arm64
source .venv_arm64/bin/activate

echo "[3/5] Installing Python dependencies and PyTorch ExecuTorch (XNNPACK backend)..."
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
pip install executorch torchao || echo "Note: If using Python 3.13 on Debian testing, use Python 3.11/3.12 for prebuilt executorch wheels."

echo "[3b/5] Optional: Export official Meta Llama 3.2 1B Instruct (8da4w XNNPACK .pte) when HF_TOKEN is set..."
if [[ -n "${HF_TOKEN:-}" ]]; then
    echo "HF_TOKEN detected. Ready to export meta-llama/Llama-3.2-1B-Instruct via ExecuTorch (8da4w XNNPACK):"
    echo "  python -m executorch.examples.models.llama.export_llama --model llama3_2 --checkpoint meta-llama/Llama-3.2-1B-Instruct -q 8da4w -d xnnpack -o models/llama_executorch/llama_3_2_1b_8da4w.pte"
else
    echo "HF_TOKEN not set; using preserved lightweight comparison model (SmolLM2-135M-Instruct)."
fi

echo "[4/5] Verifying models and ExecuTorch .pte artifact..."
python deployment/arm64/verify_arm64_executorch.py

echo "[5/5] Running unit and integration test suite..."
python -m unittest discover -s tests -p "test_*.py" -v

echo "=============================================================================="
echo "SecureEdge AI is ready on Raspberry Pi 5!"
echo "Launch dashboard offline with:"
echo "  source .venv_arm64/bin/activate && python scripts/run_application.py"
echo "=============================================================================="
