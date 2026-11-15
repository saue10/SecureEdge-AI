#!/usr/bin/env bash
# ==============================================================================
# SecureEdge AI — Reproducible Linux / ARM64 Meta Llama 3.2 1B Instruct
# ExecuTorch (8da4w + XNNPACK) Export & Verification Procedure
# Bharat AI-SoC Challenge 2026-27 | Problem Statement 3 (PS3)
# ==============================================================================
set -euo pipefail

if [[ -z "${HF_TOKEN:-}" ]]; then
    echo "ERROR: HF_TOKEN is not set."
    echo "To export meta-llama/Llama-3.2-1B-Instruct:"
    echo "  1. Accept the Meta Llama 3.2 Community License on HuggingFace."
    echo "  2. Create a read-only access token at https://huggingface.co/settings/tokens"
    echo "  3. Export it in your shell (never commit tokens to Git):"
    echo "       export HF_TOKEN=hf_..."
    exit 1
fi

echo "[1/5] Creating Python 3.11/3.12 virtual environment (.venv_executorch)..."
python3 -m venv .venv_executorch
source .venv_executorch/bin/activate

echo "[2/5] Installing SecureEdge AI dependencies + ExecuTorch + torchao..."
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt
pip install executorch torchao

echo "[3/5] Exporting meta-llama/Llama-3.2-1B-Instruct (8da4w + XNNPACK)..."
mkdir -p models/llama_executorch/tokenizer_llama_3_2_1b
python -c "
from transformers import AutoTokenizer
tok = AutoTokenizer.from_pretrained('meta-llama/Llama-3.2-1B-Instruct')
tok.save_pretrained('models/llama_executorch/tokenizer_llama_3_2_1b')
"

python -m executorch.examples.models.llama.export_llama \
  --model llama3_2 \
  --checkpoint meta-llama/Llama-3.2-1B-Instruct \
  -q 8da4w \
  -d xnnpack \
  -o models/llama_executorch/llama_3_2_1b_8da4w.pte

echo "[4/5] Verifying ExecuTorch runtime & ARM64 readiness..."
python deployment/arm64/verify_arm64_executorch.py

echo "[5/5] Running full end-to-end test suite..."
python -m unittest discover -s tests -p "test_*.py" -v
