"""
Standalone Llama-family ExecuTorch Export Script for SecureEdge AI.
Exports HuggingFaceTB/SmolLM2-135M-Instruct (default ungated 135M LlamaForCausalLM)
or meta-llama/Llama-3.2-1B-Instruct (when HF_TOKEN is configured) to .pte and .pt2.
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import ensure_directories
from src.executorch.exporter import DEFAULT_PRETRAINED_LLAMA_ID, LlamaExecuTorchExporter


def main() -> None:
    parser = argparse.ArgumentParser(description="Export pretrained Llama-family model to ExecuTorch .pte")
    parser.add_argument(
        "--model-id",
        default=DEFAULT_PRETRAINED_LLAMA_ID,
        help="HuggingFace model ID (e.g. HuggingFaceTB/SmolLM2-135M-Instruct or meta-llama/Llama-3.2-1B-Instruct)",
    )
    parser.add_argument("--seq-len", type=int, default=96, help="Static sequence length for ExecuTorch export")
    args = parser.parse_args()

    ensure_directories()
    meta = LlamaExecuTorchExporter.export_pretrained_llama(model_id=args.model_id, seq_len=args.seq_len)
    print(f"Exported {meta['model_id']} ({meta['parameter_count']:,} params) -> {meta['pte_artifact_path']} ({meta['pte_size_mb']} MB, {meta['graph_node_count']} nodes)")


if __name__ == "__main__":
    main()
