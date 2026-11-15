"""Local runtime engine for executing exported Llama .pte / ExportedProgram graphs."""

import io
import json
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import torch

from src.common.config import HOST_ARCH, HOST_OS, LLAMA_MODEL_DIR
from src.common.logger import get_logger
from src.executorch.exporter import PTE_MAGIC_HEADER

logger = get_logger("SecureEdge.ExecuTorchRuntime")


class ExecuTorchLlamaRuntime:
    """
    Executes local Llama causal inference using the exported ExecuTorch (.pte / .pt2) static graph.
    Supports native C++ executorch.runtime on ARM64/Linux and torch.export.ExportedProgram static
    graph execution on Windows Python 3.13 hosts.
    """

    DEFAULT_PTE_PATH = LLAMA_MODEL_DIR / "llama_3_2_cyber_advisor.pte"
    DEFAULT_PT2_PATH = LLAMA_MODEL_DIR / "llama_3_2_cyber_advisor.pt2"
    DEFAULT_META_PATH = LLAMA_MODEL_DIR / "export_metadata.json"

    def __init__(
        self,
        pte_path: Optional[Path] = None,
        pt2_path: Optional[Path] = None,
        meta_path: Optional[Path] = None,
    ) -> None:
        self.pte_path = Path(pte_path) if pte_path else self.DEFAULT_PTE_PATH
        self.pt2_path = Path(pt2_path) if pt2_path else self.DEFAULT_PT2_PATH
        self.meta_path = Path(meta_path) if meta_path else self.DEFAULT_META_PATH

        self.exported_program: Any = None
        self.compiled_module: Any = None
        self.native_et_program: Any = None
        self.metadata: Dict[str, Any] = {}
        self.seq_len: int = 64
        self.runtime_backend: str = "Uninitialized"
        self.is_loaded: bool = False
        self.load()

    def verify_pte_artifact(self) -> Dict[str, Any]:
        """Verify that the .pte artifact exists on disk and inspect its header/integrity."""
        if not self.pte_path.exists():
            return {"verified": False, "reason": f"Missing .pte artifact at {self.pte_path}"}

        size_bytes = self.pte_path.stat().st_size
        if size_bytes < 64:
            return {"verified": False, "reason": "Corrupted or empty .pte file"}

        with open(self.pte_path, "rb") as f:
            head = f.read(8)
            if head == PTE_MAGIC_HEADER:
                hdr_len = struct.unpack("<I", f.read(4))[0]
                hdr_json = json.loads(f.read(hdr_len).decode("utf-8"))
                return {
                    "verified": True,
                    "format": hdr_json.get("format", "ExecuTorch-PTE"),
                    "size_bytes": size_bytes,
                    "size_mb": round(size_bytes / (1024 * 1024), 3),
                    "header": hdr_json,
                }
            # Native FlatBuffer .pte starts with 4-byte root offset followed by "ET12" magic at offset 4
            if b"ET" in head:
                return {
                    "verified": True,
                    "format": "ExecuTorch-Native-FlatBuffer-PTE",
                    "size_bytes": size_bytes,
                    "size_mb": round(size_bytes / (1024 * 1024), 3),
                }

        return {"verified": False, "reason": "Unrecognized .pte header signature"}

    def load(self) -> bool:
        """Load the exported Llama graph artifact from disk."""
        if self.meta_path.exists():
            try:
                self.metadata = json.loads(self.meta_path.read_text(encoding="utf-8"))
                self.seq_len = int(self.metadata.get("max_seq_len", 64))
            except Exception:
                self.metadata = {}

        if not self.pte_path.exists() and not self.pt2_path.exists():
            self.is_loaded = False
            self.runtime_backend = "Artifact-Missing"
            return False

        # 1. Try native ExecuTorch C++ pybindings if installed (e.g. on Linux / ARM64)
        try:
            from executorch.runtime import Runtime  # type: ignore

            rt = Runtime.get()
            prog = rt.load_program(str(self.pte_path))
            self.native_et_program = prog.load_method("forward")
            self.runtime_backend = f"ExecuTorch-Native-Runtime ({HOST_ARCH})"
            self.is_loaded = True
            logger.info("Loaded native ExecuTorch .pte program from %s", self.pte_path)
            return True
        except Exception:
            pass

        # 2. Load the torch.export.ExportedProgram from the .pte container or .pt2 archive
        try:
            if self.pt2_path.exists():
                self.exported_program = torch.export.load(str(self.pt2_path))
            elif self.pte_path.exists():
                with open(self.pte_path, "rb") as f:
                    magic = f.read(8)
                    if magic == PTE_MAGIC_HEADER:
                        hdr_len = struct.unpack("<I", f.read(4))[0]
                        _ = f.read(hdr_len)
                        payload_len = struct.unpack("<Q", f.read(8))[0]
                        pt2_bytes = f.read(payload_len)
                        buf = io.BytesIO(pt2_bytes)
                        self.exported_program = torch.export.load(buf)

            if self.exported_program is not None:
                self.compiled_module = self.exported_program.module()
                self.runtime_backend = f"ExecuTorch-ExportedProgram-Graph ({HOST_ARCH}-{HOST_OS})"
                self.is_loaded = True
                logger.info("Loaded exported Llama static graph (%s)", self.runtime_backend)
                return True
        except Exception as exc:
            logger.error("Failed to load exported Llama graph: %s", exc)

        self.is_loaded = False
        self.runtime_backend = "Load-Error"
        return False

    def forward_Step(self, input_ids: torch.Tensor) -> torch.Tensor:
        """Execute a single static-shape forward pass through the exported Llama graph."""
        if not self.is_loaded:
            raise RuntimeError("ExecuTorchLlamaRuntime is not loaded.")

        if self.native_et_program is not None:
            outputs = self.native_et_program.execute([input_ids])
            return outputs[0]

        with torch.no_grad():
            return self.compiled_module(input_ids)

    def generate_tokens(
        self,
        prompt_token_ids: List[int],
        max_new_tokens: int = 24,
        eos_token_id: int = 2,
        pad_token_id: int = 0,
    ) -> Tuple[List[int], Dict[str, float]]:
        """
        Run greedy autoregressive token generation over the fixed-shape (1, seq_len) exported Llama graph.
        Returns (generated_token_ids, performance_metrics).
        """
        if not self.is_loaded:
            raise RuntimeError("ExecuTorchLlamaRuntime is not loaded.")

        proc = psutil.Process()
        rss_before_mb = proc.memory_info().rss / (1024 * 1024)
        t0 = time.perf_counter()

        seq = list(prompt_token_ids)[: self.seq_len - 1]
        if not seq:
            seq = [1]  # BOS token

        generated: List[int] = []
        steps_executed = 0

        for _ in range(max_new_tokens):
            cur_len = len(seq)
            if cur_len >= self.seq_len:
                break

            # Pad sequence to fixed static graph length (1, self.seq_len)
            padded = seq + [pad_token_id] * (self.seq_len - cur_len)
            input_tensor = torch.tensor([padded], dtype=torch.long)

            logits = self.forward_Step(input_tensor)
            next_token_logits = logits[0, cur_len - 1, :]
            next_token = int(torch.argmax(next_token_logits).item())

            steps_executed += 1
            if next_token == eos_token_id:
                break
            seq.append(next_token)
            generated.append(next_token)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        rss_after_mb = proc.memory_info().rss / (1024 * 1024)
        tokens_per_sec = (steps_executed / max(elapsed_ms / 1000.0, 1e-6)) if steps_executed > 0 else 0.0

        perf = {
            "latency_ms": round(elapsed_ms, 3),
            "steps_executed": float(steps_executed),
            "tokens_per_sec": round(tokens_per_sec, 2),
            "rss_memory_mb": round(rss_after_mb, 2),
            "rss_delta_mb": round(max(0.0, rss_after_mb - rss_before_mb), 3),
        }
        return generated, perf
