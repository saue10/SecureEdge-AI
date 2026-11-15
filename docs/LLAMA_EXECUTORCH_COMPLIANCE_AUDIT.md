# SecureEdge AI — Evidence-Based Llama & ExecuTorch Compliance Audit

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 (PS3)  
**Audited Commit:** `4c005b3` (branch `main`)  
**Audit Date:** 15 November 2026  

---

## 1. Strict Separation of Verified Status

| Category | Status | Evidence |
| :--- | :---: | :--- |
| **Code Implemented** | ✅ Yes | `src/url_detection/`, `src/sms_detection/`, `src/network_detection/`, `src/threat_engine/`, `src/executorch/exporter.py`, `src/executorch/runtime.py`, `src/llama/advisor.py`, `app/main.py`, `deployment/` |
| **Tests Passed (16/16)** | ✅ Yes (`SmolLM2-135M` + 3 Detectors) | `python -m unittest discover -s tests -p "test_*.py" -v` — 16/16 tests pass using `HuggingFaceTB/SmolLM2-135M-Instruct` comparison artifact |
| **Meta Llama 3.2 1B Export Completed** | ❌ No (Blocked) | `meta-llama/Llama-3.2-1B-Instruct` is `gated=manual` (`HF token present: False`); `executorch` + `torchao` cannot install/run on this Windows 11 host |
| **Native ExecuTorch Runtime Inference Completed** | ❌ No (Blocked) | `executorch` is not installed on Windows (`torch>=2.10.0` fails `c10.dll`/`torch_cpu.dll` init); runtime executes `torch.export.ExportedProgram.module()` on host |
| **Physical ARM64 Hardware Inference Completed** | ❌ No (Pending Hardware) | No physical Raspberry Pi 5 / Android board attached (`HOST_PREPARED_PENDING_PHYSICAL_ARM64_BOARD`) |

---

## 2. Component Inspection & API/Version Compatibility Findings

### 2.1 Package & Environment Compatibility (Windows 11 `amd64`)
- **Installed:** `Python 3.13.2`, `torch 2.8.0+cpu`, `transformers 5.17.0`, `huggingface_hub 1.32.0`, `scikit-learn 1.8.0`, `scapy 2.6.1`.
- **Not Installed / Incompatible:** `executorch` (PyPI `1.1.0`–`1.6.0` require `torch >= 2.10.0`, which failed Windows DLL init `WinError 1114`/`126` on `c10.dll`/`torch_cpu.dll` on this host), `torchao` (not installed), `docker` (not installed), `wsl` (`Wsl/E_ACCESSDENIED`).

### 2.2 Exporter (`src/executorch/exporter.py`)
- **Verified:** `LlamaExecuTorchExporter.export_pretrained_llama()` supports `quantization="8da4w"` via `torchao.quantization.Int8DynamicActivationInt4WeightConfig(group_size=32)` and lowers via `to_edge_transform_and_lower(exported_program, partitioner=[XnnpackPartitioner()])` when `executorch.exir` is present.
- **Audit Findings (Disclosed):**
  1. `export_llama_to_pte()` line 204 records `"quantization": "float32 (...)"` statically rather than propagating the `quantization` parameter (`"8da4w"` vs `"float32"`).
  2. `Int8DynamicActivationInt4WeightConfig` requires `torchao >= 0.10` + `torch >= 2.10` on Linux/ARM64; it is not installed on this Windows host.

### 2.3 Runtime & Advisor (`src/executorch/runtime.py`, `src/llama/advisor.py`)
- **Verified:** `ExecuTorchLlamaRuntime` checks `OFFICIAL_META_LLAMA_PTE` (`models/llama_executorch/llama_3_2_1b_8da4w.pte`) first and only falls back to `DEFAULT_PTE_PATH` (`smollm2_135m_cyber_advisor.pte`) when the Meta Llama `.pte` is absent. `LlamaCyberAdvisor` strictly loads offline tokenizers (`local_files_only=True`) and locks `risk_level` to the detector verdict.
- **Audit Findings (Disclosed for Linux/ARM64 Integration):**
  1. **Signature Mismatch with `export_llama`:** `deployment/linux/export_meta_llama_executorch.sh` invokes `executorch.examples.models.llama.export_llama` (which exports a KV-cache stateful graph taking `(tokens, input_pos)`), whereas `ExecuTorchLlamaRuntime.forward_Step()` passes a stateless `(1, seq_len)` `[input_ids]` tensor (matching `LlamaExecuTorchExporter.export_pretrained_llama(..., quantization="8da4w")`). On Linux/ARM64, exporting via `LlamaExecuTorchExporter.export_pretrained_llama("meta-llama/Llama-3.2-1B-Instruct", quantization="8da4w")` matches `ExecuTorchLlamaRuntime` directly, whereas `export_llama` requires `executorch.extension.llm.runner`.
  2. **Metadata Fallback:** If `llama_3_2_1b_8da4w.pte` exists without `llama_3_2_1b_export_metadata.json`, `ExecuTorchLlamaRuntime` falls back to `export_metadata.json` (`SmolLM2-135M-Instruct` metadata).
  3. **Llama 3.2 `eos_token_id`:** `Llama-3.2-1B-Instruct` can expose `eos_token_id` as a list `[128001, 128008, 128009]` in `generation_config.json`; `advisor.py` line 115 calls `int(getattr(self.tokenizer, "eos_token_id", 2) or 2)` which assumes a scalar integer.

### 2.4 Linux Script & ARM64 Dockerfile (`deployment/linux/export_meta_llama_executorch.sh`, `deployment/arm64/Dockerfile.arm64`)
- Both install `executorch` + `torchao` cleanly on Linux `x86_64` / `aarch64` (Python 3.11/3.12), require `HF_TOKEN` via environment variable (never stored in repo), and run `verify_arm64_executorch.py` + `unittest`.

---

## 3. Authentication Instructions (When Running on Linux / ARM64)

1. Accept the **Meta Llama 3.2 Community License** on HuggingFace for `meta-llama/Llama-3.2-1B-Instruct`.
2. Generate a read-only access token in your HuggingFace account settings.
3. Export it in your Linux/Raspberry Pi 5 shell (never commit tokens to Git):
   ```bash
   export HF_TOKEN=<your_token>
   bash deployment/linux/export_meta_llama_executorch.sh
   ```
