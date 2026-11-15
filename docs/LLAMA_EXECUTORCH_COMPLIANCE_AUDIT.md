# SecureEdge AI — Llama & ExecuTorch Compliance Status Report

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 (PS3)  
**Audit Date:** 15 November 2026  
**Confirmed Phase 1 Submission Deadline:** 23 November 2026  

---

## 1. Executive Compliance Statement

This audit strictly distinguishes between **architecture-class similarity** and **authentic Meta Llama checkpoint provenance + native ExecuTorch runtime execution**:

1. **Preserved Lightweight Comparison Model (`HuggingFaceTB/SmolLM2-135M-Instruct`):**
   - Uses `transformers.LlamaForCausalLM` (`134,515,008` params, Apache-2.0), exported via `torch.export.export()` (`2,457` nodes, `520.94 MB` `.pte`/`.pt2`) and verified end-to-end (`16/16` tests pass).
   - **Important:** `SmolLM2-135M-Instruct` is a **SmolLM2-family** model, **not** an authentic Meta Llama checkpoint, and is **preserved strictly as a lightweight open-access comparison model**.
2. **Authentic Meta Llama Target (`meta-llama/Llama-3.2-1B-Instruct`):**
   - **Investigation & Verification Completed:** Verified gating, license, config, host disk/RAM, and ARM64 quantization specs.
   - **Current Status:** **BLOCKED ON WINDOWS 11 HOST** by three external/environmental constraints documented below. No fabricated inference or ARM64 execution is claimed.

---

## 2. Meta Llama 3.2 1B Instruct Investigation Findings

| Check | Observed Result |
| :--- | :--- |
| **Official Repo (`meta-llama/Llama-3.2-1B-Instruct`)** | `gated=manual`, `private=False`, requires Meta Llama 3.2 Community License acceptance + `HF_TOKEN` (`HF token present: False` on host) |
| **Ungated Mirror (`unsloth/Llama-3.2-1B-Instruct`)** | `gated=False`, `model.safetensors = 2357.14 MB`, `tokenizer.json = 16.41 MB`, `config.json` verified (`LlamaForCausalLM`, `16` layers, `2048` hidden, `8192` intermediate, `32` attn heads, `8` KV heads, `vocab_size = 128256`, `rope_theta = 500000.0`, `rope_scaling.rope_type = "llama3"`, `torch_dtype = "bfloat16"`) |
| **Host Disk Space** | `C:/`: `6.53 GB` free (insufficient for default HF cache); `F:/`: `52.44 GB` free |
| **Host System RAM** | `8.32 GB` (`7.75 GiB`) total, `0.84 GB` available (`89.8%` used), `15.10 GB` swap free |

---

## 3. Supported ExecuTorch & ARM64 CPU Quantization Configurations

| Configuration | Quantization Scheme | Estimated `.pte` Size (`Llama-3.2-1B`) | ARM64 CPU Target (XNNPACK) |
| :--- | :--- | :---: | :--- |
| **`8da4w` (Recommended)** | 8-bit dynamic activations + 4-bit group-wise weights (`group_size=32` via `torchao`) | `~0.75–0.90 GB` | Cortex-A76 NEON `asimddp` / `i8mm` (fits 4 GB / 8 GB RPi 5) |
| **`8w` (Weight-Only Int8)** | 8-bit weight-only quantization | `~1.30 GB` | Cortex-A76 NEON fallback |
| **`bf16` / `fp16`** | Unquantized 16-bit weights | `~2.36 GB` | High memory bandwidth; not ideal for 4 GB boards |
| **`fp32` (Unquantized)** | 32-bit float | `~4.94 GB` (+ `~10–14 GB` trace RAM) | Exceeds 7.75 GiB Windows host physical RAM |

---

## 4. Exact Technical Blockers Prevented on Current Windows 11 Host

1. **Blocker 1 — Meta Gated Checkpoint Access:** `meta-llama/Llama-3.2-1B-Instruct` requires an authenticated HuggingFace token (`HF_TOKEN`) with accepted Meta Llama 3.2 license terms (`HF token present: False`).
2. **Blocker 2 — ExecuTorch Runtime & Official LLM Exporter on Windows 11:**
   - PyPI `executorch` wheels (`1.1.0` through `1.6.0`) require `torch >= 2.10.0` (`1.1.0`) or `torch >= 2.15.0` (`1.6.0`).
   - Testing `torch 2.10.0+cpu` and `torch 2.15.0` on this Windows 11 host failed Windows DLL initialization (`WinError 1114` on `c10.dll` / `WinError 126` on `torch_cpu.dll`), whereas `torch==2.8.0+cpu` loads cleanly but has no compatible `executorch` wheel.
   - `torchao` is not installed, `docker` is not installed, and `wsl` returns `Wsl/E_ACCESSDENIED`.
   - Consequently, `executorch.examples.models.llama.export_llama` and `executorch.runtime.Runtime` cannot execute on this Windows host.
3. **Blocker 3 — Host RAM vs. Unquantized FP32 Export:** With `0.84 GB` free physical RAM (`7.75 GiB` total), unquantized FP32 `torch.export` of a `1.24B` model (`~10–14 GB` peak tracing memory) cannot run safely without `torchao` `8da4w` quantization on a Linux/ARM64 environment.

---

## 5. Exact Resolution Steps on Linux / ARM64 Target

Once on a Linux x86_64 or Raspberry Pi 5 (`aarch64`) environment with `HF_TOKEN` configured, run the reproducible export script [`deployment/linux/export_meta_llama_executorch.sh`](../deployment/linux/export_meta_llama_executorch.sh) (or `deployment/raspberry_pi/setup_rpi5.sh`):
```bash
export HF_TOKEN=<your_license_approved_hf_token>
bash deployment/linux/export_meta_llama_executorch.sh
```
`ExecuTorchLlamaRuntime` (`src/executorch/runtime.py`) and `LlamaCyberAdvisor` (`src/llama/advisor.py`) automatically detect `llama_3_2_1b_8da4w.pte` + `tokenizer_llama_3_2_1b/` and execute through `executorch.runtime.Runtime` on Linux/ARM64 when `executorch` is installed.
