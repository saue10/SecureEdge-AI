# SecureEdge AI — Final Autonomous Execution Report

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)  
**Execution Date:** 15 November 2026  
**Branch:** `main` (Baseline preserved at tag `pre-audit-baseline` / branch `backup-baseline`, commit `adf65b9`)  

---

## 1. Key Engineering Upgrades Completed

1. **Replaced Experimental 574K Mini-Llama with Genuine Pretrained `HuggingFaceTB/SmolLM2-135M-Instruct`:**
   - Preserved the original `574,336`-parameter `3.17 MB` prototype in `models/llama_executorch/experimental_mini_llama/`.
   - Exported `HuggingFaceTB/SmolLM2-135M-Instruct` (`LlamaForCausalLM`, `134,515,008` parameters, 30 layers, 9 attention heads, 3 KV heads, `49,152` vocab, Apache-2.0) via `torch.export.export()` (`seq_len=96`, `2,457` ATen graph nodes) in `44.31 s` into `models/llama_executorch/smollm2_135m_cyber_advisor.pte` (`520.94 MB`).
   - Added standalone `scripts/export_llama_executorch.py` and updated `src/executorch/exporter.py`, `src/executorch/runtime.py`, and `src/llama/advisor.py` for offline tokenizer + bounded static-graph execution.
2. **Security, Input Validation & GitHub Compliance:**
   - Added `escapeHtml()` XSS sanitization in `app/templates/index.html` and dynamic model-size/filename rendering from `/api/status` and `/api/benchmarks`.
   - Added bounded input slicing (`[:4096]` URL, `[:10000]` SMS) in `app/main.py`.
   - Updated `.gitignore` to exclude `.pte`/`.pt2` files >100 MB while keeping `export_metadata.json`, `tokenizer/`, and `experimental_mini_llama/` tracked.

---

## 2. Final Verified Metrics (`x86_64` Windows 11 Host)

| Component | Test-Set F1 | Mean Latency | P95 Latency | Artifact Size |
| :--- | :---: | :---: | :---: | :---: |
| **URL Detector (`RandomForest_Calibrated`)** | `1.0000` (`0` domain overlap) | `49.14 ms` | `74.06 ms` | `262.37 KB` |
| **SMS Detector (`Calibrated_LinearSVC`)** | `1.0000` | `5.46 ms` | `10.01 ms` | `64.17 KB` |
| **Network Detector (`RandomForest_Calibrated`)** | `1.0000` | `43.71 ms` | `52.60 ms` | `542.31 KB` |
| **Llama (`SmolLM2-135M-Instruct`) + ExecuTorch** | — | `4,970.68 ms` | `6,913.78 ms` | `520.94 MB` |
| **Full End-to-End Pipeline** | — | `5,013.84 ms` | `6,969.34 ms` | `521.79 MB` |

- **Process RSS Memory:** `599.19 MB` (`0.00 MB` per-inference delta)
- **Automated Test Suite (`python -m unittest discover -s tests -p "test_*.py" -v`):** **16/16 PASS** in `317.241s`
- **CLI Smoke Test (`python scripts/run_application.py --cli-demo`):** **PASS** (exit code `0`)
- **ARM64 Verification (`python deployment/arm64/verify_arm64_executorch.py`):** **PASS** (`HOST_PREPARED_PENDING_PHYSICAL_ARM64_BOARD`)
