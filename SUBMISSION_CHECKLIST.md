# SecureEdge AI — Phase 1 Submission Checklist

**Competition:** 2nd Edition of Bharat AI-SoC Challenge 2026–27 (PS3)  
**Confirmed Phase 1 Deadline:** 23 November 2026  

---

## Automated Engineering & Repository Deliverables (Completed)

- [x] **Complete Source Code (`src/`, `app/`, `scripts/`, `deployment/`):** Modular, tested Python codebase across Phases 1–5.
- [x] **Unified Primary Application (Flask):**
  - 10-view Cybersecurity Dashboard (`python scripts/run_application.py --host 127.0.0.1 --port 8501`)
  - Default offline `FAST TRIAGE` mode (`~189 MB` RSS, zero LLM startup overhead) + optional `DEEP ANALYSIS` with deterministic fallback
  - Controlled offline synthetic demonstration mode (10 scenarios) & redacted JSON/Markdown incident export
- [x] **Hardened Detectors & Calibrated Policy (Phase 3):**
  - `HardenedURLDetector` (`0.342 MB`), `HardenedSMSDetector` (`0.169 MB`), `ContextAwareNetworkDetector` (`2.216 MB`)
  - `CalibratedDecisionPolicy` (`confirmed_malicious`, `suspicious_unknown`, `normal`, `insufficient_evidence`)
- [x] **Lightweight Comparison LLM (`SmolLM2-135M-Instruct`) Preserved:**
  - `HuggingFaceTB/SmolLM2-135M-Instruct` (`LlamaForCausalLM`, 134.5M params, Apache-2.0) exported via `python scripts/export_llama_executorch.py` (`.pte`/`.pt2` excluded in `.gitignore`; offline tokenizer in `models/llama_executorch/tokenizer/`)
- [ ] **Authentic Meta Llama 3.2 1B + Native ExecuTorch (`8da4w` XNNPACK) & Physical ARM64:**
  - **Not verified on this Windows 11 x86_64 host** (`HF_TOKEN` + Linux/ARM64 `executorch` required). See `docs/PHASE5_FINAL_INTEGRATION_AUDIT.md` and `deployment/linux/export_meta_llama_executorch.sh`.
- [x] **Automated QA & Benchmarks:**
  - Full suite: `python -m unittest discover -s tests -p "test_*.py" -v` (Phase 1–5 unit, integration, security, and E2E tests)
  - Evaluation results: `results/phase3_hardening/phase3_results.json`, `results/adaptive_threat_intelligence/phase2_results.json`, `results/reliable_evaluation/reliable_evaluation_results.json`
- [x] **Documentation & Demo Script:**
  - `README.md`, `docs/PHASE5_FINAL_INTEGRATION_AUDIT.md`, `docs/PHASE4_PRODUCTIZATION_REPORT.md`, `docs/PHASE3_EVALUATION_REPORT.md`, `docs/DEMO_SCRIPT.md`, `docs/DEMO_SCENARIOS.md`

---

## Manual External Actions Required Before 23 November 2026

- [ ] **1. Push to GitHub:** `git push -u origin main`
- [ ] **2. Record 5-Minute Demonstration Video:** Follow `docs/DEMO_SCRIPT.md` on `http://127.0.0.1:8501`.
- [ ] **3. (Optional, if Linux/ARM64 Available) Export & Verify Meta Llama 3.2 1B:** Run `deployment/linux/export_meta_llama_executorch.sh` with `HF_TOKEN`.
- [ ] **4. Submit Official Challenge Form:** Submit GitHub URL, Technical Report, and Demo Video on or before **23 November 2026**.
