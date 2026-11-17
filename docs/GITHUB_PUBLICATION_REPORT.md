# SecureEdge AI — GitHub Publication Report

**Date:** 2026-11-17  
**Repository URL:** https://github.com/saue10/SecureEdge-AI  
**GitHub Visibility:** Public (verified via unauthenticated HTTP `200 OK` on repo, `README.md`, and screenshot)  
**Branch Pushed:** `main` (`origin/main`)  
**Published Commit SHA:** `450ca5802c5cf9508691d7041c654bfad756e989` (`450ca58`)  
**Local vs. Remote SHA Match:** **YES — Exact Match** (`450ca5802c5cf9508691d7041c654bfad756e989`)  
**Number of Tracked Files Published:** `145`

---

## 1. Post-Push Verification Results
- `git push -u origin main`: Succeeded (`* [new branch] main -> main`, `branch 'main' set up to track 'origin/main'`).
- `git log -1 --oneline`: `450ca58 SecureEdge AI: Prepare Bharat AI-SoC Challenge initial submission`.
- `git remote -v`: `origin https://github.com/saue10/SecureEdge-AI.git` (`fetch` & `push`).
- `https://github.com/saue10/SecureEdge-AI`: HTTP `200 OK`.
- `https://raw.githubusercontent.com/saue10/SecureEdge-AI/main/README.md`: HTTP `200 OK`.
- `https://raw.githubusercontent.com/saue10/SecureEdge-AI/main/docs/submission/screenshots/01_security_overview.png`: HTTP `200 OK` (`108,989` bytes; all 6 screenshots & evaluation plots are committed in `450ca58`).
- `git status -s`: Only untracked `?? docs/GITHUB_PUBLICATION_REPORT.md` (created as the post-push publication report).

## 2. Deliberately Excluded Files (`.gitignore`)
- Large `>100 MB` LLM artifacts (`models/llama_executorch/smollm2_135m_cyber_advisor.pte`, `.pt2`) — regenerated locally via `python scripts/export_llama_executorch.py`.
- Runtime history logs (`data/processed/detection_history.json`, `data/processed/incidents_history.json`), `logs/`, `__pycache__/`, and `.venv/`.

## 3. Scope & Compliance Reminder
- Verified on Windows 11 `x86_64` CPU-only host with `SmolLM2-135M-Instruct` comparison static graph.
- Genuine Meta Llama 3.2 ExecuTorch, native `executorch` runtime, physical ARM64, and PYNQ-Z2 FPGA execution remain **unverified** and are documented honestly in `README.md` and `docs/INITIAL_SUBMISSION_REPORT.md`.
