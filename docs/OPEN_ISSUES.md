# SecureEdge AI — Open Issues & Technical Blockers Log

**Last Updated:** 2026-11-15  

---

## Active External Items (Requiring Physical Hardware or Organizer Portal)

| ID | Component | Severity | Description | Status / Action Required |
| :--- | :--- | :--- | :--- | :--- |
| **EXT-001** | Physical ARM64 Board Validation | Info | Development host is an `x86_64` Windows 11 laptop (`Intel Core i5-1135G7`) with no physical Raspberry Pi 5 or Android board attached. | **Host Prototype & ARM64 Package Complete:** All benchmarks are transparently labelled `x86_64 Host Measured`. When your Raspberry Pi 5 or ARM64 Linux device is available, run `./deployment/raspberry_pi/setup_rpi5.sh` and `python deployment/arm64/verify_arm64_executorch.py` to record on-board ARM64 telemetry. |
| **EXT-002** | GitHub Remote Repository Push | Info | Local Git repository is initialized and committed cleanly on `main`, but no remote GitHub URL or credentials are configured yet. | **Ready to Push:** Run `git remote add origin <your-github-repo-url>` and `git push -u origin main`. |

---

## Resolved Technical Issues

| ID | Component | Description | Resolution |
| :--- | :--- | :--- | :--- |
| **ISS-001** | Host RAM Constraint (7.75 GB Total) | Low free RAM (~0.74–1.5 GB) risked OOM during training and LLM graph export. | **Resolved:** Used compact feature matrices, `gc.collect()`, and an ungated 134.5M-parameter `HuggingFaceTB/SmolLM2-135M-Instruct` (`LlamaForCausalLM`, `520.94 MB` `.pte`), keeping peak process RSS at `599.19 MB`. |
| **ISS-003** | ExecuTorch Windows Python 3.13 Compatibility | PyPI does not publish prebuilt Windows `cp313` C++ pybinding wheels for `executorch` (and `torch 2.10+`/`2.15` fail Windows `c10.dll` init on this host). | **Resolved:** Implemented dual-path `LlamaExecuTorchExporter` and `ExecuTorchLlamaRuntime` using PyTorch 2.8 `torch.export.export()` (`2,457` static graph nodes) packaged into `smollm2_135m_cyber_advisor.pte` + `.pt2` on Windows, with native `executorch.exir` `XnnpackPartitioner` support for Linux/ARM64. |
| **ISS-005** | Scapy PCAP Connection Frequency Count | Initial `packets_to_flows` counted every packet toward `connection_frequency`, causing a 18-packet benign HTTPS flow to appear anomalous. | **Resolved:** Updated `ScapyFlowCollector.packets_to_flows` to count TCP SYN handshakes (`tcp_flags_int & 1`), Verified in `test_e2e_network_pcap_to_llama_pipeline`. |
| **ISS-006** | Very Long Benign SMS Outlier | 15,000-character benign SMS caused `StandardScaler` linear outlier in SVM. | **Resolved:** Capped `char_length` (`500`) and `word_count` (`100`) in structural features and added a conversational guardrail. Verified in `test_sms_edge_cases_empty_and_very_long`. |
