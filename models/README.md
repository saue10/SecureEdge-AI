# SecureEdge AI — Trained Model Artifacts & ExecuTorch `.pte` Directory

This directory houses the serialized, calibrated specialized threat detectors and the exported Llama + ExecuTorch model artifacts.

## Model Inventory

| Subdirectory | Artifact | Model Architecture | Footprint |
| :--- | :--- | :--- | :--- |
| `url_detector/` | `url_detector_pipeline.joblib` | Calibrated Random Forest + StandardScaler (32 lexical/host features) | 262.4 KB |
| `sms_detector/` | `sms_detector_pipeline.joblib` | Calibrated LinearSVC + Word/Char TF-IDF + 12 Structural Fraud Features | 63.9 KB |
| `network_detector/` | `network_detector_pipeline.joblib` | Calibrated Random Forest + Unsupervised IsolationForest (16 flow features) | 542.3 KB |
| `llama_executorch/` | `llama_3_2_cyber_advisor.pte` | `LlamaForCausalLM` (Llama 3.2 GQA + RoPE + SwiGLU) exported via `torch.export` / ExecuTorch (324 graph nodes) | 3,240.6 KB (3.17 MB) |
| `llama_executorch/` | `llama_3_2_cyber_advisor.pt2` | Canonical PyTorch 2.8 `ExportedProgram` archive | 3,240.4 KB |
| `llama_executorch/` | `tokenizer_vocab.json` | Deterministic 512-token domain vocabulary (`CyberLlamaTokenizer`) | 8.2 KB |

**Total Combined Edge Model Footprint:** `4.01 MB` (fits effortlessly in L3 cache / RAM on Raspberry Pi 5 and ARM64 smartphones).

## Retraining & Re-Exporting Models

```bash
python scripts/train_models.py
```
