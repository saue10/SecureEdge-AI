# SecureEdge AI — Edge Deployment & Hardware Verification Guide

**Project:** SecureEdge AI (Bharat AI-SoC Challenge 2026–27 | PS3)

---

## 1. Host vs. ARM Target Execution Disclosure

In strict compliance with competition integrity rules:
- **Development & Host Verification Environment:** Windows 11 (`10.0.26200-SP0`, `AMD64` / `x86_64`), 11th Gen Intel Core i5-1135G7 @ 2.40 GHz (4 cores / 8 threads), 7.75 GB RAM, Python 3.13.2, PyTorch 2.8.0+cpu. All benchmarks measured on this machine are explicitly labelled **`x86_64 Host Measured`**.
- **ARM64 Edge Target Status:** Physical ARM hardware (Raspberry Pi 5 / Android device) was not connected to the host machine during this session. Full ARM64 deployment scripts, Docker build configurations, and hardware capability verifiers are implemented in `deployment/` and marked **`HOST_PREPARED_PENDING_PHYSICAL_ARM64_BOARD`**.

---

## 2. Deploying on Raspberry Pi 5 (ARM64 Linux)

### 2.1 Hardware Prerequisites
- **Board:** Raspberry Pi 5 (4 GB or 8 GB RAM recommended; total model footprint is only `4.01 MB`).
- **OS:** Raspberry Pi OS (64-bit, Debian 12 Bookworm) or Ubuntu 24.04 LTS (`aarch64`).
- **Optional Accelerator:** Raspberry Pi AI HAT+ (Hailo-8L / Hailo-8). Note that if Hailo is present, HailoRT accelerates convolutional vision pipelines on the NPU while Llama + ExecuTorch runs on the quad-core ARM Cortex-A76 CPU via the **XNNPACK** delegate.

### 2.2 Automated Installation & Verification
```bash
chmod +x deployment/raspberry_pi/setup_rpi5.sh
./deployment/raspberry_pi/setup_rpi5.sh
```

### 2.3 Verifying ARM64 NEON / DotProd & ExecuTorch `.pte`
```bash
python deployment/arm64/verify_arm64_executorch.py
cat evaluation/benchmark_results/arm64_verification_status.json
```
When executed on a Raspberry Pi 5, `verify_arm64_executorch.py` reads `/proc/cpuinfo` and `/proc/device-tree/model`, confirms `aarch64` + `asimd` (NEON) + `asimddp` (DotProd), loads `models/llama_executorch/llama_3_2_cyber_advisor.pte`, runs end-to-end smoke tests, and records `"verification_status": "VERIFIED_ON_ARM64_TARGET"`.

---

## 3. Deploying via Multi-Arch ARM64 Docker Container

```bash
docker buildx build --platform linux/arm64 -t secureedge-ai:arm64 -f deployment/arm64/Dockerfile.arm64 .
docker run --rm -p 8501:8501 secureedge-ai:arm64
```

---

## 4. Offline Air-Gapped Operation Verification

Once `scripts/train_models.py` has populated `models/`, SecureEdge AI requires **zero internet connectivity**:
1. Disable Wi-Fi / Ethernet on the edge device.
2. Start the dashboard:
   ```bash
   python scripts/run_application.py --host 127.0.0.1 --port 8501
   ```
3. The top status pill automatically detects air-gapped operation and displays:
   `OFFLINE AIR-GAPPED MODE (100% Local On-Device Execution)`.
