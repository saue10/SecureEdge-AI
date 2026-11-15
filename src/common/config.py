"""Global configuration and paths for SecureEdge AI."""

from pathlib import Path
import platform
import os

# Base directory of the repository
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Data paths
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

# Model paths
MODELS_DIR = PROJECT_ROOT / "models"
URL_MODEL_DIR = MODELS_DIR / "url_detector"
SMS_MODEL_DIR = MODELS_DIR / "sms_detector"
NETWORK_MODEL_DIR = MODELS_DIR / "network_detector"
LLAMA_MODEL_DIR = MODELS_DIR / "llama_executorch"

# Evaluation & Benchmark paths
EVALUATION_DIR = PROJECT_ROOT / "evaluation"
METRICS_DIR = EVALUATION_DIR / "metrics"
FIGURES_DIR = EVALUATION_DIR / "figures"
BENCHMARKS_DIR = EVALUATION_DIR / "benchmark_results"

# Documentation & Demo paths
DOCS_DIR = PROJECT_ROOT / "docs"
DEMO_DIR = PROJECT_ROOT / "demo"
SCREENSHOTS_DIR = DEMO_DIR / "screenshots"

# Runtime History & Logs
LOGS_DIR = PROJECT_ROOT / "logs"
HISTORY_DB_PATH = DATA_DIR / "processed" / "detection_history.json"

# Global Reproducibility Seed
RANDOM_SEED = 42

# Hardware & Platform Detection
HOST_OS = platform.system()
HOST_ARCH = platform.machine().lower()
IS_ARM = HOST_ARCH in ("aarch64", "arm64", "armv8l", "armv7l")


def ensure_directories() -> None:
    """Create all required project directories if they do not exist."""
    for directory in [
        RAW_DATA_DIR,
        PROCESSED_DATA_DIR,
        URL_MODEL_DIR,
        SMS_MODEL_DIR,
        NETWORK_MODEL_DIR,
        LLAMA_MODEL_DIR,
        METRICS_DIR,
        FIGURES_DIR,
        BENCHMARKS_DIR,
        DOCS_DIR,
        DEMO_DIR,
        SCREENSHOTS_DIR,
        LOGS_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
