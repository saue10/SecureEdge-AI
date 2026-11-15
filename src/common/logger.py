"""Structured logging utility for SecureEdge AI."""

import logging
import sys
from pathlib import Path
from src.common.config import LOGS_DIR, ensure_directories


def get_logger(name: str) -> logging.Logger:
    """Create or retrieve a configured logger writing to stdout and logs/secureedge.log."""
    ensure_directories()
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    try:
        log_file: Path = LOGS_DIR / "secureedge.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        pass

    return logger
