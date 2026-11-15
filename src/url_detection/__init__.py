"""Phishing URL Detection module for SecureEdge AI."""

from src.url_detection.features import URLFeatureExtractor
from src.url_detection.detector import PhishingURLDetector

__all__ = ["URLFeatureExtractor", "PhishingURLDetector"]
