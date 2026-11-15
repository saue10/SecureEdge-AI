"""Scam and Spam SMS Detection module for SecureEdge AI."""

from src.sms_detection.features import SMSFeatureExtractor
from src.sms_detection.detector import ScamSMSDetector

__all__ = ["SMSFeatureExtractor", "ScamSMSDetector"]
