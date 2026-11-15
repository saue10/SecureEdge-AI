"""Text preprocessing, tokenization, and structural feature extraction for SMS Scam & Spam detection."""

import re
from typing import Dict, List, Tuple
import numpy as np


URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bblocked\s+today\b", r"\btoday\s+only\b",
    r"\bwithin\s+\d+\s*(hours?|hrs?|mins?|minutes?)\b",
    r"\bexpire[sd]?\b", r"\bfinal\s+notice\b", r"\blast\s+chance\b", r"\bact\s+now\b",
    r"\baction\s+required\b", r"\bsuspended\b", r"\bblocked\b", r"\bdeactivated\b",
    r"\bfrozen\b", r"\brestricted\b",
]

FINANCIAL_SCAM_PATTERNS = [
    r"\bkyc\b", r"\bpan\s*card\b", r"\baadhaar\b", r"\bupi\b", r"\botp\b",
    r"\bbank\s+account\b", r"\bnet\s*banking\b", r"\bcredit\s+card\b", r"\bdebit\s+card\b",
    r"\brefund\b", r"\bincome\s*tax\b", r"\belectricity\s+bill\b", r"\bpower\s+disconnect\b",
    r"\bcustoms\s+parcel\b", r"\bfedex\b", r"\bdhl\b", r"\bpolice\b", r"\bcbi\b",
    r"\bdigital\s+arrest\b", r"\bloan\s+approved\b", r"\bpre-?approved\b", r"\bcashback\b",
    r"\blottery\b", r"\bprize\b", r"\bwinner\b", r"\bwon\b", r"\bclaim\b",
    r"\bpart-?time\s+job\b", r"\btelegram\b", r"\bwhatsapp\b", r"\binvestment\b",
    r"\bcrypto\b", r"\busdt\b", r"\bsbi\b", r"\bhdfc\b", r"\bicici\b", r"\baxis\b",
    r"\bpaytm\b", r"\bphonepe\b", r"\bgpay\b",
]

CREDENTIAL_COERCION_PATTERNS = [
    r"\bverify\b", r"\bupdate\b", r"\bclick\b", r"\blink\b", r"\bcall\b",
    r"\bshare\b", r"\bconfirm\b", r"\blogin\b", r"\bpassword\b", r"\bpin\b",
    r"\bcvv\b", r"\bsubmit\b", r"\bregister\b",
]

CURRENCY_REGEX = re.compile(
    r"(?:rs\.?|inr|usd|\$|£|€|₹)\s*\d[\d,]*(?:\.\d+)?|\d[\d,]*\s*(?:rs|inr|lakhs?|crores?|pounds?|dollars?)",
    re.IGNORECASE,
)

URL_IN_TEXT_REGEX = re.compile(
    r"(?:https?://|www\.|[a-zA-Z0-9-]+\.(?:com|in|org|net|xyz|top|tk|ml|ga|cf|gq|ly|co|me|info|click|link|apk))(?:/[^\s]*)?",
    re.IGNORECASE,
)

PHONE_IN_TEXT_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-\s]?)?(?:\d{10}|\d{5}[-\s]\d{5}|\d{3,4}[-\s]\d{3}[-\s]\d{3,4}|08\d{8,9}|09\d{8,9})"
)

STRUCTURAL_FEATURE_NAMES: List[str] = [
    "char_length",
    "word_count",
    "uppercase_ratio",
    "digit_ratio",
    "exclamation_count",
    "has_url",
    "has_phone_number",
    "has_currency_amount",
    "urgency_match_count",
    "financial_scam_match_count",
    "credential_coercion_match_count",
    "is_otp_legit_pattern",
]


class SMSFeatureExtractor:
    """Text normalizer and structural scam indicator extractor for SMS messages."""

    structural_feature_names: List[str] = STRUCTURAL_FEATURE_NAMES

    @staticmethod
    def clean_text(raw_text: str) -> str:
        """Clean and normalize SMS text while preserving semantic tokens for TF-IDF."""
        if not raw_text or not isinstance(raw_text, str):
            return ""
        text = raw_text.strip()
        # Replace URLs, currency, and phone numbers with canonical meta-tokens for TF-IDF
        text = URL_IN_TEXT_REGEX.sub(" __URL_TOKEN__ ", text)
        text = CURRENCY_REGEX.sub(" __CURRENCY_TOKEN__ ", text)
        text = PHONE_IN_TEXT_REGEX.sub(" __PHONE_TOKEN__ ", text)
        text = re.sub(r"\s+", " ", text)
        return text.lower().strip()

    @classmethod
    def extract_structural_features_and_evidence(cls, raw_text: str) -> Tuple[Dict[str, float], List[str]]:
        """Extract 12 structural/heuristic features and human-readable forensic evidence from an SMS."""
        if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
            empty = {k: 0.0 for k in STRUCTURAL_FEATURE_NAMES}
            return empty, ["Empty or blank SMS message"]

        stripped = raw_text.strip()
        lower = stripped.lower()
        char_len = len(stripped)
        words = [w for w in re.split(r"\s+", stripped) if w]
        word_count = len(words)

        alpha_chars = [c for c in stripped if c.isalpha()]
        upper_chars = [c for c in alpha_chars if c.isupper()]
        uppercase_ratio = len(upper_chars) / max(len(alpha_chars), 1)
        digit_ratio = sum(c.isdigit() for c in stripped) / max(char_len, 1)
        exclamation_count = float(stripped.count("!"))

        urls_found = URL_IN_TEXT_REGEX.findall(stripped)
        phones_found = PHONE_IN_TEXT_REGEX.findall(stripped)
        currencies_found = CURRENCY_REGEX.findall(stripped)

        has_url = 1.0 if urls_found else 0.0
        has_phone = 1.0 if phones_found else 0.0
        has_currency = 1.0 if currencies_found else 0.0

        urgency_matches = [p for p in URGENCY_PATTERNS if re.search(p, lower)]
        financial_matches = [p for p in FINANCIAL_SCAM_PATTERNS if re.search(p, lower)]
        coercion_matches = [p for p in CREDENTIAL_COERCION_PATTERNS if re.search(p, lower)]

        # Legitimate transactional OTP pattern: contains OTP and explicitly says "do not share" and has NO URL
        is_legit_otp = 1.0 if (
            re.search(r"\botp\b", lower)
            and re.search(r"\b(do\s+not\s+share|never\s+share|don'?t\s+share)\b", lower)
            and not urls_found
        ) else 0.0

        features: Dict[str, float] = {
            "char_length": float(min(char_len, 500)),
            "word_count": float(min(word_count, 100)),
            "uppercase_ratio": round(uppercase_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "exclamation_count": exclamation_count,
            "has_url": has_url,
            "has_phone_number": has_phone,
            "has_currency_amount": has_currency,
            "urgency_match_count": float(len(urgency_matches)),
            "financial_scam_match_count": float(len(financial_matches)),
            "credential_coercion_match_count": float(len(coercion_matches)),
            "is_otp_legit_pattern": is_legit_otp,
        }

        evidence: List[str] = []
        if has_url > 0:
            evidence.append(f"Contains embedded link ({urls_found[0][:50]}) inside SMS body")
        if len(urgency_matches) > 0:
            evidence.append(f"Psychological urgency/coercion language detected ({len(urgency_matches)} urgency markers)")
        if len(financial_matches) > 0:
            evidence.append(
                f"Financial, KYC, prize, or banking lure indicators detected ({len(financial_matches)} pattern matches)"
            )
        if len(coercion_matches) > 0 and (has_url > 0 or has_phone > 0 or len(financial_matches) > 0):
            evidence.append("Solicits user action (click link, call number, verify KYC, or submit credentials)")
        if has_currency > 0:
            evidence.append(f"References monetary value or financial reward ({currencies_found[0].strip()})")
        if has_phone > 0 and (len(urgency_matches) > 0 or len(financial_matches) > 0 or has_currency > 0):
            evidence.append(f"Includes callback phone number ({phones_found[0].strip()}) paired with lure/urgency")
        if uppercase_ratio > 0.35 and char_len > 25:
            evidence.append(f"High proportion of ALL-CAPS text ({uppercase_ratio:.0%}) typical of spam/scam alerts")
        if is_legit_otp > 0:
            evidence.append("Contains standard transactional OTP warning ('do not share') with no external links")

        if not evidence:
            evidence.append("Conversational or informational SMS with no scam, coercion, or phishing indicators")

        return features, evidence

    @classmethod
    def extract_structural_matrix(cls, texts: List[str]) -> np.ndarray:
        """Return 2D numpy array of shape (N, 12) containing structural SMS features."""
        rows = []
        for t in texts:
            feats, _ = cls.extract_structural_features_and_evidence(t)
            rows.append([feats[k] for k in STRUCTURAL_FEATURE_NAMES])
        return np.array(rows, dtype=np.float64)
