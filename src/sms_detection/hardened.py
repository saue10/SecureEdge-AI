"""Hardened SMS Scam & Adversarial Obfuscation Detection (Phase 3 — Priority 1).

Addresses spaced-out text, leetspeak, Unicode homoglyphs/confusables, zero-width
characters, repeated-character obfuscation, and Hinglish scam indicators while
preserving legitimate OTPs, banking alerts, personal chats, and commercial messages.
"""

import re
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from src.common.config import SMS_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import DetectorResult
from src.sms_detection.features import (
    CREDENTIAL_COERCION_PATTERNS,
    CURRENCY_REGEX,
    FINANCIAL_SCAM_PATTERNS,
    PHONE_IN_TEXT_REGEX,
    URGENCY_PATTERNS,
    URL_IN_TEXT_REGEX,
)

logger = get_logger("SecureEdge.HardenedSMS")

# Zero-width and invisible formatting characters used to break tokenizers
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\xad]")

# Cyrillic, Greek, and common Unicode confusables mapped to ASCII skeletons
SMS_CONFUSABLE_MAP: Dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u043a": "k",
    "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    # Cyrillic uppercase
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0406": "I",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x", "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
}

# Spaced/punctuated single-character obfuscation (e.g., "k y c", "u.p.i", "b-l-o-c-k-e-d")
SPACED_OBFUSCATION_RE = re.compile(
    r"(?<![a-zA-Z0-9])([a-zA-Z0-9])(?:[ \t._*|-]+([a-zA-Z0-9])){2,}(?![a-zA-Z0-9])"
)

# Obfuscated URLs like "bit . ly / abc" or "sbi-kyc[.]xyz"
OBFUSCATED_URL_RE = re.compile(
    r"(?:https?://|www\.|[a-z0-9-]+\s*(?:\[\.\]|\(\.\)|\.)\s*(?:com|in|org|net|xyz|top|tk|ml|ga|cf|gq|ly|co|me|info|click|link|apk|vip|icu))",
    re.IGNORECASE,
)

# Hinglish / Romanized Hindi scam & coercion markers
HINGLISH_SCAM_PATTERNS: List[str] = [
    r"\bkhata\b",
    r"\bband\s*(?:ho\s*jayega|hoga|kar\s*diya|kar\s*di|ho\s*gaya)\b",
    r"\bturant\b",
    r"\babhi\s*(?:verify|update|click|call|karo|kare|bhejo|check)\b",
    r"\bkyc\s*(?:karo|kare|karao|karvao|update\s*karo|pending\s*hai)\b",
    r"\b(?:ekyc|e-kyc)\b",
    r"\binaam\b",
    r"\b(?:jeet|jeeta|jeete)\s*(?:hai|hain|gaye|ho)\b",
    r"\blakh\b",
    r"\b(?:karod|crore)\b",
    r"\bbhejo\b",
    r"\bdabaao\b",
    r"\blink\s*(?:par|pe)\b",
    r"\bbijli\s*(?:bill|connection)\b",
    r"\bkat\s*jayega\b",
    r"\b(?:otp|pin|cvv)\s*(?:bhejo|batayein|batao|share\s*karo|do)\b",
    r"\bpaise\s*(?:milenge|aayenge|claim|bhejo|transfer)\b",
    r"\bapk\s*(?:install|download)\b",
]

# Legitimate bank transactional alert indicators (not asking to click untrusted links or share OTP/PIN)
LEGIT_BANK_ALERT_RE = re.compile(
    r"\b(?:debited|credited|avl\s*bal|available\s*bal(?:ance)?|a/c\s*(?:no\.?)?\s*[x*]+\d{2,4}|"
    r"txn\s*(?:id|ref)|upi\s*ref\s*(?:no)?|if\s*not\s*(?:done\s*by\s*)?you\s*(?:call|report))\b",
    re.IGNORECASE,
)

LEET_CHAR_MAP: Dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
}

HARDENED_SMS_FEATURE_NAMES: List[str] = [
    "char_length",
    "word_count",
    "uppercase_ratio",
    "digit_ratio",
    "exclamation_count",
    "has_url",
    "has_obfuscated_url",
    "has_phone_number",
    "has_currency_amount",
    "urgency_match_count",
    "financial_scam_match_count",
    "credential_coercion_match_count",
    "hinglish_scam_match_count",
    "is_otp_legit_pattern",
    "is_benign_bank_alert_pattern",
    "zero_width_count",
    "confusable_char_count",
    "spaced_obfuscation_count",
    "leetspeak_token_count",
    "repeated_char_obfuscation_count",
]


class HardenedSMSPreprocessor:
    """Adversarial-aware Unicode, homoglyph, spacing, leetspeak, and Hinglish SMS preprocessor."""

    @staticmethod
    def _collapse_spaced_match(match: re.Match) -> str:
        raw = match.group(0)
        # Preserve pure numeric sequences like phone numbers or dates separated by spaces/hyphens
        stripped = re.sub(r"[ \t._*|-]+", "", raw)
        if stripped.isdigit():
            return raw
        return stripped

    @classmethod
    def _decode_leetspeak_token(cls, token: str) -> Tuple[str, bool]:
        """Decode leetspeak only when a token mixes letters with leet digits/symbols."""
        has_alpha = any(c.isalpha() for c in token)
        has_leet = any(c in LEET_CHAR_MAP for c in token)
        if not (has_alpha and has_leet):
            return token, False
        decoded = "".join(LEET_CHAR_MAP.get(c, c) for c in token)
        return decoded, decoded != token

    @classmethod
    def normalize(cls, raw_text: str) -> Dict[str, Any]:
        """Normalize SMS text and return intermediate forms + obfuscation counters."""
        if not raw_text or not isinstance(raw_text, str):
            return {
                "tfidf_text": "",
                "keyword_text": "",
                "zero_width_count": 0,
                "confusable_char_count": 0,
                "spaced_obfuscation_count": 0,
                "leetspeak_token_count": 0,
                "repeated_char_obfuscation_count": 0,
            }

        # 1. Strip zero-width & invisible chars first
        zw_matches = ZERO_WIDTH_RE.findall(raw_text)
        zero_width_count = len(zw_matches)
        no_zw = ZERO_WIDTH_RE.sub("", raw_text)

        # 2. NFKC Unicode normalization (fullwidth, mathematical bold/italic, compatibility forms)
        nfkc = unicodedata.normalize("NFKC", no_zw)

        # 3. Map Cyrillic / Greek homoglyphs and count confusables
        confusable_count = 0
        mapped_chars: List[str] = []
        for ch in nfkc:
            repl = SMS_CONFUSABLE_MAP.get(ch)
            if repl is not None:
                confusable_count += 1
                mapped_chars.append(repl)
            else:
                mapped_chars.append(ch)
        de_homoglyphed = "".join(mapped_chars)

        # 4. Collapse spaced/punctuated letter obfuscation (e.g., "k y c", "u.p.i")
        spaced_matches = list(SPACED_OBFUSCATION_RE.finditer(de_homoglyphed))
        spaced_count = sum(
            1 for m in spaced_matches if not re.sub(r"[ \t._*|-]+", "", m.group(0)).isdigit()
        )
        de_spaced = SPACED_OBFUSCATION_RE.sub(cls._collapse_spaced_match, de_homoglyphed)

        # 5. Repeated character obfuscation (3+ identical alpha chars -> 2 for TF-IDF, 1 for keyword matching)
        repeated_matches = re.findall(r"([a-zA-Z])\1{2,}", de_spaced)
        repeated_count = len(repeated_matches)
        de_repeated_tfidf = re.sub(r"([a-zA-Z])\1{2,}", r"\1\1", de_spaced)
        de_repeated_kw = re.sub(r"([a-zA-Z])\1+", r"\1", de_spaced)

        # 6. Selective leetspeak decoding (only tokens containing both alpha and leet chars)
        leet_count = 0
        decoded_tokens: List[str] = []
        for tok in de_repeated_tfidf.split():
            dec, changed = cls._decode_leetspeak_token(tok)
            if changed:
                leet_count += 1
            decoded_tokens.append(dec)
        leet_norm_tfidf = " ".join(decoded_tokens)

        decoded_kw_tokens: List[str] = []
        for tok in de_repeated_kw.split():
            dec, _ = cls._decode_leetspeak_token(tok)
            decoded_kw_tokens.append(dec)
        leet_norm_kw = " ".join(decoded_kw_tokens)

        # 7. Canonical meta-token replacement for URL, currency, and phone numbers
        def _canonicalize(txt: str) -> str:
            t = OBFUSCATED_URL_RE.sub(" __URL_TOKEN__ ", txt)
            t = URL_IN_TEXT_REGEX.sub(" __URL_TOKEN__ ", t)
            t = CURRENCY_REGEX.sub(" __CURRENCY_TOKEN__ ", t)
            t = PHONE_IN_TEXT_REGEX.sub(" __PHONE_TOKEN__ ", t)
            t = re.sub(r"\s+", " ", t).lower().strip()
            return t

        return {
            "tfidf_text": _canonicalize(leet_norm_tfidf),
            "keyword_text": _canonicalize(leet_norm_kw),
            "raw_deobfuscated": leet_norm_tfidf.lower().strip(),
            "raw_kw_deobfuscated": leet_norm_kw.lower().strip(),
            "zero_width_count": zero_width_count,
            "confusable_char_count": confusable_count,
            "spaced_obfuscation_count": spaced_count,
            "leetspeak_token_count": leet_count,
            "repeated_char_obfuscation_count": repeated_count,
        }

    @classmethod
    def extract_features_and_evidence(cls, raw_text: str) -> Tuple[Dict[str, float], List[str], Dict[str, Any]]:
        """Extract 20 hardened structural/adversarial features and forensic evidence."""
        if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
            empty = {k: 0.0 for k in HARDENED_SMS_FEATURE_NAMES}
            return empty, ["Empty or blank SMS message"], {"tfidf_text": "", "keyword_text": ""}

        norm = cls.normalize(raw_text)
        stripped = raw_text.strip()
        kw_text = norm["raw_kw_deobfuscated"]
        deobf_text = norm["raw_deobfuscated"]

        char_len = len(stripped)
        words = [w for w in re.split(r"\s+", stripped) if w]
        word_count = len(words)

        alpha_chars = [c for c in stripped if c.isalpha()]
        upper_chars = [c for c in alpha_chars if c.isupper()]
        uppercase_ratio = len(upper_chars) / max(len(alpha_chars), 1)
        digit_ratio = sum(c.isdigit() for c in stripped) / max(char_len, 1)
        exclamation_count = float(stripped.count("!"))

        urls_found = URL_IN_TEXT_REGEX.findall(deobf_text)
        obf_urls_found = OBFUSCATED_URL_RE.findall(deobf_text)
        phones_found = PHONE_IN_TEXT_REGEX.findall(deobf_text)
        currencies_found = CURRENCY_REGEX.findall(deobf_text)

        has_url = 1.0 if (urls_found or obf_urls_found) else 0.0
        has_obf_url = 1.0 if (obf_urls_found and not urls_found) else 0.0
        has_phone = 1.0 if phones_found else 0.0
        has_currency = 1.0 if currencies_found else 0.0

        # Match patterns against both deobfuscated and collapsed-repeat forms
        search_corpus = f"{deobf_text} || {kw_text}"
        urgency_matches = [p for p in URGENCY_PATTERNS if re.search(p, search_corpus)]
        financial_matches = [p for p in FINANCIAL_SCAM_PATTERNS if re.search(p, search_corpus)]
        coercion_matches = [p for p in CREDENTIAL_COERCION_PATTERNS if re.search(p, search_corpus)]
        hinglish_matches = [p for p in HINGLISH_SCAM_PATTERNS if re.search(p, search_corpus)]

        is_legit_otp = (
            1.0
            if (
                re.search(r"\botp\b|\bverification\s+code\b", search_corpus)
                and re.search(r"\b(do\s+not\s+share|never\s+share|don'?t\s+share|mat\s+batana)\b", search_corpus)
                and has_url == 0.0
                and norm["confusable_char_count"] == 0
                and norm["zero_width_count"] == 0
            )
            else 0.0
        )

        non_call_coercion = [p for p in coercion_matches if p != r"\bcall\b"]
        is_benign_bank_alert = (
            1.0
            if (
                LEGIT_BANK_ALERT_RE.search(deobf_text)
                and has_url == 0.0
                and len(hinglish_matches) == 0
                and len(non_call_coercion) == 0
                and norm["confusable_char_count"] == 0
                and norm["spaced_obfuscation_count"] == 0
            )
            else 0.0
        )

        features: Dict[str, float] = {
            "char_length": float(min(char_len, 500)),
            "word_count": float(min(word_count, 100)),
            "uppercase_ratio": round(uppercase_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "exclamation_count": exclamation_count,
            "has_url": has_url,
            "has_obfuscated_url": has_obf_url,
            "has_phone_number": has_phone,
            "has_currency_amount": has_currency,
            "urgency_match_count": float(len(urgency_matches)),
            "financial_scam_match_count": float(len(financial_matches)),
            "credential_coercion_match_count": float(len(coercion_matches)),
            "hinglish_scam_match_count": float(len(hinglish_matches)),
            "is_otp_legit_pattern": is_legit_otp,
            "is_benign_bank_alert_pattern": is_benign_bank_alert,
            "zero_width_count": float(norm["zero_width_count"]),
            "confusable_char_count": float(norm["confusable_char_count"]),
            "spaced_obfuscation_count": float(norm["spaced_obfuscation_count"]),
            "leetspeak_token_count": float(norm["leetspeak_token_count"]),
            "repeated_char_obfuscation_count": float(norm["repeated_char_obfuscation_count"]),
        }

        evidence: List[str] = []
        if norm["confusable_char_count"] > 0:
            evidence.append(
                f"Unicode homoglyph/confusable substitution detected ({norm['confusable_char_count']} characters)"
            )
        if norm["zero_width_count"] > 0:
            evidence.append(
                f"Zero-width invisible character obfuscation detected ({norm['zero_width_count']} chars)"
            )
        if norm["spaced_obfuscation_count"] > 0:
            evidence.append(
                f"Spaced/punctuated token obfuscation detected ({norm['spaced_obfuscation_count']} segments)"
            )
        if norm["leetspeak_token_count"] > 0:
            evidence.append(
                f"Leetspeak/symbol substitution detected ({norm['leetspeak_token_count']} tokens)"
            )
        if len(hinglish_matches) > 0:
            evidence.append(
                f"Hinglish social-engineering scam phrasing detected ({len(hinglish_matches)} markers)"
            )
        if has_url > 0:
            sample_url = (urls_found or obf_urls_found)[0][:50]
            evidence.append(f"Contains embedded/obfuscated link ({sample_url}) inside SMS body")
        if len(urgency_matches) > 0:
            evidence.append(f"Urgency/coercion language detected ({len(urgency_matches)} markers)")
        if len(financial_matches) > 0:
            evidence.append(f"Financial/KYC/prize lure indicators detected ({len(financial_matches)} markers)")
        if is_legit_otp > 0:
            evidence.append("Matches legitimate transactional OTP alert with non-sharing warning and no link")
        if is_benign_bank_alert > 0:
            evidence.append("Matches legitimate bank balance/transaction notification with no untrusted link")
        if not evidence:
            evidence.append("No adversarial obfuscation or scam indicators detected in normalized SMS")

        return features, evidence, norm


class HardenedSMSDetector:
    """Calibrated, adversarial-hardened SMS scam detector (Word + Char TF-IDF + Rule-Assisted Features)."""

    DEFAULT_MODEL_PATH = SMS_MODEL_DIR / "sms_hardened_pipeline.joblib"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.word_vectorizer: Optional[TfidfVectorizer] = None
        self.char_vectorizer: Optional[TfidfVectorizer] = None
        self.scaler: Optional[StandardScaler] = None
        self.classifier: Any = None
        self.model_version: str = "sms-hardened-calibrated-v3.0"
        self.is_calibrated: bool = True
        self.metadata: Dict[str, Any] = {}
        self._load_if_exists()

    def _load_if_exists(self) -> bool:
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.word_vectorizer = bundle["word_vectorizer"]
                self.char_vectorizer = bundle["char_vectorizer"]
                self.scaler = bundle["scaler"]
                self.classifier = bundle["classifier"]
                self.model_version = bundle.get("model_version", self.model_version)
                self.is_calibrated = bundle.get("is_calibrated", True)
                self.metadata = bundle.get("metadata", {})
                return True
            except Exception as exc:
                logger.warning("Could not load hardened SMS bundle from %s: %s", self.model_path, exc)
                self.classifier = None
        return False

    def fit(
        self,
        train_texts: List[str],
        train_labels: np.ndarray,
        val_texts: Optional[List[str]] = None,
        val_labels: Optional[np.ndarray] = None,
        save_path: Optional[Path] = None,
    ) -> "HardenedSMSDetector":
        """Train word+char TF-IDF + structural features and calibrate strictly on validation split."""
        self.word_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=4000,
            sublinear_tf=True,
            min_df=2,
        )
        self.char_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=8000,
            sublinear_tf=True,
            min_df=2,
        )
        self.scaler = StandardScaler()

        train_norms = [HardenedSMSPreprocessor.extract_features_and_evidence(t) for t in train_texts]
        tr_tfidf_texts = [n[2]["tfidf_text"] for n in train_norms]
        tr_struct = np.array(
            [[n[0][k] for k in HARDENED_SMS_FEATURE_NAMES] for n in train_norms],
            dtype=np.float64,
        )

        Xw = self.word_vectorizer.fit_transform(tr_tfidf_texts)
        Xc = self.char_vectorizer.fit_transform(tr_tfidf_texts)
        Xs = csr_matrix(self.scaler.fit_transform(tr_struct))
        X_train = hstack([Xw, Xc, Xs])

        base_clf = LogisticRegression(
            C=1.5,
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )
        base_clf.fit(X_train, train_labels)

        if val_texts is not None and val_labels is not None and len(val_texts) >= 20:
            val_norms = [HardenedSMSPreprocessor.extract_features_and_evidence(t) for t in val_texts]
            va_tfidf_texts = [n[2]["tfidf_text"] for n in val_norms]
            va_struct = np.array(
                [[n[0][k] for k in HARDENED_SMS_FEATURE_NAMES] for n in val_norms],
                dtype=np.float64,
            )
            X_val = hstack([
                self.word_vectorizer.transform(va_tfidf_texts),
                self.char_vectorizer.transform(va_tfidf_texts),
                csr_matrix(self.scaler.transform(va_struct)),
            ])
            try:
                from sklearn.frozen import FrozenEstimator
                cal = CalibratedClassifierCV(FrozenEstimator(base_clf), method="sigmoid")
            except ImportError:
                cal = CalibratedClassifierCV(base_clf, cv="prefit", method="sigmoid")
            cal.fit(X_val, val_labels)
            self.classifier = cal
            self.is_calibrated = True
        else:
            self.classifier = base_clf
            self.is_calibrated = False

        if save_path is not None:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                {
                    "word_vectorizer": self.word_vectorizer,
                    "char_vectorizer": self.char_vectorizer,
                    "scaler": self.scaler,
                    "classifier": self.classifier,
                    "model_version": self.model_version,
                    "is_calibrated": self.is_calibrated,
                    "metadata": self.metadata,
                },
                save_path,
            )
        return self

    @staticmethod
    def _rule_assisted_risk(f: Dict[str, float]) -> float:
        """Compute bounded deterministic risk in [0, 1] from adversarial and semantic cues."""
        if f["is_otp_legit_pattern"] > 0 and f["has_url"] == 0:
            return 0.04
        if f["is_benign_bank_alert_pattern"] > 0 and f["has_url"] == 0:
            return 0.08

        obf_signals = (
            (1 if f["confusable_char_count"] > 0 else 0)
            + (1 if f["zero_width_count"] > 0 else 0)
            + (1 if f["spaced_obfuscation_count"] > 0 else 0)
            + (1 if f["leetspeak_token_count"] > 0 else 0)
            + (1 if f["repeated_char_obfuscation_count"] > 0 else 0)
        )

        score = 0.0
        if f["has_url"] > 0:
            score += 0.25
        if f["has_obfuscated_url"] > 0:
            score += 0.20
        if f["hinglish_scam_match_count"] >= 1:
            score += min(0.45, 0.26 * f["hinglish_scam_match_count"])
        if f["financial_scam_match_count"] >= 1:
            score += min(0.35, 0.18 * f["financial_scam_match_count"])
        if f["urgency_match_count"] >= 1:
            score += min(0.28, 0.14 * f["urgency_match_count"])
        if f["credential_coercion_match_count"] >= 1:
            score += min(0.24, 0.12 * f["credential_coercion_match_count"])
        if f["has_phone_number"] > 0 and (f["urgency_match_count"] > 0 or f["financial_scam_match_count"] > 0 or f["hinglish_scam_match_count"] > 0):
            score += 0.15
        if obf_signals >= 1 and (
            f["financial_scam_match_count"] > 0
            or f["urgency_match_count"] > 0
            or f["hinglish_scam_match_count"] > 0
            or f["credential_coercion_match_count"] > 0
            or f["has_url"] > 0
        ):
            score += min(0.35, 0.22 + 0.08 * (obf_signals - 1))

        return min(1.0, score)

    def predict_proba_and_features(self, raw_text: str) -> Tuple[float, Dict[str, float], List[str]]:
        """Return calibrated/rule-assisted scam probability, features, and evidence."""
        feats, evidence, norm = HardenedSMSPreprocessor.extract_features_and_evidence(raw_text)
        rule_prob = self._rule_assisted_risk(feats)

        if (
            self.classifier is not None
            and self.word_vectorizer is not None
            and self.char_vectorizer is not None
            and self.scaler is not None
        ):
            Xw = self.word_vectorizer.transform([norm["tfidf_text"]])
            Xc = self.char_vectorizer.transform([norm["tfidf_text"]])
            Xs = csr_matrix(
                self.scaler.transform(
                    np.array([[feats[k] for k in HARDENED_SMS_FEATURE_NAMES]], dtype=np.float64)
                )
            )
            ml_prob = float(self.classifier.predict_proba(hstack([Xw, Xc, Xs]))[0][1])
        else:
            ml_prob = rule_prob

        # Guardrails: preserve legitimate OTPs & clean bank alerts; elevate confirmed adversarial obfuscation
        if feats["is_otp_legit_pattern"] > 0 and feats["has_url"] == 0:
            prob = min(ml_prob * 0.25, 0.15)
        elif feats["is_benign_bank_alert_pattern"] > 0 and feats["has_url"] == 0:
            prob = min(ml_prob * 0.35, 0.22)
        else:
            # Rule-assisted floor when adversarial obfuscation + semantic scam cues co-occur
            obf_active = (
                feats["confusable_char_count"] > 0
                or feats["zero_width_count"] > 0
                or feats["spaced_obfuscation_count"] > 0
                or feats["leetspeak_token_count"] > 0
                or feats["hinglish_scam_match_count"] >= 2
            )
            if obf_active and rule_prob >= 0.55:
                prob = max(ml_prob, 0.45 * ml_prob + 0.55 * rule_prob, 0.65)
            else:
                prob = 0.72 * ml_prob + 0.28 * rule_prob

        prob = max(0.0, min(1.0, prob))
        return prob, feats, evidence

    def predict(self, raw_text: str) -> DetectorResult:
        """Classify an SMS message and return a standardized DetectorResult."""
        t0 = time.perf_counter()
        if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
            return DetectorResult(
                source="sms",
                threat_type="benign",
                classification="benign",
                confidence=1.0,
                risk_score=0,
                evidence=["Empty or blank SMS input provided; no threat indicators present."],
                model_version=self.model_version,
                inference_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                features={},
                raw_input_summary="<empty>",
                is_calibrated=self.is_calibrated,
            )

        prob, feats, evidence = self.predict_proba_and_features(raw_text)
        risk_score = int(round(prob * 100))

        is_scam = (
            feats["financial_scam_match_count"] >= 1
            or feats["hinglish_scam_match_count"] >= 1
            or (feats["has_url"] > 0 and feats["credential_coercion_match_count"] >= 1)
        )

        if risk_score >= 60:
            classification = "malicious"
            threat_type = "scam" if is_scam else "spam"
            confidence = prob
        elif risk_score >= 35:
            classification = "suspicious"
            threat_type = "scam" if is_scam else "spam"
            confidence = prob
        else:
            classification = "benign"
            threat_type = "benign"
            confidence = 1.0 - prob

        return DetectorResult(
            source="sms",
            threat_type=threat_type,
            classification=classification,
            confidence=round(float(confidence), 4),
            risk_score=risk_score,
            evidence=evidence,
            model_version=self.model_version,
            inference_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            features=feats,
            raw_input_summary=raw_text.strip()[:120],
            is_calibrated=self.is_calibrated,
        )
