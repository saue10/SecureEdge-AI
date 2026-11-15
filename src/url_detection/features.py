"""Lexical, structural, and host-level URL feature extraction for Phishing Detection."""

import ipaddress
import math
import re
from collections import Counter
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, unquote, urlparse
import numpy as np


SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "club",
    "work", "date", "loan", "click", "link", "zip", "mov", "icu",
    "vip", "win", "bid", "stream", "download", "xin", "kim", "men",
    "buzz", "rest", "fit", "cn", "ru", "su", "sbs", "cfd", "cyou",
}

TRUSTED_TLDS = {
    "gov", "edu", "mil", "int", "ac.in", "gov.in", "nic.in", "org.in",
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "secure",
    "account", "banking", "confirm", "password", "credential", "wallet",
    "kyc", "pan", "aadhaar", "upi", "refund", "suspend", "unlock",
    "authenticate", "webscr", "cmd", "ebayisapi", "wp-admin", "wp-includes",
    "support", "billing", "invoice", "recover", "validate", "bonus",
    "free", "gift", "claim", "urgent", "alert", "security", "token",
}

TARGETED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "sbi", "hdfc", "icici",
    "axisbank", "kotak", "paytm", "phonepe", "gpay", "bhim",
    "NPCI", "irctc", "epfo", "incometax", "dhl", "fedex", "indiapost",
    "binance", "coinbase", "metamask", "steam", "linkedin", "dropbox",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "tiny.cc",
    "rb.gy", "cutt.ly", "shorturl.at", "v.gd", "qr.ae",
}

FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "has_ip_address",
    "has_https",
    "num_dots",
    "num_hyphens",
    "num_Rule_at",
    "num_question_marks",
    "num_ampersands",
    "num_equals",
    "num_underscores",
    "num_slashes",
    "num_percent_encoding",
    "digit_ratio_url",
    "digit_ratio_hostname",
    "special_char_ratio",
    "subdomain_count",
    "path_depth",
    "has_non_standard_port",
    "has_punycode",
    "is_shortener",
    "suspicious_tld",
    "trusted_tld",
    "suspicious_keyword_count",
    "brand_in_subdomain_or_path",
    "hostname_entropy",
    "url_entropy",
    "longest_token_length",
    "has_double_slash_in_path",
    "has_executable_extension",
]


def shannon_entropy(text: str) -> float:
    """Compute Shannon character entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class URLFeatureExtractor:
    """Deterministic lexical & structural feature extractor for URLs."""

    feature_names: List[str] = FEATURE_NAMES

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Normalize raw URL string for consistent parsing."""
        if not raw_url or not isinstance(raw_url, str):
            return ""
        cleaned = raw_url.strip()
        if not cleaned:
            return ""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = "http://" + cleaned
        return cleaned

    @classmethod
    def extract_registered_domain(cls, raw_url: str) -> str:
        """Extract effective registered domain (e.g. 'example.com' or 'sbi.co.in') for group splitting."""
        norm = cls.normalize_url(raw_url)
        if not norm:
            return "empty"
        try:
            parsed = urlparse(norm)
            host = (parsed.hostname or "").lower().strip(".")
        except ValueError:
            return "invalid"
        if not host:
            return "empty"
        if cls._is_ip_address(host):
            return host
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        # Handle two-level ccTLDs like .co.in, .ac.in, .gov.in, .co.uk, .com.au
        if len(parts) >= 3 and parts[-2] in {"co", "ac", "gov", "org", "net", "edu", "nic", "com"} and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """Return True if hostname is an IPv4, IPv6, or hex/octal IP representation."""
        if not hostname:
            return False
        clean_host = hostname.strip("[]")
        try:
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            pass
        # Check hex or integer encoded IPv4
        if re.match(r"^(0x[0-9a-fA-F]+|\d{8,10})$", clean_host):
            return True
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", clean_host):
            return True
        return False

    @classmethod
    def extract_features_and_evidence(cls, raw_url: str) -> Tuple[Dict[str, float], List[str]]:
        """Extract all 32 numeric features and human-readable forensic evidence from a URL."""
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            empty_feats = {name: 0.0 for name in FEATURE_NAMES}
            return empty_feats, ["Empty or missing URL input"]

        raw_stripped = raw_url.strip()
        explicit_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_stripped))
        normalized = cls.normalize_url(raw_stripped)

        try:
            parsed = urlparse(normalized)
            scheme = (parsed.scheme or "").lower()
            hostname = (parsed.hostname or "").lower()
            path = parsed.path or ""
            query = parsed.query or ""
            try:
                port = parsed.port
            except ValueError:
                port = -1
        except ValueError:
            # Malformed URL structure (e.g. invalid IPv6 brackets)
            scheme = "http"
            hostname = raw_stripped.split("/")[0].lower()
            path = "/" + "/".join(raw_stripped.split("/")[1:])
            query = ""
            port = -1

        full_lower = normalized.lower()
        url_len = len(raw_stripped)
        host_len = len(hostname)
        path_len = len(path)
        query_len = len(query)

        has_ip = 1.0 if cls._is_ip_address(hostname) else 0.0
        has_https = 1.0 if (scheme == "https" and explicit_scheme) else 0.0

        num_dots = float(raw_stripped.count("."))
        num_hyphens = float(hostname.count("-"))
        num_at = float(raw_stripped.count("@"))
        num_qmark = float(raw_stripped.count("?"))
        num_amp = float(raw_stripped.count("&"))
        num_eq = float(raw_stripped.count("="))
        num_underscore = float(raw_stripped.count("_"))
        num_slashes = float(raw_stripped.count("/"))
        num_percent = float(raw_stripped.count("%"))

        digits_url = sum(c.isdigit() for c in raw_stripped)
        digits_host = sum(c.isdigit() for c in hostname)
        special_chars = sum(not c.isalnum() for c in raw_stripped)

        digit_ratio_url = digits_url / max(url_len, 1)
        digit_ratio_host = digits_host / max(host_len, 1)
        special_ratio = special_chars / max(url_len, 1)

        # Subdomain count
        host_parts = [p for p in hostname.split(".") if p]
        if has_ip or len(host_parts) <= 2:
            subdomain_count = 0.0
        else:
            # Adjust for 2-part ccTLDs like .co.in
            if len(host_parts) >= 3 and host_parts[-2] in {"co", "ac", "gov", "org", "net", "edu", "nic"} and len(host_parts[-1]) == 2:
                subdomain_count = float(max(0, len(host_parts) - 3))
            else:
                subdomain_count = float(max(0, len(host_parts) - 2))

        path_segments = [seg for seg in path.split("/") if seg]
        path_depth = float(len(path_segments))

        has_non_std_port = 1.0 if (port is not None and port not in (80, 443)) else 0.0
        has_punycode = 1.0 if "xn--" in hostname else 0.0
        is_shortener = 1.0 if hostname in SHORTENER_DOMAINS else 0.0

        tld = host_parts[-1] if host_parts else ""
        two_part_tld = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else tld
        is_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        is_trusted_tld = 1.0 if (tld in TRUSTED_TLDS or two_part_tld in TRUSTED_TLDS) else 0.0

        # Keyword analysis
        tokens = [t for t in re.split(r"[^a-z0-9]+", full_lower) if t]
        matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in tokens or kw in full_lower]
        suspicious_kw_count = float(len(set(matched_keywords)))

        # Brand impersonation check: brand name appears in subdomain or path, NOT as the registered domain
        reg_domain = cls.extract_registered_domain(raw_stripped)
        reg_domain_base = reg_domain.split(".")[0] if reg_domain else ""
        subdomain_and_path = (hostname[: max(0, len(hostname) - len(reg_domain))] + " " + path.lower() + " " + query.lower())
        impersonated_brands = [
            b.lower()
            for b in TARGETED_BRANDS
            if b.lower() in subdomain_and_path and b.lower() != reg_domain_base
        ]
        brand_impersonation = 1.0 if impersonated_brands else 0.0

        host_entropy = shannon_entropy(hostname)
        url_entropy = shannon_entropy(raw_stripped)
        longest_token = float(max((len(t) for t in tokens), default=0))
        double_slash_path = 1.0 if "//" in path else 0.0
        exec_ext = 1.0 if re.search(r"\.(exe|apk|bat|scr|vbs|msi|jar|zip|rar|sh)(\?|$)", full_lower) else 0.0

        features: Dict[str, float] = {
            "url_length": float(url_len),
            "hostname_length": float(host_len),
            "path_length": float(path_len),
            "query_length": float(query_len),
            "has_ip_address": has_ip,
            "has_https": has_https,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_Rule_at": num_at,
            "num_question_marks": num_qmark,
            "num_ampersands": num_amp,
            "num_equals": num_eq,
            "num_underscores": num_underscore,
            "num_slashes": num_slashes,
            "num_percent_encoding": num_percent,
            "digit_ratio_url": round(digit_ratio_url, 4),
            "digit_ratio_hostname": round(digit_ratio_host, 4),
            "special_char_ratio": round(special_ratio, 4),
            "subdomain_count": subdomain_count,
            "path_depth": path_depth,
            "has_non_standard_port": has_non_std_port,
            "has_punycode": has_punycode,
            "is_shortener": is_shortener,
            "suspicious_tld": is_suspicious_tld,
            "trusted_tld": is_trusted_tld,
            "suspicious_keyword_count": suspicious_kw_count,
            "brand_in_subdomain_or_path": brand_impersonation,
            "hostname_entropy": round(host_entropy, 4),
            "url_entropy": round(url_entropy, 4),
            "longest_token_length": longest_token,
            "has_double_slash_in_path": double_slash_path,
            "has_executable_extension": exec_ext,
        }

        # Build human-readable forensic evidence
        evidence: List[str] = []
        if has_ip > 0:
            evidence.append(f"Raw IP address used as hostname ({hostname}) instead of registered domain")
        if brand_impersonation > 0:
            evidence.append(
                f"Brand impersonation indicator: {', '.join(sorted(set(impersonated_brands)))} found outside registered domain ({reg_domain})"
            )
        if num_at > 0:
            evidence.append("Contains '@' symbol in URL (credential/redirect obfuscation technique)")
        if has_punycode > 0:
            evidence.append("Contains Punycode ('xn--') internationalized domain homograph indicator")
        if is_suspicious_tld > 0:
            evidence.append(f"High-risk top-level domain (.{tld}) frequently abused in phishing campaigns")
        if num_hyphens >= 2:
            evidence.append(f"Excessive hyphens in hostname ({int(num_hyphens)} hyphens in {hostname})")
        if subdomain_count >= 2:
            evidence.append(f"Deep subdomain nesting ({int(subdomain_count)} subdomain levels)")
        if suspicious_kw_count >= 1:
            top_kws = sorted(set(matched_keywords))[:4]
            evidence.append(f"Credential/phishing keywords in URL: {', '.join(top_kws)}")
        if url_len > 75:
            evidence.append(f"Abnormally long URL ({url_len} characters)")
        if digit_ratio_host > 0.18:
            evidence.append(f"High numeric character density in hostname ({digit_ratio_host:.0%})")
        if has_non_std_port > 0:
            evidence.append(f"Non-standard network port specified in URL (port {port})")
        if exec_ext > 0:
            evidence.append("URL points directly to a potentially malicious executable or archive payload")
        if is_shortener > 0:
            evidence.append(f"URL shortener service ({hostname}) masks final destination domain")
        if has_https == 0.0:
            evidence.append("Unencrypted HTTP scheme or missing TLS transport indicator")

        if not evidence:
            evidence.append(f"Standard URL structure on registered domain '{reg_domain}' with no lexical anomalies")

        return features, evidence

    @classmethod
    def transform_single(cls, raw_url: str) -> np.ndarray:
        """Return a 1D numpy float64 feature vector for a single URL."""
        features, _ = cls.extract_features_and_evidence(raw_url)
        return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float64)

    @classmethod
    def transform_batch(cls, urls: List[str]) -> np.ndarray:
        """Return a 2D numpy float64 matrix of shape (N, 32) for a list of URLs."""
        return np.vstack([cls.transform_single(u) for u in urls])
