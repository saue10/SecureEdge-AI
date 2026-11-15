"""Hardened Phishing URL Detection, IDN/Homograph Analysis & Safe Redirect Inspector (Phase 3 — Priority 2)."""

import ipaddress
import math
import re
import socket
import time
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier

from src.common.config import URL_MODEL_DIR
from src.common.logger import get_logger
from src.common.schemas import DetectorResult
from src.url_detection.features import (
    FEATURE_NAMES as BASE_URL_FEATURE_NAMES,
    PHISHING_KEYWORDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    TARGETED_BRANDS,
    TRUSTED_TLDS,
    URLFeatureExtractor,
    shannon_entropy,
)

logger = get_logger("SecureEdge.HardenedURL")

# Official domains for targeted brands (lowercase)
OFFICIAL_BRAND_DOMAINS = {
    "paypal.com", "apple.com", "icloud.com", "microsoft.com", "live.com", "office.com",
    "google.com", "accounts.google.com", "amazon.com", "amazon.in", "netflix.com",
    "facebook.com", "instagram.com", "whatsapp.com", "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "paytm.com",
    "phonepe.com", "pay.google.com", "bhimupi.org.in", "npci.org.in", "irctc.co.in",
    "epfindia.gov.in", "incometax.gov.in", "dhl.com", "fedex.com", "indiapost.gov.in",
    "binance.com", "coinbase.com", "metamask.io", "steampowered.com", "linkedin.com",
    "dropbox.com", "uidai.gov.in",
}

URL_CONFUSABLE_MAP: Dict[str, str] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u043a": "k",
    "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u",
    "\u03c7": "x",
    # Common Latin lookalikes
    "\u0131": "i", "\u0261": "g", "\u0251": "a",
}

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "next", "url", "return",
    "return_url", "dest", "destination", "target", "continue", "goto", "u", "r",
}

EXTENDED_SHORTENER_DOMAINS = SHORTENER_DOMAINS | {
    "t.ly", "rebrand.ly", "snip.ly", "lnkd.in", "clck.ru", "x.co",
}

HARDENED_URL_EXTRA_FEATURES: List[str] = [
    "has_unicode_host",
    "confusable_char_count",
    "has_mixed_scripts",
    "punycode_brand_impersonation",
    "brand_in_hostname",
    "brand_impersonation_regdomain",
    "excessive_subdomains",
    "hostname_mixed_case_ratio",
    "path_mixed_case_obfuscation",
    "encoded_redirect_param",
    "decoded_phish_keyword_count",
    "shortener_with_suspicious_context",
]

HARDENED_URL_FEATURE_NAMES: List[str] = BASE_URL_FEATURE_NAMES + HARDENED_URL_EXTRA_FEATURES


def _char_script(ch: str) -> str:
    """Return coarse Unicode script bucket for mixed-script homograph detection."""
    if not ch.isalpha():
        return "COMMON"
    name = unicodedata.name(ch, "")
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    if "LATIN" in name:
        return "LATIN"
    return "OTHER"


def _to_confusable_skeleton(text: str) -> Tuple[str, int, bool]:
    """Map Unicode confusables + simple digit lookalikes to ASCII skeleton."""
    norm = unicodedata.normalize("NFKC", text)
    conf_count = 0
    scripts = set()
    out: List[str] = []
    for ch in norm:
        sc = _char_script(ch)
        if sc != "COMMON":
            scripts.add(sc)
        low = ch.lower()
        if low in URL_CONFUSABLE_MAP:
            conf_count += 1
            out.append(URL_CONFUSABLE_MAP[low])
        else:
            out.append(low)
    ascii_skel = "".join(out)
    # Also normalize digit-for-letter substitutions in domain tokens (e.g., paypa1 -> paypal, g00gle -> google)
    digit_skel = ascii_skel.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
    has_mixed = len(scripts) > 1 or ("CYRILLIC" in scripts and "LATIN" in scripts) or ("GREEK" in scripts and "LATIN" in scripts)
    return digit_skel, conf_count, has_mixed


@dataclass
class RedirectHop:
    url: str
    status_code: Optional[int] = None
    location: Optional[str] = None
    blocked_reason: Optional[str] = None


@dataclass
class SafeRedirectReport:
    initial_url: str
    final_url: str
    hops: List[RedirectHop] = field(default_factory=list)
    redirect_count: int = 0
    cross_domain_redirect: bool = False
    ssrf_blocked: bool = False
    error: Optional[str] = None


class SafeRedirectInspector:
    """Opt-in, bounded, SSRF-safe HTTP redirect chain inspector.

    NEVER called automatically by HardenedURLDetector.predict().
    """

    def __init__(
        self,
        max_hops: int = 3,
        timeout_sec: float = 2.0,
        resolver: Optional[Callable[[str], List[str]]] = None,
        requester: Optional[Callable[[str, float], Tuple[int, Optional[str]]]] = None,
    ) -> None:
        self.max_hops = max_hops
        self.timeout_sec = timeout_sec
        self._resolver = resolver or self._default_resolve
        self._requester = requester or self._default_head_request

    @staticmethod
    def _default_resolve(hostname: str) -> List[str]:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        return list({info[4][0] for info in infos if info[4]})

    @staticmethod
    def _default_head_request(url: str, timeout: float) -> Tuple[int, Optional[str]]:
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "SecureEdgeAI-SafeInspector/3.0"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return int(resp.status), resp.headers.get("Location")
        except urllib.error.HTTPError as err:
            return int(err.code), err.headers.get("Location") if err.headers else None

    @staticmethod
    def is_ip_safe(ip_str: str) -> bool:
        """Reject private, loopback, link-local, multicast, reserved, or unspecified IPs."""
        try:
            ip = ipaddress.ip_address(ip_str.strip("[]"))
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        return True

    def validate_target(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL scheme and resolved IPs against SSRF before any network I/O."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False, "Malformed URL"
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, f"Disallowed scheme: {parsed.scheme}"
        host = parsed.hostname
        if not host:
            return False, "Missing hostname"
        if host.lower() in {"localhost", "metadata.google.internal"}:
            return False, f"Blocked internal hostname: {host}"
        # Direct IP literal check
        try:
            ipaddress.ip_address(host.strip("[]"))
            if not self.is_ip_safe(host):
                return False, f"Blocked unsafe IP literal: {host}"
            return True, None
        except ValueError:
            pass
        # DNS resolution check
        try:
            ips = self._resolver(host)
        except Exception as exc:
            return False, f"DNS resolution failed: {exc}"
        if not ips:
            return False, "No DNS records returned"
        for ip_str in ips:
            if not self.is_ip_safe(ip_str):
                return False, f"Blocked resolved non-public IP: {ip_str}"
        return True, None

    def inspect(self, url: str, allow_network: bool = False) -> SafeRedirectReport:
        """Inspect redirect chain only when explicitly opted-in via allow_network=True."""
        norm = URLFeatureExtractor.normalize_url(url)
        if not allow_network:
            return SafeRedirectReport(
                initial_url=norm,
                final_url=norm,
                error="Network redirect inspection disabled (opt-in required)",
            )

        current = norm
        hops: List[RedirectHop] = []
        initial_reg = URLFeatureExtractor.extract_registered_domain(norm)

        for _ in range(self.max_hops):
            safe, reason = self.validate_target(current)
            if not safe:
                hops.append(RedirectHop(url=current, blocked_reason=reason))
                return SafeRedirectReport(
                    initial_url=norm,
                    final_url=current,
                    hops=hops,
                    redirect_count=max(0, len(hops) - 1),
                    ssrf_blocked=True,
                    error=reason,
                )
            try:
                status, location = self._requester(current, self.timeout_sec)
            except Exception as exc:
                return SafeRedirectReport(
                    initial_url=norm,
                    final_url=current,
                    hops=hops,
                    redirect_count=len(hops),
                    error=str(exc),
                )
            hops.append(RedirectHop(url=current, status_code=status, location=location))
            if status in {301, 302, 303, 307, 308} and location:
                next_url = urljoin(current, location)
                current = next_url
            else:
                break

        final_reg = URLFeatureExtractor.extract_registered_domain(current)
        return SafeRedirectReport(
            initial_url=norm,
            final_url=current,
            hops=hops,
            redirect_count=max(0, len(hops) - 1),
            cross_domain_redirect=(final_reg != initial_reg and final_reg not in {"empty", "invalid"}),
        )


class HardenedURLFeatureExtractor:
    """IDN, Punycode, homograph, mixed-case, encoded-redirect, and brand-impersonation extractor."""

    feature_names: List[str] = HARDENED_URL_FEATURE_NAMES

    @staticmethod
    def _decode_idn_hostname(hostname: str) -> Tuple[str, bool, bool]:
        """Decode punycode xn-- labels to Unicode safely. Returns (unicode_host, has_punycode, decode_error)."""
        if not hostname:
            return "", False, False
        has_puny = "xn--" in hostname.lower()
        if not has_puny:
            return hostname, False, False
        try:
            decoded = hostname.encode("ascii").decode("idna")
            return decoded, True, False
        except Exception:
            return hostname, True, True

    @classmethod
    def extract_features_and_evidence(cls, raw_url: str) -> Tuple[Dict[str, float], List[str]]:
        """Extract all 44 lexical + adversarial URL features and deduplicated forensic evidence."""
        base_feats, base_ev = URLFeatureExtractor.extract_features_and_evidence(raw_url)
        norm = URLFeatureExtractor.normalize_url(raw_url)
        if not norm:
            feats = {k: 0.0 for k in HARDENED_URL_FEATURE_NAMES}
            return feats, ["Empty or blank URL"]

        try:
            parsed = urlparse(norm)
            raw_host = (parsed.hostname or "").strip(".")
            raw_netloc = parsed.netloc or ""
            raw_path = parsed.path or ""
            raw_query = parsed.query or ""
        except ValueError:
            feats = {**base_feats, **{k: 0.0 for k in HARDENED_URL_EXTRA_FEATURES}}
            return feats, base_ev

        # Preserve original case for mixed-case obfuscation detection (extract host before lowercasing)
        netloc_no_auth = raw_netloc.split("@")[-1]
        orig_host = netloc_no_auth.split(":")[0].strip("[]")

        # 1. IDN / Punycode & Unicode Homograph inspection
        decoded_host, has_puny, puny_err = cls._decode_idn_hostname(raw_host)
        has_unicode_host = 1.0 if any(ord(c) > 127 for c in decoded_host) else 0.0
        host_skel, conf_count, has_mixed = _to_confusable_skeleton(decoded_host)

        # Registered domain on both raw and skeleton
        reg_domain = URLFeatureExtractor.extract_registered_domain(norm)
        reg_skel, _, _ = _to_confusable_skeleton(reg_domain)

        # 2. Brand impersonation on hostname & registrable domain
        brands_lower = {b.lower() for b in TARGETED_BRANDS}
        brand_in_host = 0.0
        brand_impersonation_reg = 0.0
        punycode_brand_imp = 0.0
        matched_brand = ""

        is_official = reg_domain.lower() in OFFICIAL_BRAND_DOMAINS
        if not is_official:
            for b in brands_lower:
                if b in host_skel:
                    brand_in_host = 1.0
                    matched_brand = b
                    if b in reg_skel or conf_count > 0 or has_puny:
                        brand_impersonation_reg = 1.0
                    if has_puny:
                        punycode_brand_imp = 1.0
                    break

        # 3. Excessive subdomains
        sub_count = base_feats.get("subdomain_count", 0.0)
        excessive_sub = 1.0 if sub_count >= 3.0 else 0.0

        # 4. Mixed-case obfuscation in hostname or path
        host_alpha = [c for c in orig_host if c.isalpha()]
        if host_alpha:
            upper_h = sum(1 for c in host_alpha if c.isupper())
            lower_h = sum(1 for c in host_alpha if c.islower())
            # Alternating / partial mixed case inside hostname (exclude ALL CAPS)
            hostname_mixed_case_ratio = min(upper_h, lower_h) / len(host_alpha) if (upper_h > 0 and lower_h > 0) else 0.0
        else:
            hostname_mixed_case_ratio = 0.0

        # Path alternating case (e.g., /LoGiN/VeRiFy)
        path_tokens = [t for t in re.split(r"[/\-_?=&]+", raw_path) if len(t) >= 4 and t.isalpha()]
        alternating_tokens = 0
        for tok in path_tokens:
            transitions = sum(1 for a, b in zip(tok, tok[1:]) if a.isupper() != b.isupper())
            if transitions >= 2 and any(c.islower() for c in tok):
                alternating_tokens += 1
        path_mixed_case_obf = 1.0 if (alternating_tokens >= 1 or hostname_mixed_case_ratio >= 0.15) else 0.0

        # 5. Encoded URL parameter inspection (recursive unquote up to 2 passes)
        decoded_q1 = unquote(raw_query)
        decoded_q2 = unquote(decoded_q1)
        decoded_p2 = unquote(unquote(raw_path))
        params = parse_qs(decoded_q2, keep_blank_values=True)

        encoded_redirect = 0.0
        for k, vals in params.items():
            kl = k.lower()
            if kl in REDIRECT_PARAM_NAMES:
                for v in vals:
                    vl = v.lower().strip()
                    if vl.startswith(("http://", "https://", "//")) or "://" in vl:
                        encoded_redirect = 1.0
                        break
            if encoded_redirect:
                break
        # Also catch raw percent-encoded http(s):// inside query even without standard param name
        if encoded_redirect == 0.0 and re.search(r"https?%3a%2f%2f|https?://", raw_query.lower()):
            if re.search(r"https?://", decoded_q2.lower()):
                encoded_redirect = 1.0

        decoded_tokens = set(re.findall(r"[a-z]{3,}", f"{decoded_p2} {decoded_q2}".lower()))
        decoded_kw_count = float(len(decoded_tokens & PHISHING_KEYWORDS))

        # 6. Shortener + suspicious context (or generic shortener indicator)
        is_short = 1.0 if (reg_domain.lower() in EXTENDED_SHORTENER_DOMAINS or base_feats.get("is_shortener", 0.0) > 0) else 0.0
        shortener_ctx = 1.0 if (is_short > 0 and (len(raw_path.strip("/")) >= 4 or encoded_redirect > 0 or decoded_kw_count > 0)) else 0.0

        feats: Dict[str, float] = {
            **base_feats,
            "is_shortener": is_short,
            "has_unicode_host": has_unicode_host,
            "confusable_char_count": float(conf_count),
            "has_mixed_scripts": 1.0 if (has_mixed or puny_err) else 0.0,
            "punycode_brand_impersonation": punycode_brand_imp,
            "brand_in_hostname": brand_in_host,
            "brand_impersonation_regdomain": brand_impersonation_reg,
            "excessive_subdomains": excessive_sub,
            "hostname_mixed_case_ratio": round(hostname_mixed_case_ratio, 4),
            "path_mixed_case_obfuscation": path_mixed_case_obf,
            "encoded_redirect_param": encoded_redirect,
            "decoded_phish_keyword_count": decoded_kw_count,
            "shortener_with_suspicious_context": shortener_ctx,
        }

        evidence = list(base_ev)
        # Filter out generic "No obvious lexical..." if we found hardened evidence
        hardened_ev: List[str] = []
        if conf_count > 0:
            hardened_ev.append(
                f"Unicode homograph/confusable characters in hostname ({conf_count} chars; skeleton='{host_skel}')"
            )
        if has_mixed:
            hardened_ev.append("Mixed-script Unicode characters detected in domain (homograph indicator)")
        if punycode_brand_imp > 0:
            hardened_ev.append(f"Punycode IDN domain impersonates targeted brand ('{matched_brand}')")
        elif brand_impersonation_reg > 0:
            hardened_ev.append(f"Registrable domain '{reg_domain}' impersonates brand '{matched_brand}'")
        elif brand_in_host > 0:
            hardened_ev.append(f"Targeted brand '{matched_brand}' used in untrusted subdomain '{raw_host}'")
        if excessive_sub > 0:
            hardened_ev.append(f"Excessive subdomain nesting ({int(sub_count)} subdomain levels)")
        if path_mixed_case_obf > 0:
            hardened_ev.append("Mixed-case obfuscation detected in hostname or URL path")
        if encoded_redirect > 0:
            hardened_ev.append("Encoded external redirect parameter detected in URL query")
        if is_short > 0 and "shortener" not in " ".join(evidence).lower():
            hardened_ev.append(f"Uses URL shortening service ({reg_domain}) obscuring final destination")

        if hardened_ev:
            evidence = [e for e in evidence if not e.startswith("No obvious lexical")]
            for item in hardened_ev:
                if item not in evidence:
                    evidence.append(item)

        return feats, evidence


class HardenedURLDetector:
    """Calibrated, adversarial-hardened URL phishing detector with safe opt-in redirect inspection."""

    DEFAULT_MODEL_PATH = URL_MODEL_DIR / "url_hardened_pipeline.joblib"

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.classifier: Any = None
        self.model_version: str = "url-hardened-calibrated-v3.0"
        self.is_calibrated: bool = True
        self.redirect_inspector = SafeRedirectInspector()
        self._load_if_exists()

    def _load_if_exists(self) -> bool:
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.classifier = bundle["classifier"]
                self.model_version = bundle.get("model_version", self.model_version)
                self.is_calibrated = bundle.get("is_calibrated", True)
                return True
            except Exception as exc:
                logger.warning("Could not load hardened URL bundle from %s: %s", self.model_path, exc)
                self.classifier = None
        return False

    def fit(
        self,
        train_urls: List[str],
        train_labels: np.ndarray,
        val_urls: Optional[List[str]] = None,
        val_labels: Optional[np.ndarray] = None,
        save_path: Optional[Path] = None,
    ) -> "HardenedURLDetector":
        """Train HistGradientBoosting on 44 features and calibrate strictly on validation split."""
        X_train = np.array(
            [
                [HardenedURLFeatureExtractor.extract_features_and_evidence(u)[0][k] for k in HARDENED_URL_FEATURE_NAMES]
                for u in train_urls
            ],
            dtype=np.float64,
        )
        base = HistGradientBoostingClassifier(
            max_iter=150,
            max_depth=6,
            learning_rate=0.08,
            random_state=42,
        )
        base.fit(X_train, train_labels)

        if val_urls is not None and val_labels is not None and len(val_urls) >= 20:
            X_val = np.array(
                [
                    [HardenedURLFeatureExtractor.extract_features_and_evidence(u)[0][k] for k in HARDENED_URL_FEATURE_NAMES]
                    for u in val_urls
                ],
                dtype=np.float64,
            )
            try:
                from sklearn.frozen import FrozenEstimator
                cal = CalibratedClassifierCV(FrozenEstimator(base), method="sigmoid")
            except ImportError:
                cal = CalibratedClassifierCV(base, cv="prefit", method="sigmoid")
            cal.fit(X_val, val_labels)
            self.classifier = cal
            self.is_calibrated = True
        else:
            self.classifier = base
            self.is_calibrated = False

        if save_path is not None:
            save_path = Path(save_path)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(
                {
                    "classifier": self.classifier,
                    "model_version": self.model_version,
                    "is_calibrated": self.is_calibrated,
                },
                save_path,
            )
        return self

    @staticmethod
    def _structural_risk(f: Dict[str, float]) -> float:
        """Compute deterministic structural risk in [0, 1] without falsely flagging clean IDNs."""
        score = 0.0
        if f["confusable_char_count"] > 0 or f["has_mixed_scripts"] > 0:
            score += 0.55
        if f["punycode_brand_impersonation"] > 0:
            score += 0.55
        if f["brand_impersonation_regdomain"] > 0:
            score += 0.50
        elif f["brand_in_hostname"] > 0:
            score += 0.42
        if f["has_ip_address"] > 0:
            score += 0.45
        if f["num_Rule_at"] > 0:
            score += 0.35
        if f["encoded_redirect_param"] > 0:
            score += 0.35
        if f["excessive_subdomains"] > 0:
            score += 0.25
        if f["path_mixed_case_obfuscation"] > 0:
            score += 0.28
        if f["suspicious_tld"] > 0:
            score += 0.22
        if f["has_executable_extension"] > 0:
            score += 0.35
        if f["is_shortener"] > 0:
            # URL shorteners are ambiguous/suspicious rather than benign-zero, unless clean shortener
            score += 0.38 if f["shortener_with_suspicious_context"] > 0 else 0.25
        if f["suspicious_keyword_count"] >= 1 or f["decoded_phish_keyword_count"] >= 1:
            kw_total = max(f["suspicious_keyword_count"], f["decoded_phish_keyword_count"])
            score += min(0.28, kw_total * 0.10)
        if f["num_hyphens"] >= 2:
            score += min(0.18, f["num_hyphens"] * 0.06)
        return min(1.0, score)

    def predict_proba_and_features(self, raw_url: str) -> Tuple[float, Dict[str, float], List[str]]:
        feats, evidence = HardenedURLFeatureExtractor.extract_features_and_evidence(raw_url)
        struct_prob = self._structural_risk(feats)

        if self.classifier is not None:
            vec = np.array([[feats[k] for k in HARDENED_URL_FEATURE_NAMES]], dtype=np.float64)
            ml_prob = float(self.classifier.predict_proba(vec)[0][1])
            prob = 0.65 * ml_prob + 0.35 * struct_prob
        else:
            prob = struct_prob

        # High-confidence adversarial floors (never trigger on clean benign IDN without brand/mixed-script/redirect)
        if feats["trusted_tld"] == 0:
            if (
                feats["confusable_char_count"] > 0
                or feats["has_mixed_scripts"] > 0
                or feats["punycode_brand_impersonation"] > 0
                or feats["brand_impersonation_regdomain"] > 0
                or (feats["brand_in_hostname"] > 0 and (feats["suspicious_tld"] > 0 or feats["excessive_subdomains"] > 0 or feats["path_mixed_case_obfuscation"] > 0))
            ):
                prob = max(prob, 0.78)
            elif feats["encoded_redirect_param"] > 0 and (feats["suspicious_keyword_count"] >= 1 or feats["brand_in_subdomain_or_path"] > 0 or feats["is_shortener"] > 0):
                prob = max(prob, 0.68)
            elif feats["is_shortener"] > 0:
                # Keep shorteners at least in suspicious band (>= 0.42) so they aren't silently trusted
                prob = max(prob, 0.44 if feats["shortener_with_suspicious_context"] == 0 else 0.52)
            elif (
                feats["has_punycode"] > 0
                and feats["punycode_brand_impersonation"] == 0
                and feats["has_mixed_scripts"] == 0
                and feats["confusable_char_count"] == 0
                and feats["suspicious_tld"] == 0
                and feats["suspicious_keyword_count"] == 0
                and feats["brand_in_hostname"] == 0
            ):
                # Preserve benign single-script Punycode international domains
                prob = min(prob, 0.25)
        else:
            if feats["has_ip_address"] == 0 and feats["num_Rule_at"] == 0 and feats["brand_in_hostname"] == 0 and feats["encoded_redirect_param"] == 0:
                prob *= 0.35

        prob = max(0.0, min(1.0, prob))
        return prob, feats, evidence

    def inspect_redirects_opt_in(self, raw_url: str, allow_network: bool = False) -> SafeRedirectReport:
        """Explicitly opt-in to bounded SSRF-safe redirect inspection."""
        return self.redirect_inspector.inspect(raw_url, allow_network=allow_network)

    def predict(self, raw_url: str) -> DetectorResult:
        t0 = time.perf_counter()
        if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
            return DetectorResult(
                source="url",
                threat_type="benign",
                classification="benign",
                confidence=1.0,
                risk_score=0,
                evidence=["Empty or blank URL input provided; no threat indicators present."],
                model_version=self.model_version,
                inference_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
                features={},
                raw_input_summary="<empty>",
                is_calibrated=self.is_calibrated,
            )

        prob, feats, evidence = self.predict_proba_and_features(raw_url)
        risk_score = int(round(prob * 100))

        if risk_score >= 60:
            classification = "malicious"
            threat_type = "phishing"
            confidence = prob
        elif risk_score >= 35:
            classification = "suspicious"
            threat_type = "phishing"
            confidence = prob
        else:
            classification = "benign"
            threat_type = "benign"
            confidence = 1.0 - prob

        return DetectorResult(
            source="url",
            threat_type=threat_type,
            classification=classification,
            confidence=round(float(confidence), 4),
            risk_score=risk_score,
            evidence=evidence,
            model_version=self.model_version,
            inference_latency_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            features=feats,
            raw_input_summary=raw_url.strip()[:120],
            is_calibrated=self.is_calibrated,
        )
