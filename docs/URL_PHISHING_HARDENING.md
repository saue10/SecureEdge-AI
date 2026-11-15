# URL Phishing Hardening & Safe Redirect Inspection (Phase 3 — Priority 2)

## 1. Phase 2 Weaknesses Addressed
The Phase 2 audit found `PhishingURLDetector` missed `6/14` adversarial URLs (`57.14%` recall), failing on Cyrillic confusables, Unicode homographs, Punycode IDN impersonation, URL shorteners, excessive subdomains, mixed-case obfuscation, and encoded redirect parameters.

## 2. Hardened Architecture (`src/url_detection/hardened.py`)
- **`HardenedURLFeatureExtractor` (44 features):**
  - **IDN & Punycode Decoding:** Safely decodes `xn--` labels via `idna`, checking decoded hostnames for mixed scripts (`has_mixed_scripts`) and confusable characters (`confusable_char_count`).
  - **Brand Impersonation via Registrable Domain:** Maps hostnames/registrable domains to ASCII confusable skeletons and checks against `TARGETED_BRANDS` excluding `OFFICIAL_BRAND_DOMAINS`.
  - **Mixed-Case & Excessive Subdomains:** Computes `hostname_mixed_case_ratio`, alternating-case path tokens (`path_mixed_case_obfuscation`), and `excessive_subdomains` (`>= 3`).
  - **Encoded Redirect Parameter Inspection:** Recursively URL-decodes query parameters (`unquote` up to 2 passes) to flag embedded `http://` / `https://` redirect targets and decoded phishing keywords.
  - **Clean International Domain Preservation:** Single-script Punycode/Unicode IDNs without mixed scripts, confusables, suspicious TLDs, or brand impersonation are dampened (`<= 0.25`) to prevent false positives on legitimate international websites.
- **`SafeRedirectInspector` (Opt-in, Bounded, SSRF-Safe):**
  - Never invoked automatically during `predict()`.
  - Requires explicit `allow_network=True`, restricts schemes to `http`/`https`, resolves DNS and blocks private/loopback/link-local/multicast/reserved IPs (including `127.0.0.1` and `169.254.169.254`) at every redirect hop (`max_hops = 3`, `timeout = 2.0s`).

## 3. Experimental Results (`results/phase3_hardening/phase3_results.json`)
Clean group split by `registered_domain`: `1,127` train, `246` validation calibration, `227` clean test.  
Adversarial dataset (synthetic): `230` attacks + `220` benign hard negatives.

| Model | Clean Macro F1 | Clean FPR | Adv Recall | Adv Macro F1 | P50 Latency | P95 Latency |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `PhishingURLDetector` | `0.9416` | `0.1250` | `0.6087` (`140/230`) | `0.6768` | `21.148 ms` | `28.552 ms` |
| **`HardenedURLDetector`** | **`0.9867`** | **`0.0288`** | **`0.9391` (`216/230`)** | **`0.8447`** | **`3.115 ms`** | **`4.054 ms`** |

### Benign Hard-Negative Breakdown (`HardenedURLDetector`)
- `benign_idn` (`55`): `0` flagged (`0.0%` FPR)
- `benign_official_brand` (`55`): `0` flagged (`0.0%` FPR)
- `benign_research_blog` (`55`): `0` flagged (`0.0%` FPR)
- `benign_shortener` (`55`): `55/55` flagged as `suspicious` (intentional policy: bare shorteners obscure destination and map to `suspicious_unknown` unless resolved via opt-in `SafeRedirectInspector`).

**Remaining Gap:** `14/230` (`6.09%`) adversarial URLs (primarily bare generic-host encoded redirects lacking phishing keywords) were missed offline without live redirect resolution.
