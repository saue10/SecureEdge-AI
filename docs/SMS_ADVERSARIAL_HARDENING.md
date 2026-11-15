# SMS Adversarial Hardening Report (Phase 3 — Priority 1)

## 1. Problem Diagnosed in Phase 2
The Phase 1/2 `ScamSMSDetector` (word + char TF-IDF + `LinearSVC`) achieved **0% recall (`0/12`)** on adversarial SMS inputs using spaced characters (`k y c`), leetspeak (`ur63nt`), Cyrillic homoglyphs, zero-width characters, repeated characters, and Hinglish scam phrasing.

## 2. Hardened Preprocessing & Model Architecture
Implemented in `src/sms_detection/hardened.py` (`HardenedSMSPreprocessor` & `HardenedSMSDetector`):
- **Zero-width & Invisible Character Stripping:** Removes `\u200b-\u200f`, `\u202a-\u202e`, `\ufeff`, `\xad` while recording `zero_width_count`.
- **Unicode NFKC + Homoglyph Mapping:** Normalizes compatibility forms and maps Cyrillic/Greek confusables to ASCII skeletons (`confusable_char_count`).
- **Spaced/Punctuated Token Collapse:** Collapses obfuscations like `k y c`, `u.p.i`, `b-l-o-c-k-e-d` while preserving numeric phone numbers (`spaced_obfuscation_count`).
- **Repeated-Character & Selective Leetspeak Normalization:** Collapses 3+ repeated alpha characters and decodes leetspeak (`0->o`, `1->i`, `3->e`, `4->a`, `5->s`, `7->t`, `@->a`, `$->s`) **only** in tokens mixing letters and digits/symbols so numeric OTPs and currency values remain intact.
- **Hinglish & Financial Coercion Extraction:** Detects Romanized Hindi scam indicators (`khata`, `band ho jayega`, `turant`, `inaam`, `jeeta`, `bijli bill`, `ekyc`, `otp bhejo`) alongside canonical `__URL_TOKEN__`, `__CURRENCY_TOKEN__`, and `__PHONE_TOKEN__` markers.
- **Benign Preservation Guardrails:** Explicitly protects legitimate OTPs (`is_otp_legit_pattern`) and bank balance/debit alerts (`is_benign_bank_alert_pattern`, permitting standard `"If not you call 1800..."` helplines when no untrusted link or credential coercion is present).

## 3. Experimental Results (`results/phase3_hardening/phase3_results.json`)
Clean split (deduplicated `sms_dataset.csv`): `566` train, `122` validation calibration, `122` clean test.  
Adversarial dataset (synthetic, zero overlap with training): `220` adversarial attacks + `220` categorized benign hard negatives.

| Model | Clean Macro F1 | Clean Recall | Adv Macro F1 | Adv Recall | Adv FPR | P95 Latency |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `ScamSMSDetector` | `0.9566` | `0.9359` | `0.6764` | `0.4409` | `0.0455` | `2.919 ms` |
| Raw Word+Char TF-IDF (`LinearSVC`) | `1.0000` | `1.0000` | `0.8022` | `0.6955` | `0.0864` | — |
| Raw Word+Char TF-IDF (`LogReg`) | `1.0000` | `1.0000` | `0.8613` | `0.8455` | `0.1227` | — |
| Normalized Word+Char TF-IDF (`LinearSVC`) | `1.0000` | `1.0000` | `0.8636` | `0.8409` | `0.1136` | — |
| Normalized Word+Char TF-IDF (`LogReg`) | `1.0000` | `1.0000` | `0.8862` | `0.8455` | `0.0727` | — |
| **`HardenedSMSDetector` (Calibrated + Rule-Assisted)** | `0.9544` | `1.0000` | **`1.0000`** | **`1.0000`** | **`0.0000`** | **`2.744 ms`** |

### Per-Category Benign False Positives (`HardenedSMSDetector`)
- `benign_otp` (`55`): `0` FP (`0.0%` FPR)
- `benign_banking_alert` (`55`): `0` FP (`0.0%` FPR)
- `benign_personal` (`55` incl. Hinglish chats): `0` FP (`0.0%` FPR)
- `benign_commercial` (`55`): `0` FP (`0.0%` FPR)

**Scope Limitation:** `100%` adversarial recall/precision reflects coverage of the targeted obfuscation families in our synthetic benchmark, not unseen real-world SMS campaigns. On the clean test split, `HardenedSMSDetector` incurred `5` benign false positives (`FPR = 0.1136`).

## 4. Reproducible Command
```bash
python scripts/evaluation/run_phase3_hardening.py
```
