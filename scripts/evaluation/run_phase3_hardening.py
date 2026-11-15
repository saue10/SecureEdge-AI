"""Phase 3 Hardening, Adversarial Evaluation, Model Comparison & Edge Benchmarking.

Runs cleanly on Windows 11 CPU-only environment with zero train/test leakage.
Saves all outputs to results/phase3_hardening/phase3_results.json.
"""

import csv
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import psutil
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.svm import LinearSVC

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.network_detection.adaptive import AdaptiveNetworkDetector
from src.network_detection.context_aware import ContextAwareNetworkDetector
from src.sms_detection.detector import ScamSMSDetector
from src.sms_detection.hardened import HardenedSMSDetector, HardenedSMSPreprocessor
from src.threat_engine.calibrated_policy import CalibratedThreatEngine
from src.url_detection.detector import PhishingURLDetector
from src.url_detection.features import URLFeatureExtractor
from src.url_detection.hardened import HardenedURLDetector

OUT_DIR = ROOT / "results" / "phase3_hardening"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, latencies_ms: List[float]) -> Dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / max(fp + tn, 1))
    fnr = float(fn / max(fn + tp, 1))
    return {
        "count": int(len(y_true)),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "p50_latency_ms": round(float(np.percentile(latencies_ms, 50)), 3) if latencies_ms else 0.0,
        "p95_latency_ms": round(float(np.percentile(latencies_ms, 95)), 3) if latencies_ms else 0.0,
    }


def generate_adversarial_sms_dataset(seed: int = 2026) -> List[Dict[str, Any]]:
    """Generate >= 220 adversarial SMS attacks and >= 220 categorized benign hard negatives."""
    rng = random.Random(seed)
    rows: List[Dict[str, Any]] = []

    banks = ["SBI", "HDFC", "ICICI", "Axis", "Paytm", "PhonePe", "Kotak"]
    urls_obf = [
        "http://sbi-kyc-update99.xyz/verify",
        "https://bit . ly / 3xKycNow",
        "http://hdfc-pan-verify[.]top/login",
        "http://paytm-refund-claim.icu/go",
        "http://rb.gy/k9verify",
    ]
    phones = ["+91 9811223344", "9876501234", "+91-8800112233", "9123456789"]

    # 1. Spaced obfuscation (35)
    for i in range(35):
        b = banks[i % len(banks)]
        u = urls_obf[i % len(urls_obf)]
        txt = f"U R G E N T: Your {b} k y c is e x p i r e d. A/c b l o c k e d today. C l i c k {u} to v e r i f y #{i}"
        rows.append({"text": txt, "label": 1, "category": "spaced_obfuscation"})

    # 2. Leetspeak obfuscation (35)
    for i in range(35):
        b = banks[i % len(banks)]
        u = urls_obf[(i + 1) % len(urls_obf)]
        txt = f"UR63NT {b} 4lert: P4N kyc upd4t3 r3quir3d w1th1n 2 hrs or b4nk 4cc0unt bl0ck3d. Cl1ck {u} #{i}"
        rows.append({"text": txt, "label": 1, "category": "leetspeak"})

    # 3. Cyrillic / Greek homoglyph obfuscation (35)
    for i in range(35):
        p = phones[i % len(phones)]
        # Replace ASCII a,e,o,p,c with Cyrillic lookalikes
        txt = f"FІNAL NОTІCE: Yоur Рaytm wаllet will be susреnded tоday. Cаll {p} or vеrify kус ref#{100+i}"
        rows.append({"text": txt, "label": 1, "category": "unicode_homoglyph"})

    # 4. Zero-width invisible chars (35)
    zw = "\u200b"
    for i in range(35):
        b = banks[i % len(banks)]
        u = urls_obf[(i + 2) % len(urls_obf)]
        txt = f"U{zw}R{zw}G{zw}E{zw}N{zw}T {b}: K{zw}Y{zw}C p{zw}e{zw}n{zw}d{zw}i{zw}n{zw}g! C{zw}l{zw}i{zw}c{zw}k {u} ref{i}"
        rows.append({"text": txt, "label": 1, "category": "zero_width"})

    # 5. Repeated character obfuscation (35)
    for i in range(35):
        b = banks[i % len(banks)]
        p = phones[(i + 1) % len(phones)]
        txt = f"UUUURRRGGGEEENT!! {b} kkkkyyyyccc suspppenndedd! Share OOOTTTPPP or callll {p} now!! #{i}"
        rows.append({"text": txt, "label": 1, "category": "repeated_chars"})

    # 6. Hinglish scam messages (45)
    hinglish_templates = [
        "Aapka {b} khata aaj raat band ho jayega, turant eKYC verify karo {u} warna paise block honge #{i}",
        "Badhai ho! Aapne {amt} lakh ka inaam jeeta hai, claim karne ke liye link par dabaao {u} #{i}",
        "Aapka bijli bill pending hai, 2 ghante mein connection kat jayega, turant call karo {p} #{i}",
        "Sir aapke UPI par {amt} cashback aaya hai, PIN aur OTP bhejo ya {u} par update karo #{i}",
    ]
    for i in range(45):
        tpl = hinglish_templates[i % len(hinglish_templates)]
        txt = tpl.format(
            b=banks[i % len(banks)],
            u=urls_obf[i % len(urls_obf)],
            p=phones[i % len(phones)],
            amt=rng.choice([5, 10, 25, 50]),
            i=i,
        )
        rows.append({"text": txt, "label": 1, "category": "hinglish_scam"})

    # Benign Hard Negatives (4 categories x 55 = 220)
    # 1. Legitimate OTPs (55)
    for i in range(55):
        code = 100000 + (i * 7919) % 899999
        b = banks[i % len(banks)]
        txt = f"{code} is your OTP for {b} login/transaction. Valid for 10 mins. Do not share this OTP with anyone. Ref #{i}"
        rows.append({"text": txt, "label": 0, "category": "benign_otp"})

    # 2. Legitimate banking alerts (55)
    for i in range(55):
        b = banks[i % len(banks)]
        amt = 250 + i * 37
        bal = 15400 + i * 113
        txt = f"{b} Bank: A/c XX4821 debited for Rs.{amt}.00 via UPI Ref 6123{i:02d}. Avl Bal Rs.{bal}.00. If not you call 18002091111."
        rows.append({"text": txt, "label": 0, "category": "benign_banking_alert"})

    # 3. Personal & Hinglish casual messages (55)
    personal_templates = [
        "Hey, reaching office in 15 mins. Did you review the slides for meeting #{i}?",
        "Bhai kal subah 10 baje milte hain cafeteria mein, laptop le aana #{i}",
        "Mom transferred Rs {amt} for groceries, let me know when you get home #{i}",
        "Aaj shaam ko dinner plan hai kya? Call me once you are free #{i}",
    ]
    for i in range(55):
        txt = personal_templates[i % len(personal_templates)].format(i=i, amt=400 + i * 15)
        rows.append({"text": txt, "label": 0, "category": "benign_personal"})

    # 4. Commercial / delivery / appointment alerts (55)
    commercial_templates = [
        "Your order #ORD{i:04d} has been dispatched via BlueDart and will arrive tomorrow between 10 AM and 6 PM.",
        "Reminder: Your dental appointment at City Care Clinic is confirmed for Friday at 4:30 PM. Ref {i}.",
        "Your broadband plan renewal of Rs {amt} is scheduled on 25 Nov via autopay. Thank you for staying connected #{i}.",
        "IndiGo Flight 6E-{fl} check-in is now open. Please carry a valid photo ID at the airport gate #{i}.",
    ]
    for i in range(55):
        txt = commercial_templates[i % len(commercial_templates)].format(i=i, amt=799 + (i % 5) * 100, fl=200 + i)
        rows.append({"text": txt, "label": 0, "category": "benign_commercial"})

    return rows


def generate_adversarial_url_dataset(seed: int = 2026) -> List[Dict[str, Any]]:
    """Generate >= 220 adversarial phishing URLs and >= 220 benign hard negatives."""
    rows: List[Dict[str, Any]] = []
    brands = ["paypal", "sbi", "hdfc", "icici", "paytm", "google", "microsoft", "amazon", "apple"]

    # 1. Cyrillic & Greek confusable homographs (40)
    cyr_brands = [
        "раypal", "gооgle", "аmazon", "miсrosoft", "іcici", "рaytm", "арple", "sbі"
    ]
    for i in range(40):
        cb = cyr_brands[i % len(cyr_brands)]
        rows.append({
            "url": f"https://{cb}-security{i}.com/account/login?id={i}",
            "label": 1,
            "category": "cyrillic_homograph",
        })

    # 2. Punycode IDN brand impersonation (35)
    puny_hosts = [
        "xn--pypal-4ve.com",
        "xn--gogle-1qa.com",
        "xn--sbi-kyc-0va.xyz",
        "xn--icci-bank-q9a.top",
        "xn--paytm-updte-8qa.com",
    ]
    for i in range(35):
        ph = puny_hosts[i % len(puny_hosts)]
        rows.append({
            "url": f"https://{ph}/verify/session/{i}",
            "label": 1,
            "category": "punycode_impersonation",
        })

    # 3. URL shorteners with phishing context (35)
    shorteners = ["bit.ly", "tinyurl.com", "rb.gy", "cutt.ly", "t.co"]
    for i in range(35):
        sh = shorteners[i % len(shorteners)]
        b = brands[i % len(brands)]
        rows.append({
            "url": f"https://{sh}/{b}-kyc-verify-{i}?redirect=https%3A%2F%2Fevil-login.xyz%2Fauth",
            "label": 1,
            "category": "phish_shortener",
        })

    # 4. Suspicious brand-related registrable domains (40)
    tlds = ["xyz", "top", "icu", "vip", "click"]
    for i in range(40):
        b = brands[i % len(brands)]
        tld = tlds[i % len(tlds)]
        rows.append({
            "url": f"https://{b}-online-update-{i}.{tld}/kyc/confirm",
            "label": 1,
            "category": "brand_regdomain",
        })

    # 5. Excessive subdomains (30)
    for i in range(30):
        b = brands[i % len(brands)]
        rows.append({
            "url": f"https://login.secure.verify.kyc.{b}.portal-check{i}.com/auth/step2",
            "label": 1,
            "category": "excessive_subdomains",
        })

    # 6. Mixed-case obfuscation (25)
    for i in range(25):
        rows.append({
            "url": f"https://PaYpAl-SeCuRe-UpDaTe{i}.xyz/LoGiN/VeRiFy",
            "label": 1,
            "category": "mixed_case_obfuscation",
        })

    # 7. Encoded redirect parameters (25)
    for i in range(25):
        rows.append({
            "url": f"https://auth-helper{i}.org/oauth?next=https%3A%2F%2Fsbi-kyc-claim.xyz%2Flogin%3Fu%3D{i}",
            "label": 1,
            "category": "encoded_redirect",
        })

    # Benign Hard Negatives (220 total)
    # 1. Benign international IDN domains (55)
    idn_domains = [
        "münchen.de", "café-paris.fr", "zürich-tourismus.ch", "bücher-shop.de", "xn--mnchen-3ya.de"
    ]
    for i in range(55):
        dom = idn_domains[i % len(idn_domains)]
        rows.append({
            "url": f"https://{dom}/articles/guide-{i}?lang=en",
            "label": 0,
            "category": "benign_idn",
        })

    # 2. Benign URL shortener references (55) — tracked separately
    for i in range(55):
        sh = shorteners[i % len(shorteners)]
        rows.append({
            "url": f"https://{sh}/docs{i:03d}",
            "label": 0,
            "category": "benign_shortener",
        })

    # 3. Official brand domains (55)
    officials = [
        "https://www.paypal.com/in/home",
        "https://retail.onlinesbi.sbi/retail/login.htm",
        "https://www.icicibank.com/personal-banking",
        "https://www.incometax.gov.in/iec/foportal/",
        "https://accounts.google.com/ServiceLogin",
    ]
    for i in range(55):
        base = officials[i % len(officials)]
        rows.append({
            "url": f"{base}?ref=nav_{i}",
            "label": 0,
            "category": "benign_official_brand",
        })

    # 4. Tech docs / research blogs / benign queries (55)
    for i in range(55):
        rows.append({
            "url": f"https://security-research-journal{i}.org/posts/analyzing-paypal-phishing-trends?page={i%5+1}",
            "label": 0,
            "category": "benign_research_blog",
        })

    return rows


def generate_adversarial_network_dataset(seed: int = 2026) -> Tuple[List[Dict[str, Any]], np.ndarray, List[str]]:
    """Generate >= 220 evasive network attack flows and >= 220 benign hard-negative flows."""
    rng = random.Random(seed)
    flows: List[Dict[str, Any]] = []
    labels: List[int] = []
    cats: List[str] = []

    # 1. Evasive / Stealth / Adversarial Attacks (220)
    for i in range(60):  # Stealth low-slow multi-port probe
        dur = rng.uniform(5.0, 20.0)
        pkts = rng.randint(15, 45)
        b_cnt = pkts * rng.randint(60, 140)
        flows.append({
            "src_ip": f"10.20.1.{10 + (i % 15)}",
            "dst_ip": "192.168.1.10",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.22, 0.45),
            "rst_flag_ratio": rng.uniform(0.15, 0.35),
            "ack_flag_ratio": rng.uniform(0.30, 0.55),
            "fin_flag_ratio": 0.05,
            "unique_dst_ports_window": rng.randint(5, 14),
            "connection_frequency": rng.randint(4, 12),
            "payload_byte_ratio": rng.uniform(0.15, 0.45),
        })
        labels.append(1)
        cats.append("adv_stealth_probe")

    for i in range(60):  # Throttled sustained outbound data exfiltration
        dur = rng.uniform(3.0, 12.0)
        pkts = rng.randint(300, 900)
        bpp = rng.randint(900, 1380)
        b_cnt = pkts * bpp
        flows.append({
            "src_ip": f"192.168.1.{30 + (i % 10)}",
            "dst_ip": f"45.77.12.{20 + i}",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": 0.01,
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": 0.99,
            "fin_flag_ratio": 0.01,
            "unique_dst_ports_window": 1,
            "connection_frequency": rng.randint(2, 6),
            "payload_byte_ratio": rng.uniform(0.91, 0.98),
        })
        labels.append(1)
        cats.append("adv_throttled_exfil")

    for i in range(50):  # Mimicry SYN flood
        dur = rng.uniform(0.2, 1.0)
        pkts = rng.randint(120, 400)
        b_cnt = pkts * 58
        flows.append({
            "src_ip": f"10.99.0.{10 + i}",
            "dst_ip": "192.168.1.10",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.75, 0.95),
            "rst_flag_ratio": rng.uniform(0.02, 0.10),
            "ack_flag_ratio": rng.uniform(0.04, 0.18),
            "fin_flag_ratio": 0.0,
            "unique_dst_ports_window": rng.randint(1, 3),
            "connection_frequency": rng.randint(40, 140),
            "payload_byte_ratio": 0.02,
        })
        labels.append(1)
        cats.append("adv_syn_flood")

    for i in range(50):  # High-RST credential brute-force / scan
        dur = rng.uniform(0.5, 2.5)
        pkts = rng.randint(40, 120)
        b_cnt = pkts * 74
        flows.append({
            "src_ip": f"10.50.2.{10 + i}",
            "dst_ip": "192.168.1.10",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.35, 0.55),
            "rst_flag_ratio": rng.uniform(0.50, 0.75),
            "ack_flag_ratio": rng.uniform(0.15, 0.35),
            "fin_flag_ratio": 0.0,
            "unique_dst_ports_window": rng.randint(20, 65),
            "connection_frequency": rng.randint(25, 70),
            "payload_byte_ratio": 0.05,
        })
        labels.append(1)
        cats.append("adv_rst_scan")

    # 2. Benign Hard Negatives (220)
    for i in range(75):  # Microservice RPC burst (high PPS, healthy ACK, moderate payload)
        dur = rng.uniform(0.15, 0.8)
        pkts = rng.randint(20, 90)
        b_cnt = pkts * rng.randint(140, 320)
        flows.append({
            "src_ip": f"192.168.1.{10 + (i % 5)}",
            "dst_ip": "192.168.1.20",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.10, 0.24),
            "rst_flag_ratio": rng.uniform(0.02, 0.14),
            "ack_flag_ratio": rng.uniform(0.55, 0.82),
            "fin_flag_ratio": rng.uniform(0.08, 0.18),
            "unique_dst_ports_window": rng.randint(3, 10),
            "connection_frequency": rng.randint(8, 22),
            "payload_byte_ratio": rng.uniform(0.45, 0.72),
        })
        labels.append(0)
        cats.append("benign_microservice_burst")

    for i in range(75):  # Long-lived interactive SSH session
        dur = rng.uniform(12.0, 90.0)
        pkts = rng.randint(40, 220)
        b_cnt = pkts * rng.randint(95, 210)
        flows.append({
            "src_ip": f"192.168.1.{100 + (i % 8)}",
            "dst_ip": "192.168.1.5",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.01, 0.05),
            "rst_flag_ratio": 0.0,
            "ack_flag_ratio": rng.uniform(0.90, 0.99),
            "fin_flag_ratio": rng.uniform(0.01, 0.04),
            "unique_dst_ports_window": 1,
            "connection_frequency": 1,
            "payload_byte_ratio": rng.uniform(0.40, 0.68),
        })
        labels.append(0)
        cats.append("benign_ssh_long")

    for i in range(70):  # Legitimate HTTPS / gRPC / CDN burst
        dur = rng.uniform(1.0, 5.0)
        pkts = rng.randint(40, 160)
        b_cnt = pkts * rng.randint(350, 580)
        flows.append({
            "src_ip": f"192.168.1.{60 + (i % 6)}",
            "dst_ip": "142.250.71.46",
            "flow_duration_sec": dur,
            "packet_count": pkts,
            "byte_count": b_cnt,
            "packets_per_sec": pkts / dur,
            "bytes_per_sec": b_cnt / dur,
            "syn_flag_ratio": rng.uniform(0.02, 0.08),
            "rst_flag_ratio": rng.uniform(0.0, 0.04),
            "ack_flag_ratio": rng.uniform(0.85, 0.97),
            "fin_flag_ratio": rng.uniform(0.02, 0.06),
            "unique_dst_ports_window": rng.randint(1, 3),
            "connection_frequency": rng.randint(1, 5),
            "payload_byte_ratio": rng.uniform(0.55, 0.78),
        })
        labels.append(0)
        cats.append("benign_https_burst")

    return flows, np.array(labels, dtype=int), cats


def run_sms_experiments() -> Tuple[Dict[str, Any], HardenedSMSDetector]:
    """Run clean & adversarial SMS benchmarks + baseline/ablation comparisons."""
    with open(ROOT / "data" / "raw" / "sms_dataset.csv", encoding="utf-8") as f:
        raw_rows = list(csv.DictReader(f))

    # Deduplicate exact texts to guarantee zero train/val/test leakage
    seen = set()
    dedup_rows = []
    for r in raw_rows:
        norm = " ".join(r["text"].lower().split())
        if norm not in seen:
            seen.add(norm)
            dedup_rows.append((r["text"], int(r["label"])))

    texts = [x[0] for x in dedup_rows]
    labels = np.array([x[1] for x in dedup_rows], dtype=int)

    tr_val_x, clean_test_x, tr_val_y, clean_test_y = train_test_split(
        texts, labels, test_size=0.15, stratify=labels, random_state=42
    )
    train_x, val_x, train_y, val_y = train_test_split(
        tr_val_x, tr_val_y, test_size=0.1765, stratify=tr_val_y, random_state=42
    )

    # Fit hardened SMS detector strictly on train + val calibration
    hardened_sms = HardenedSMSDetector()
    sms_model_path = ROOT / "models" / "sms" / "sms_hardened_pipeline.joblib"
    hardened_sms.fit(train_x, train_y, val_x, val_y, save_path=sms_model_path)

    baseline_sms = ScamSMSDetector()
    adv_rows = generate_adversarial_sms_dataset()
    adv_texts = [r["text"] for r in adv_rows]
    adv_labels = np.array([r["label"] for r in adv_rows], dtype=int)
    adv_cats = [r["category"] for r in adv_rows]

    def eval_detector(det: Any, sample_texts: List[str], sample_labels: np.ndarray) -> Tuple[Dict[str, Any], np.ndarray]:
        preds, lats = [], []
        for t in sample_texts:
            res = det.predict(t)
            preds.append(1 if res.classification in {"malicious", "suspicious"} else 0)
            lats.append(res.inference_latency_ms)
        return compute_metrics(sample_labels, np.array(preds, dtype=int), lats), np.array(preds, dtype=int)

    base_clean, _ = eval_detector(baseline_sms, clean_test_x, clean_test_y)
    base_adv, _ = eval_detector(baseline_sms, adv_texts, adv_labels)
    hard_clean, _ = eval_detector(hardened_sms, clean_test_x, clean_test_y)
    hard_adv, hard_adv_preds = eval_detector(hardened_sms, adv_texts, adv_labels)

    # Per-category benign false positives on adversarial dataset
    benign_fp_by_cat: Dict[str, Any] = {}
    for cat in sorted(set(c for c in adv_cats if c.startswith("benign_"))):
        idx = [i for i, c in enumerate(adv_cats) if c == cat]
        fp_cnt = int(sum(hard_adv_preds[i] == 1 for i in idx))
        benign_fp_by_cat[cat] = {
            "total": len(idx),
            "false_positives": fp_cnt,
            "fpr": round(fp_cnt / max(len(idx), 1), 4),
        }

    # Ablation comparison: raw vs normalized Word+Char TF-IDF (LogReg vs LinearSVC)
    ablation: Dict[str, Any] = {}
    for variant_name, use_norm in [("raw_text", False), ("normalized_text", True)]:
        prep_fn = (
            (lambda s: HardenedSMSPreprocessor.normalize(s)["tfidf_text"])
            if use_norm
            else (lambda s: s.lower())
        )
        w_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=4000, sublinear_tf=True)
        c_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=8000, sublinear_tf=True)
        tr_proc = [prep_fn(t) for t in train_x]
        X_tr = hstack([w_vec.fit_transform(tr_proc), c_vec.fit_transform(tr_proc)])
        X_cl = hstack([w_vec.transform([prep_fn(t) for t in clean_test_x]), c_vec.transform([prep_fn(t) for t in clean_test_x])])
        X_ad = hstack([w_vec.transform([prep_fn(t) for t in adv_texts]), c_vec.transform([prep_fn(t) for t in adv_texts])])

        for clf_name, clf in [
            ("LogisticRegression", LogisticRegression(C=1.5, max_iter=1000, class_weight="balanced", random_state=42)),
            ("LinearSVC", LinearSVC(C=1.0, class_weight="balanced", random_state=42)),
        ]:
            clf.fit(X_tr, train_y)
            cl_pred = clf.predict(X_cl)
            ad_pred = clf.predict(X_ad)
            ablation[f"{variant_name}_{clf_name}"] = {
                "clean": compute_metrics(clean_test_y, cl_pred, []),
                "adversarial": compute_metrics(adv_labels, ad_pred, []),
            }

    return {
        "clean_split_sizes": {"train": len(train_x), "val_cal": len(val_x), "clean_test": len(clean_test_x)},
        "adversarial_dataset_size": {"attacks": int(sum(adv_labels == 1)), "benign_hard_negatives": int(sum(adv_labels == 0))},
        "baseline_scam_sms": {"clean": base_clean, "adversarial": base_adv},
        "hardened_sms": {
            "clean": hard_clean,
            "adversarial": hard_adv,
            "benign_fp_by_category": benign_fp_by_cat,
            "model_size_mb": round(sms_model_path.stat().st_size / (1024 * 1024), 3),
        },
        "ablation_models": ablation,
    }, hardened_sms


def run_url_experiments() -> Tuple[Dict[str, Any], HardenedURLDetector]:
    """Run group-split clean & adversarial URL benchmarks + IDN/shortener FP breakdown."""
    with open(ROOT / "data" / "raw" / "url_dataset.csv", encoding="utf-8") as f:
        raw_rows = list(csv.DictReader(f))

    urls = [r["url"] for r in raw_rows]
    labels = np.array([int(r["label"]) for r in raw_rows], dtype=int)
    groups = np.array([URLFeatureExtractor.extract_registered_domain(u) for u in urls])

    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)
    tr_val_idx, test_idx = next(gss1.split(urls, labels, groups))
    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.1765, random_state=42)
    tr_rel, val_rel = next(gss2.split([urls[i] for i in tr_val_idx], labels[tr_val_idx], groups[tr_val_idx]))
    train_idx = tr_val_idx[tr_rel]
    val_idx = tr_val_idx[val_rel]

    train_urls = [urls[i] for i in train_idx]
    val_urls = [urls[i] for i in val_idx]
    clean_test_urls = [urls[i] for i in test_idx]

    hardened_url = HardenedURLDetector()
    url_model_path = ROOT / "models" / "url" / "url_hardened_pipeline.joblib"
    hardened_url.fit(train_urls, labels[train_idx], val_urls, labels[val_idx], save_path=url_model_path)

    baseline_url = PhishingURLDetector()
    adv_rows = generate_adversarial_url_dataset()
    adv_urls = [r["url"] for r in adv_rows]
    adv_labels = np.array([r["label"] for r in adv_rows], dtype=int)
    adv_cats = [r["category"] for r in adv_rows]

    def eval_url(det: Any, sample_urls: List[str], sample_labels: np.ndarray) -> Tuple[Dict[str, Any], np.ndarray]:
        preds, lats = [], []
        for u in sample_urls:
            res = det.predict(u)
            preds.append(1 if res.classification in {"malicious", "suspicious"} else 0)
            lats.append(res.inference_latency_ms)
        return compute_metrics(sample_labels, np.array(preds, dtype=int), lats), np.array(preds, dtype=int)

    base_clean, _ = eval_url(baseline_url, clean_test_urls, labels[test_idx])
    base_adv, _ = eval_url(baseline_url, adv_urls, adv_labels)
    hard_clean, _ = eval_url(hardened_url, clean_test_urls, labels[test_idx])
    hard_adv, hard_adv_preds = eval_url(hardened_url, adv_urls, adv_labels)

    benign_fp_by_cat: Dict[str, Any] = {}
    for cat in sorted(set(c for c in adv_cats if c.startswith("benign_"))):
        idx = [i for i, c in enumerate(adv_cats) if c == cat]
        fp_cnt = int(sum(hard_adv_preds[i] == 1 for i in idx))
        benign_fp_by_cat[cat] = {
            "total": len(idx),
            "flagged_suspicious_or_malicious": fp_cnt,
            "fpr": round(fp_cnt / max(len(idx), 1), 4),
        }

    return {
        "clean_split_sizes": {"train": len(train_urls), "val_cal": len(val_urls), "clean_test": len(clean_test_urls)},
        "adversarial_dataset_size": {"attacks": int(sum(adv_labels == 1)), "benign_hard_negatives": int(sum(adv_labels == 0))},
        "baseline_url": {"clean": base_clean, "adversarial": base_adv},
        "hardened_url": {
            "clean": hard_clean,
            "adversarial": hard_adv,
            "benign_fp_by_category": benign_fp_by_cat,
            "model_size_mb": round(url_model_path.stat().st_size / (1024 * 1024), 3),
        },
    }, hardened_url


def run_network_experiments() -> Tuple[Dict[str, Any], ContextAwareNetworkDetector]:
    """Evaluate Phase 2 AdaptiveNetworkDetector vs Phase 3 ContextAwareNetworkDetector on known, unseen & adversarial flows."""
    with open(ROOT / "data" / "raw" / "network_flows_dataset.csv", encoding="utf-8") as f:
        raw_rows = list(csv.DictReader(f))

    unseen_scenarios = {
        "benign_ssh_session",
        "benign_microservice_burst",
        "data_exfiltration_anomaly",
        "stealth_low_slow_probe",
    }

    known_rows = [r for r in raw_rows if r["attack_type"] not in unseen_scenarios]
    unseen_rows = [r for r in raw_rows if r["attack_type"] in unseen_scenarios]

    known_labels = np.array([int(r["label"]) for r in known_rows], dtype=int)
    unseen_labels = np.array([int(r["label"]) for r in unseen_rows], dtype=int)

    tr_val_idx, test_idx = train_test_split(
        np.arange(len(known_rows)), test_size=0.20, stratify=known_labels, random_state=42
    )
    tr_idx, val_idx = train_test_split(
        tr_val_idx, test_size=0.1875, stratify=known_labels[tr_val_idx], random_state=42
    )

    train_flows = [known_rows[i] for i in tr_idx]
    val_flows = [known_rows[i] for i in val_idx]
    known_test_flows = [known_rows[i] for i in test_idx]

    # Phase 2 baseline
    p2_net = AdaptiveNetworkDetector()
    p2_net.fit([known_rows[i] for i in tr_val_idx], known_labels[tr_val_idx])

    # Phase 3 context-aware detector
    p3_net = ContextAwareNetworkDetector()
    p3_net.fit(train_flows, known_labels[tr_idx], val_flows, known_labels[val_idx])
    net_model_path = ROOT / "models" / "network" / "network_context_aware.joblib"
    net_model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(p3_net, net_model_path)

    def eval_net(det: Any, flows: List[Dict[str, Any]], y: np.ndarray) -> Dict[str, Any]:
        strict_preds, alert_preds, lats, states = [], [], [], []
        for fl in flows:
            v = det.predict(fl)
            states.append(v.state)
            strict_preds.append(1 if v.state == "confirmed_malicious" else 0)
            alert_preds.append(1 if v.state in {"confirmed_malicious", "suspicious_unknown"} else 0)
            lats.append(v.latency_ms)
        return {
            "strict_confirmed": compute_metrics(y, np.array(strict_preds), lats),
            "alert_confirmed_or_suspicious": compute_metrics(y, np.array(alert_preds), lats),
            "abstention_count": int(sum(1 for s in states if s == "insufficient_evidence")),
        }

    # Per-scenario breakdown on unseen holdout
    p3_unseen_breakdown: Dict[str, Dict[str, int]] = {}
    for sc in sorted(unseen_scenarios):
        sc_flows = [r for r in unseen_rows if r["attack_type"] == sc]
        counts = {"confirmed_malicious": 0, "suspicious_unknown": 0, "normal": 0, "insufficient_evidence": 0}
        for fl in sc_flows:
            st = p3_net.predict(fl).state
            counts[st] += 1
        p3_unseen_breakdown[sc] = counts

    adv_flows, adv_labels, _ = generate_adversarial_network_dataset()

    return {
        "phase2_adaptive_baseline": {
            "known": eval_net(p2_net, known_test_flows, known_labels[test_idx]),
            "unseen": eval_net(p2_net, unseen_rows, unseen_labels),
            "adversarial": eval_net(p2_net, adv_flows, adv_labels),
        },
        "phase3_context_aware": {
            "known": eval_net(p3_net, known_test_flows, known_labels[test_idx]),
            "unseen": eval_net(p3_net, unseen_rows, unseen_labels),
            "unseen_per_scenario": p3_unseen_breakdown,
            "adversarial": eval_net(p3_net, adv_flows, adv_labels),
            "model_size_mb": round(net_model_path.stat().st_size / (1024 * 1024), 3),
        },
    }, p3_net


def benchmark_operating_modes(
    sms_det: HardenedSMSDetector,
    url_det: HardenedURLDetector,
    net_det: ContextAwareNetworkDetector,
) -> Dict[str, Any]:
    """Benchmark FAST TRIAGE (zero LLM) vs DEEP ANALYSIS latency, RSS memory, and CPU utilization."""
    proc = psutil.Process(os.getpid())
    proc.cpu_percent(interval=None)
    engine = CalibratedThreatEngine(url_detector=url_det, sms_detector=sms_det, network_detector=net_det)

    fast_lats = []
    t_wall0 = time.perf_counter()
    for _ in range(15):
        fast_lats.append(engine.assess_sms("U R G E N T: SBI k y c expired bit.ly/kyc", mode="fast_triage").total_latency_ms)
        fast_lats.append(engine.assess_url("https://раypal-security.com/login", mode="fast_triage").total_latency_ms)
        fast_lats.append(
            engine.assess_network_flow(
                {
                    "src_ip": "192.168.1.15",
                    "flow_duration_sec": 0.3,
                    "packet_count": 30,
                    "byte_count": 6000,
                    "syn_flag_ratio": 0.15,
                    "ack_flag_ratio": 0.70,
                    "rst_flag_ratio": 0.05,
                    "unique_dst_ports_window": 6,
                    "connection_frequency": 12,
                    "payload_byte_ratio": 0.60,
                },
                mode="fast_triage",
            ).total_latency_ms
        )
    fast_wall = time.perf_counter() - t_wall0
    fast_cpu = proc.cpu_percent(interval=None)
    fast_rss_mb = proc.memory_info().rss / (1024 * 1024)

    deep_lats = []
    deep_backends = []
    for _ in range(2):
        res = engine.assess_url("https://раypal-security.com/login", mode="deep_analysis")
        deep_lats.append(res.total_latency_ms)
        deep_backends.append(res.llm_backend)
    deep_rss_mb = proc.memory_info().rss / (1024 * 1024)

    return {
        "fast_triage": {
            "runs": len(fast_lats),
            "p50_ms": round(float(np.percentile(fast_lats, 50)), 3),
            "p95_ms": round(float(np.percentile(fast_lats, 95)), 3),
            "wall_sec": round(fast_wall, 3),
            "rss_mb": round(fast_rss_mb, 2),
            "cpu_percent": round(fast_cpu, 1),
        },
        "deep_analysis": {
            "runs": len(deep_lats),
            "p50_ms": round(float(np.percentile(deep_lats, 50)), 3),
            "p95_ms": round(float(np.percentile(deep_lats, 95)), 3),
            "rss_mb": round(deep_rss_mb, 2),
            "backends": list(set(deep_backends)),
        },
    }


def main() -> None:
    print("[Phase 3] Running SMS hardening & ablation experiments...")
    sms_res, sms_det = run_sms_experiments()

    print("[Phase 3] Running URL hardening & IDN/shortener experiments...")
    url_res, url_det = run_url_experiments()

    print("[Phase 3] Running Network false-positive reduction experiments...")
    net_res, net_det = run_network_experiments()

    print("[Phase 3] Benchmarking FAST TRIAGE vs DEEP ANALYSIS...")
    bench_res = benchmark_operating_modes(sms_det, url_det, net_det)

    full_results = {
        "sms": sms_res,
        "url": url_res,
        "network": net_res,
        "operating_modes_benchmark": bench_res,
    }
    out_file = OUT_DIR / "phase3_results.json"
    out_file.write_text(json.dumps(full_results, indent=2), encoding="utf-8")
    print(f"[Phase 3] Complete! Results written to {out_file}")


if __name__ == "__main__":
    main()
