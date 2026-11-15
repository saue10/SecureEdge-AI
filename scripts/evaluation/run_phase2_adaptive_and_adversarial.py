"""
Phase 2 Evaluation Suite: Adaptive Threat Intelligence, Unseen Network Scenarios,
Adversarial Robustness (URL, SMS, Network), and FAST TRIAGE vs DEEP ANALYSIS Benchmarks.
"""

import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd
import psutil
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import RobustScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import RANDOM_SEED, RAW_DATA_DIR
from src.network_detection.adaptive import AdaptiveNetworkDetector
from src.network_detection.features import FLOW_FEATURE_NAMES
from src.sms_detection.detector import ScamSMSDetector
from src.threat_engine.adaptive_engine import AdaptiveThreatIntelligenceEngine
from src.url_detection.detector import PhishingURLDetector

OUT_DIR = PROJECT_ROOT / "results" / "adaptive_threat_intelligence"


def _metrics_dict(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]
    per_f1 = f1_score(y_true, y_pred, labels=[0, 1], average=None, zero_division=0)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "per_class_f1": {"benign": round(float(per_f1[0]), 4), "threat": round(float(per_f1[1]), 4)},
        "fpr": round(float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0, 4),
        "fnr": round(float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0, 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }


def evaluate_network_known_vs_unseen() -> Dict[str, Any]:
    df = pd.read_csv(RAW_DATA_DIR / "network_flows_dataset.csv")
    unseen_benign = ["benign_ssh_session", "benign_microservice_burst"]
    unseen_attack = ["data_exfiltration_anomaly", "stealth_low_slow_probe"]
    unseen_all = unseen_benign + unseen_attack

    known_df = df[~df["attack_type"].isin(unseen_all)].sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    split_idx = int(len(known_df) * 0.75)
    tr_df = known_df.iloc[:split_idx].reset_index(drop=True)
    te_known_df = known_df.iloc[split_idx:].reset_index(drop=True)
    te_unseen_df = df[df["attack_type"].isin(unseen_all)].reset_index(drop=True)

    tr_flows = tr_df.to_dict(orient="records")
    te_known_flows = te_known_df.to_dict(orient="records")
    te_unseen_flows = te_unseen_df.to_dict(orient="records")

    adaptive = AdaptiveNetworkDetector(supervised_threshold=0.60, anomaly_threshold=0.0, random_state=RANDOM_SEED)
    adaptive.fit(tr_flows, tr_df["label"].to_numpy())

    # Evaluate AdaptiveNetworkDetector (both strict confirmed_malicious and alert=confirmed|suspicious)
    def eval_adaptive(flows: List[Dict[str, Any]], y: np.ndarray, df_sub: pd.DataFrame) -> Dict[str, Any]:
        verdicts = [adaptive.predict(f) for f in flows]
        states = [v.state for v in verdicts]
        pred_strict = np.array([1 if s == "confirmed_malicious" else 0 for s in states])
        pred_alert = np.array([1 if s in ("confirmed_malicious", "suspicious_unknown") else 0 for s in states])
        lats = [v.latency_ms for v in verdicts]
        per_scen = {}
        for sc in sorted(df_sub["attack_type"].unique()):
            m = (df_sub["attack_type"] == sc).to_numpy()
            sc_states = [states[i] for i in range(len(states)) if m[i]]
            per_scen[sc] = {
                "count": int(np.sum(m)),
                "confirmed_malicious": sc_states.count("confirmed_malicious"),
                "suspicious_unknown": sc_states.count("suspicious_unknown"),
                "normal": sc_states.count("normal"),
            }
        return {
            "alert_mode_metrics": _metrics_dict(y, pred_alert),
            "strict_malicious_metrics": _metrics_dict(y, pred_strict),
            "per_scenario_states": per_scen,
            "p50_latency_ms": round(float(np.percentile(lats, 50)), 3),
            "p95_latency_ms": round(float(np.percentile(lats, 95)), 3),
        }

    # Baselines on raw 16 features
    X_tr = tr_df[FLOW_FEATURE_NAMES].to_numpy(dtype=np.float32)
    y_tr = tr_df["label"].to_numpy()
    X_tr_benign = tr_df[tr_df["label"] == 0][FLOW_FEATURE_NAMES].to_numpy(dtype=np.float32)

    scaler = RobustScaler()
    X_tr_b_s = scaler.fit_transform(X_tr_benign)
    X_kn_s = scaler.transform(te_known_df[FLOW_FEATURE_NAMES].to_numpy(dtype=np.float32))
    X_un_s = scaler.transform(te_unseen_df[FLOW_FEATURE_NAMES].to_numpy(dtype=np.float32))

    baselines: Dict[str, Any] = {}
    for name, clf, is_unsup in [
        ("RandomForest", RandomForestClassifier(n_estimators=120, max_depth=14, random_state=RANDOM_SEED), False),
        ("HistGradientBoosting", HistGradientBoostingClassifier(max_iter=120, max_depth=6, random_state=RANDOM_SEED), False),
        ("LogisticRegression", LogisticRegression(max_iter=1000, random_state=RANDOM_SEED), False),
        ("IsolationForest_Raw", IsolationForest(n_estimators=150, contamination=0.05, random_state=RANDOM_SEED), True),
        ("LOF_Novelty_Raw", LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.05), True),
        ("EllipticEnvelope_Raw", EllipticEnvelope(contamination=0.05, support_fraction=0.85, random_state=RANDOM_SEED), True),
    ]:
        if is_unsup:
            clf.fit(X_tr_b_s)
            p_kn = (clf.predict(X_kn_s) == -1).astype(int)
            p_un = (clf.predict(X_un_s) == -1).astype(int)
            auc_un = float(roc_auc_score(te_unseen_df["label"].to_numpy(), -clf.decision_function(X_un_s)))
        else:
            X_tr_all_s = scaler.transform(X_tr)
            clf.fit(X_tr_all_s, y_tr)
            p_kn = clf.predict(X_kn_s)
            p_un = clf.predict(X_un_s)
            auc_un = float(roc_auc_score(te_unseen_df["label"].to_numpy(), clf.predict_proba(X_un_s)[:, 1]))
        baselines[name] = {
            "known_scenarios": _metrics_dict(te_known_df["label"].to_numpy(), p_kn),
            "unseen_scenarios": {**_metrics_dict(te_unseen_df["label"].to_numpy(), p_un), "roc_auc": round(auc_un, 4)},
        }

    return {
        "unseen_benign_scenarios": unseen_benign,
        "unseen_attack_scenarios": unseen_attack,
        "adaptive_detector": {
            "known_scenarios": eval_adaptive(te_known_flows, te_known_df["label"].to_numpy(), te_known_df),
            "unseen_scenarios": eval_adaptive(te_unseen_flows, te_unseen_df["label"].to_numpy(), te_unseen_df),
        },
        "baselines": baselines,
        "fitted_adaptive_detector": adaptive,
    }


def evaluate_adversarial_suites(adaptive: AdaptiveNetworkDetector) -> Dict[str, Any]:
    url_det = PhishingURLDetector()
    sms_det = ScamSMSDetector()

    # 1. URL Adversarial Set (14 attacks + 10 benign hard-negatives)
    url_adv_samples = [
        ("http://xn--sb-6ja.com/login/verify", 1, "punycode_idn"),
        ("http://раypal-security.com/signin", 1, "unicode_confusable"),
        ("http://198.51.100.42:8080/auth/login.php", 1, "raw_ip_port"),
        ("https://hdfcbank.com.verify-kyc-portal.top/session", 1, "misleading_subdomain"),
        ("http://icici-online-update.xyz/otp/confirm", 1, "brand_impersonation"),
        ("https://bit.ly/3xKycVerify", 1, "url_shortener"),
        ("https://accounts.google.com@evil-login.ru/%2fverify%2fpin", 1, "encoded_redirect_at"),
        ("http://a.b.c.d.e.f.sbi-login-secure.info/portal", 1, "excessive_subdomains"),
        ("http://gateway-portal.net:4444/cmd/update.exe", 1, "suspicious_port_exe"),
        ("HtTp://PaYpAl-SeCuRe-UpDaTe.CoM/LoGiN?id=99", 1, "mixed_case_obfuscation"),
        ("http://0x7f.0x0.0x0.0x1/admin/login", 1, "hex_ip_obfuscation"),
        ("https://tinyurl.com/sbi-reward-claim", 1, "shortener_brand"),
        ("http://upi-refund-claim.click/v2/auth?token=abc%3D123", 1, "percent_encoded_phish"),
        ("http://support-npci.org.phish-check.biz/verify", 1, "double_brand_subdomain"),
        # Benign hard negatives
        ("https://docs.python.org/3/library/urllib.parse.html", 0, "benign_docs"),
        ("https://accounts.google.com/o/oauth2/v2/auth?client_id=123&redirect_uri=https://github.com/login", 0, "benign_oauth"),
        ("https://www.onlinesbi.sbi/sbicollect/icollecthome.htm", 0, "benign_sbi"),
        ("https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx", 0, "benign_rbi"),
        ("https://github.com/pytorch/executorch/releases/tag/v1.0", 0, "benign_github"),
        ("https://arxiv.org/abs/2401.00001", 0, "benign_arxiv"),
        ("https://www.npci.org.in/what-we-do/upi/product-overview", 0, "benign_npci"),
        ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/302", 0, "benign_mdn"),
        ("https://pypi.org/project/scikit-learn/", 0, "benign_pypi"),
        ("https://en.wikipedia.org/wiki/Transport_Layer_Security", 0, "benign_wiki"),
    ]
    url_y = np.array([x[1] for x in url_adv_samples])
    url_preds, url_lats, url_misses = [], [], []
    for u, lbl, tag in url_adv_samples:
        res = url_det.predict(u)
        pred = 1 if res.classification in ("malicious", "suspicious") else 0
        url_preds.append(pred)
        url_lats.append(res.inference_latency_ms)
        if pred != lbl:
            url_misses.append({"url": u, "tag": tag, "true": lbl, "pred": pred, "score": res.risk_score})

    # 2. SMS Adversarial Set (12 attacks + 10 benign hard-negatives)
    sms_adv_samples = [
        ("URGENT: Your S.B.I K.Y.C is blocked! V3r1fy A/c at http://sbi-kyc-fix.xyz now", 1, "leetspeak_spacing_kyc"),
        ("Dear user, U.P.I cashback Rs 5000 expiring! Enter U-P-I P!N at bit.ly/claim99", 1, "punctuation_obfuscation"),
        ("A/c XX9912 will be frozen in 2 hrs. Call customer care 9876543210 immediately", 1, "impersonated_support"),
        ("Electricity power CA-4421 cut tonight 9PM. Pay pending bill at http://power-pay.top", 1, "urgent_utility_scam"),
        ("Aapka KYC pending hai, turant verify karein warna account band hoga: http://kyc-in.click", 1, "mixed_hinglish_scam"),
        ("FINAL WARNING: Share your 6-digit O T P with agent 8899001122 to stop Rs 24,999 debit", 1, "otp_theft_spaced"),
        ("Congratz!! Won Rs. 10,00,000 Jio lottery. Click http://jio-win.biz to claim", 1, "prize_lure"),
        ("ICICI Bank: Your debit card is suspended. Update P.A.N details: http://icici-pan.info", 1, "fake_bank_pan"),
        ("Customs parcel seized! Pay Rs 1,450 clearance fee at http://indiapost-fee.xyz", 1, "customs_scam"),
        ("Earn Rs 5000/day liking YouTube videos! Join Telegram t.me/taskjob99 now", 1, "task_scam"),
        ("HDFC Alert: Suspicious login detected. Cancel by entering NetBanking PIN at http://hdfc-chk.top", 1, "credential_theft"),
        ("Paytm KYC expired! Call +91-9988776655 or click http://paytm-kyc.cfd", 1, "leetspeak_paytm"),
        # Benign hard negatives
        ("Your OTP for HDFC NetBanking login is 482910. Do not share this OTP with anyone.", 0, "benign_otp_hdfc"),
        ("654321 is your SBI UPI transaction OTP. Never share your OTP or PIN with anyone.", 0, "benign_otp_sbi"),
        ("Hey, can we meet at 5 PM near the library to review our project slides?", 0, "benign_personal"),
        ("Your Amazon order #402-112233 has been delivered to your doorstep today.", 0, "benign_delivery"),
        ("Reminder: Dentist appointment tomorrow at 10:30 AM. Reply YES to confirm.", 0, "benign_appointment"),
        ("Rs. 1,250.00 debited from A/c XX4321 via UPI to Grocery Store on 15-Nov.", 0, "benign_txn_alert"),
        ("Happy birthday! Wishing you a wonderful year ahead.", 0, "benign_personal_bday"),
        ("IRCTC: Ticket confirmed for Train 12952, Coach B2, Seat 34.", 0, "benign_irctc"),
        ("Your Jio Fiber plan renews on 20 Nov. No action is needed from your side.", 0, "benign_telecom"),
        ("Meeting link is on our internal calendar, see you at 3 PM.", 0, "benign_meeting"),
    ]
    sms_y = np.array([x[1] for x in sms_adv_samples])
    sms_preds, sms_lats, sms_misses = [], [], []
    for txt, lbl, tag in sms_adv_samples:
        res = sms_det.predict(txt)
        pred = 1 if res.classification in ("malicious", "suspicious") else 0
        sms_preds.append(pred)
        sms_lats.append(res.inference_latency_ms)
        if pred != lbl:
            sms_misses.append({"sms": txt[:60], "tag": tag, "true": lbl, "pred": pred, "score": res.risk_score})

    # 3. Network Adversarial Set (10 attacks + 6 benign hard-negatives)
    net_adv_samples = [
        ({"flow_duration_sec": 45.0, "packet_count": 30, "byte_count": 1920, "packets_per_sec": 0.67, "bytes_per_sec": 42.6, "syn_flag_ratio": 0.80, "rst_flag_ratio": 0.20, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 28, "connection_frequency": 28, "payload_byte_ratio": 0.05}, 1, "slow_rate_port_scan"),
        ({"flow_duration_sec": 1.2, "packet_count": 90, "byte_count": 5400, "packets_per_sec": 75.0, "bytes_per_sec": 4500.0, "syn_flag_ratio": 0.90, "rst_flag_ratio": 0.10, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 60, "connection_frequency": 55, "payload_byte_ratio": 0.02}, 1, "high_dst_diversity_scan"),
        ({"flow_duration_sec": 2.5, "packet_count": 1800, "byte_count": 2500000, "packets_per_sec": 720.0, "bytes_per_sec": 1000000.0, "syn_flag_ratio": 0.02, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.95, "fin_flag_ratio": 0.03, "unique_dst_ports_window": 1, "connection_frequency": 4, "payload_byte_ratio": 0.94}, 1, "unusual_outbound_exfil"),
        ({"flow_duration_sec": 0.3, "packet_count": 400, "byte_count": 24000, "packets_per_sec": 1333.0, "bytes_per_sec": 80000.0, "syn_flag_ratio": 0.95, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.05, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 2, "connection_frequency": 140, "payload_byte_ratio": 0.04}, 1, "syn_connection_burst"),
        ({"flow_duration_sec": 18.0, "packet_count": 42, "byte_count": 3800, "packets_per_sec": 2.3, "bytes_per_sec": 211.0, "syn_flag_ratio": 0.35, "rst_flag_ratio": 0.25, "ack_flag_ratio": 0.35, "fin_flag_ratio": 0.05, "unique_dst_ports_window": 7, "connection_frequency": 12, "payload_byte_ratio": 0.45}, 1, "low_and_slow_probe"),
        ({"flow_duration_sec": 2.0, "packet_count": 60, "byte_count": 3600, "packets_per_sec": 30.0, "bytes_per_sec": 1800.0, "syn_flag_ratio": 0.45, "rst_flag_ratio": 0.55, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 3, "connection_frequency": 35, "payload_byte_ratio": 0.10}, 1, "abnormal_rst_failures"),
        ({"flow_duration_sec": 3.0, "packet_count": 120, "byte_count": 90000, "packets_per_sec": 40.0, "bytes_per_sec": 30000.0, "syn_flag_ratio": 0.05, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.90, "fin_flag_ratio": 0.05, "unique_dst_ports_window": 1, "connection_frequency": 25, "payload_byte_ratio": 0.85}, 1, "c2_beaconing_burst"),
        ({"flow_duration_sec": 60.0, "packet_count": 200, "byte_count": 1800000, "packets_per_sec": 3.3, "bytes_per_sec": 30000.0, "syn_flag_ratio": 0.01, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.98, "fin_flag_ratio": 0.01, "unique_dst_ports_window": 1, "connection_frequency": 2, "payload_byte_ratio": 0.92}, 1, "slow_exfiltration"),
        ({"flow_duration_sec": 1.0, "packet_count": 85, "byte_count": 5100, "packets_per_sec": 85.0, "bytes_per_sec": 5100.0, "syn_flag_ratio": 0.50, "rst_flag_ratio": 0.48, "ack_flag_ratio": 0.02, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 12, "connection_frequency": 42, "payload_byte_ratio": 0.08}, 1, "brute_force_rst_storm"),
        ({"flow_duration_sec": 0.5, "packet_count": 150, "byte_count": 9000, "packets_per_sec": 300.0, "bytes_per_sec": 18000.0, "syn_flag_ratio": 0.88, "rst_flag_ratio": 0.12, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 40, "connection_frequency": 70, "payload_byte_ratio": 0.03}, 1, "fast_multiport_sweep"),
        # Benign hard negatives
        ({"flow_duration_sec": 5.0, "packet_count": 40, "byte_count": 28000, "packets_per_sec": 8.0, "bytes_per_sec": 5600.0, "syn_flag_ratio": 0.03, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.92, "fin_flag_ratio": 0.05, "unique_dst_ports_window": 1, "connection_frequency": 1, "payload_byte_ratio": 0.78}, 0, "benign_https_normal"),
        ({"flow_duration_sec": 0.08, "packet_count": 4, "byte_count": 420, "packets_per_sec": 50.0, "bytes_per_sec": 5250.0, "syn_flag_ratio": 0.0, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 1, "connection_frequency": 2, "payload_byte_ratio": 0.55}, 0, "benign_dns_lookup"),
        ({"flow_duration_sec": 45.0, "packet_count": 90, "byte_count": 16000, "packets_per_sec": 2.0, "bytes_per_sec": 355.0, "syn_flag_ratio": 0.02, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.95, "fin_flag_ratio": 0.03, "unique_dst_ports_window": 1, "connection_frequency": 1, "payload_byte_ratio": 0.70}, 0, "benign_ssh_session"),
        ({"flow_duration_sec": 2.5, "packet_count": 25, "byte_count": 14000, "packets_per_sec": 10.0, "bytes_per_sec": 5600.0, "syn_flag_ratio": 0.04, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.92, "fin_flag_ratio": 0.04, "unique_dst_ports_window": 2, "connection_frequency": 2, "payload_byte_ratio": 0.72}, 0, "benign_http_api"),
        ({"flow_duration_sec": 0.5, "packet_count": 6, "byte_count": 456, "packets_per_sec": 12.0, "bytes_per_sec": 912.0, "syn_flag_ratio": 0.0, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.0, "fin_flag_ratio": 0.0, "unique_dst_ports_window": 1, "connection_frequency": 1, "payload_byte_ratio": 0.50}, 0, "benign_ntp_sync"),
        ({"flow_duration_sec": 8.0, "packet_count": 120, "byte_count": 96000, "packets_per_sec": 15.0, "bytes_per_sec": 12000.0, "syn_flag_ratio": 0.02, "rst_flag_ratio": 0.0, "ack_flag_ratio": 0.95, "fin_flag_ratio": 0.03, "unique_dst_ports_window": 1, "connection_frequency": 2, "payload_byte_ratio": 0.80}, 0, "benign_tls_stream"),
    ]
    net_y = np.array([x[1] for x in net_adv_samples])
    net_preds, net_lats, net_misses = [], [], []
    for fl, lbl, tag in net_adv_samples:
        v = adaptive.predict(fl)
        pred = 1 if v.state in ("confirmed_malicious", "suspicious_unknown") else 0
        net_preds.append(pred)
        net_lats.append(v.latency_ms)
        if pred != lbl:
            net_misses.append({"tag": tag, "true": lbl, "pred": pred, "state": v.state, "sup": v.supervised_prob, "anom": v.anomaly_score})

    return {
        "url_adversarial": {**_metrics_dict(url_y, np.array(url_preds)), "p50_ms": round(float(np.percentile(url_lats, 50)), 3), "p95_ms": round(float(np.percentile(url_lats, 95)), 3), "misses": url_misses},
        "sms_adversarial": {**_metrics_dict(sms_y, np.array(sms_preds)), "p50_ms": round(float(np.percentile(sms_lats, 50)), 3), "p95_ms": round(float(np.percentile(sms_lats, 95)), 3), "misses": sms_misses},
        "network_adversarial": {**_metrics_dict(net_y, np.array(net_preds)), "p50_ms": round(float(np.percentile(net_lats, 50)), 3), "p95_ms": round(float(np.percentile(net_lats, 95)), 3), "misses": net_misses},
    }


def benchmark_fast_vs_deep(adaptive: AdaptiveNetworkDetector) -> Dict[str, Any]:
    proc = psutil.Process()
    engine = AdaptiveThreatIntelligenceEngine(adaptive_network=adaptive)

    url_sample = "http://hdfcbank.secure-login.verify-update.auth-gateway-101.xyz/kyc-update/confirm-otp.html"
    sms_sample = "URGENT: Your S.B.I K.Y.C is blocked! V3r1fy A/c at http://sbi-kyc-fix.xyz now"
    net_sample = {"flow_duration_sec": 18.0, "packet_count": 42, "byte_count": 3800, "packets_per_sec": 2.3, "bytes_per_sec": 211.0, "syn_flag_ratio": 0.35, "rst_flag_ratio": 0.25, "ack_flag_ratio": 0.35, "fin_flag_ratio": 0.05, "unique_dst_ports_window": 7, "connection_frequency": 12, "payload_byte_ratio": 0.45}

    fast_lats = []
    for _ in range(15):
        fast_lats.append(engine.assess_url(url_sample, mode="fast_triage").total_latency_ms)
        fast_lats.append(engine.assess_sms(sms_sample, mode="fast_triage").total_latency_ms)
        fast_lats.append(engine.assess_network_flow(net_sample, mode="fast_triage").total_latency_ms)
    rss_fast_mb = round(proc.memory_info().rss / (1024 * 1024), 2)

    # Deep analysis (3 runs to keep Windows laptop memory/time bounded)
    deep_lats = []
    deep_backends = []
    for fn, arg in [(engine.assess_url, url_sample), (engine.assess_sms, sms_sample), (engine.assess_network_flow, net_sample)]:
        rep = fn(arg, mode="deep_analysis")
        deep_lats.append(rep.total_latency_ms)
        deep_backends.append(rep.llm_backend)
    rss_deep_mb = round(proc.memory_info().rss / (1024 * 1024), 2)

    return {
        "fast_triage_no_llm": {
            "runs": len(fast_lats),
            "p50_latency_ms": round(float(np.percentile(fast_lats, 50)), 3),
            "p95_latency_ms": round(float(np.percentile(fast_lats, 95)), 3),
            "rss_memory_mb": rss_fast_mb,
        },
        "deep_analysis_with_local_llm": {
            "runs": len(deep_lats),
            "p50_latency_ms": round(float(np.percentile(deep_lats, 50)), 3),
            "p95_latency_ms": round(float(np.percentile(deep_lats, 95)), 3),
            "rss_memory_mb": rss_deep_mb,
            "llm_backend": deep_backends[0] if deep_backends else "unknown",
        },
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    net_res = evaluate_network_known_vs_unseen()
    adaptive = net_res.pop("fitted_adaptive_detector")
    adv_res = evaluate_adversarial_suites(adaptive)
    mode_bench = benchmark_fast_vs_deep(adaptive)

    payload = {
        "environment": {"platform": platform.platform(), "python": platform.python_version(), "seed": RANDOM_SEED},
        "network_known_vs_unseen": net_res,
        "adversarial_robustness": adv_res,
        "operating_modes_benchmark": mode_bench,
    }
    out_file = OUT_DIR / "phase2_results.json"
    out_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Saved Phase 2 results to {out_file}")


if __name__ == "__main__":
    main()
