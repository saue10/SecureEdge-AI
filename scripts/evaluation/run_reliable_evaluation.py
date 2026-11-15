"""
Phase 1: Dataset Integrity & Trustworthy Evaluation Pipeline for SecureEdge AI.
Reproducible single-command script that:
1. Audits and deduplicates SMS and URL datasets (preserving raw data unchanged).
2. Enforces leakage-resistant train/validation/test splits (zero normalized-text leakage,
   near-duplicate template grouping for SMS, registered-domain grouping for URL,
   and both src_ip-grouped and unseen-scenario splits for Network flows).
3. Fits all vectorizers, scalers, and calibration strictly on training data.
4. Selects operating thresholds strictly on validation data (never on test data),
   including a low-confidence/uncertain band [0.40, 0.60).
5. Evaluates all baseline models with per-class F1, macro/weighted F1, Brier score,
   FPR/FNR, confusion matrices, subgroup breakdowns, latency, and serialized model size.
"""

import hashlib
import io
import json
import pickle
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.sparse import hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import RANDOM_SEED, RAW_DATA_DIR
from src.network_detection.features import FLOW_FEATURE_NAMES
from src.sms_detection.features import SMSFeatureExtractor
from src.url_detection.features import URLFeatureExtractor

RESULTS_DIR = PROJECT_ROOT / "results" / "reliable_evaluation"
DATASETS_OUT_DIR = RESULTS_DIR / "datasets"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_sms_text(text: str) -> str:
    s = str(text).lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^\w\s]", "", s)
    return s.strip()


def sms_template_group(text: str) -> str:
    cleaned = SMSFeatureExtractor.clean_text(str(text))
    return re.sub(r"\d+", "<NUM>", cleaned).lower().strip()


def normalize_url_text(url: str) -> str:
    return str(url).strip().lower()


def select_validation_threshold(
    y_val: np.ndarray,
    probs_val: np.ndarray,
    min_recall: float = 0.90,
) -> Dict[str, Any]:
    """Select decision threshold strictly on validation probabilities."""
    best_thresh = 0.50
    best_score = -1.0
    for t in np.linspace(0.25, 0.75, 51):
        preds = (probs_val >= t).astype(int)
        rec = recall_score(y_val, preds, zero_division=0)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        # Prioritize recall >= min_recall, then maximize macro F1
        score = macro_f1 + (0.5 if rec >= min_recall else 0.0)
        if score > best_score:
            best_score = score
            best_thresh = float(round(t, 2))
    return {"selected_threshold": best_thresh, "val_objective_score": round(float(best_score), 4)}


def compute_full_metrics(
    y_true: np.ndarray,
    probs: np.ndarray,
    threshold: float,
    class_names: Tuple[str, str] = ("benign", "malicious"),
) -> Dict[str, Any]:
    preds = (probs >= threshold).astype(int)
    cm = confusion_matrix(y_true, preds, labels=[0, 1])
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    per_class_f1 = f1_score(y_true, preds, labels=[0, 1], average=None, zero_division=0)
    low_conf_count = int(np.sum((probs >= 0.40) & (probs < 0.60)))
    return {
        "threshold": threshold,
        "accuracy": round(float(accuracy_score(y_true, preds)), 4),
        "precision_pos": round(float(precision_score(y_true, preds, zero_division=0)), 4),
        "recall_pos": round(float(recall_score(y_true, preds, zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_true, preds, average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y_true, preds, average="weighted", zero_division=0)), 4),
        "per_class_f1": {
            class_names[0]: round(float(per_class_f1[0]), 4),
            class_names[1]: round(float(per_class_f1[1]), 4),
        },
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "brier_score": round(float(brier_score_loss(y_true, np.clip(probs, 0.0, 1.0))), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "low_confidence_uncertain_count": low_conf_count,
    }


def serialized_size_kb(obj: Any) -> float:
    buf = io.BytesIO()
    joblib.dump(obj, buf, compress=3)
    return round(len(buf.getvalue()) / 1024.0, 2)


def group_split_3way(
    df: pd.DataFrame,
    group_col: str,
    seed: int = RANDOM_SEED,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    gss1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    tr_idx, tmp_idx = next(gss1.split(df, df["label"], groups=df[group_col]))
    train_df = df.iloc[tr_idx].reset_index(drop=True)
    tmp_df = df.iloc[tmp_idx].reset_index(drop=True)

    gss2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
    val_idx, te_idx = next(gss2.split(tmp_df, tmp_df["label"], groups=tmp_df[group_col]))
    val_df = tmp_df.iloc[val_idx].reset_index(drop=True)
    test_df = tmp_df.iloc[te_idx].reset_index(drop=True)
    return train_df, val_df, test_df


def evaluate_sms_pipeline(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    raw_path = RAW_DATA_DIR / "sms_dataset.csv"
    df_raw = pd.read_csv(raw_path)
    df_raw["norm_text"] = df_raw["text"].map(normalize_sms_text)
    df_raw["template_group"] = df_raw["text"].map(sms_template_group)

    label_conflicts = int((df_raw.groupby("norm_text")["label"].nunique() > 1).sum())
    dup_mask = df_raw.duplicated(subset=["norm_text"], keep="first")
    df_removed = df_raw[dup_mask].copy()
    df_clean = df_raw[~dup_mask].reset_index(drop=True)

    df_clean.to_csv(DATASETS_OUT_DIR / "sms_deduplicated.csv", index=False)
    df_removed.to_csv(DATASETS_OUT_DIR / "sms_removed_duplicates.csv", index=False)

    # Split A: Exact-dedup Stratified 70/15/15
    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    tr_a, tmp_a = next(sss1.split(df_clean, df_clean["label"]))
    train_a = df_clean.iloc[tr_a].reset_index(drop=True)
    tmp_df_a = df_clean.iloc[tmp_a].reset_index(drop=True)
    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=seed)
    val_a, te_a = next(sss2.split(tmp_df_a, tmp_df_a["label"]))
    val_df_a = tmp_df_a.iloc[val_a].reset_index(drop=True)
    test_df_a = tmp_df_a.iloc[te_a].reset_index(drop=True)

    # Split B: Near-duplicate Template-Grouped 70/15/15 (zero template overlap)
    train_b, val_b, test_b = group_split_3way(df_clean, "template_group", seed=seed)

    def run_sms_models(tr: pd.DataFrame, va: pd.DataFrame, te: pd.DataFrame, split_name: str) -> Dict[str, Any]:
        norm_overlap = len(set(tr["norm_text"]) & set(te["norm_text"]))
        group_overlap = len(set(tr["template_group"]) & set(te["template_group"]))

        tr_clean = [SMSFeatureExtractor.clean_text(t) for t in tr["text"]]
        va_clean = [SMSFeatureExtractor.clean_text(t) for t in va["text"]]
        te_clean = [SMSFeatureExtractor.clean_text(t) for t in te["text"]]

        word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=2500, sublinear_tf=True, min_df=2)
        char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=2500, sublinear_tf=True, min_df=2)

        X_tr_w = word_vec.fit_transform(tr_clean)
        X_va_w = word_vec.transform(va_clean)
        X_te_w = word_vec.transform(te_clean)

        X_tr_c = char_vec.fit_transform(tr_clean)
        X_va_c = char_vec.transform(va_clean)
        X_te_c = char_vec.transform(te_clean)

        scaler = StandardScaler()
        S_tr_raw = SMSFeatureExtractor.extract_structural_matrix(list(tr["text"]))
        S_va_raw = SMSFeatureExtractor.extract_structural_matrix(list(va["text"]))
        S_te_raw = SMSFeatureExtractor.extract_structural_matrix(list(te["text"]))
        S_tr = scaler.fit_transform(S_tr_raw)
        S_va = scaler.transform(S_va_raw)
        S_te = scaler.transform(S_te_raw)

        X_tr_comb = hstack([X_tr_w, X_tr_c, S_tr]).tocsr()
        X_va_comb = hstack([X_va_w, X_va_c, S_va]).tocsr()
        X_te_comb = hstack([X_te_w, X_te_c, S_te]).tocsr()

        y_tr, y_va, y_te = tr["label"].to_numpy(), va["label"].to_numpy(), te["label"].to_numpy()
        otp_mask = S_te_raw[:, -1] > 0.5
        personal_ham_mask = (y_te == 0) & (~otp_mask)

        specs = {
            "RandomForest_Combined": (RandomForestClassifier(n_estimators=120, max_depth=16, random_state=seed, n_jobs=-1), X_tr_comb, X_va_comb, X_te_comb),
            "LogReg_Word_TFIDF": (LogisticRegression(max_iter=1000, C=2.0, random_state=seed), X_tr_w, X_va_w, X_te_w),
            "LogReg_Char_TFIDF": (LogisticRegression(max_iter=1000, C=2.0, random_state=seed), X_tr_c, X_va_c, X_te_c),
            "LogReg_Combined_TFIDF": (LogisticRegression(max_iter=1000, C=2.0, random_state=seed), X_tr_comb, X_va_comb, X_te_comb),
            "Calibrated_LinearSVC": (CalibratedClassifierCV(LinearSVC(C=1.0, random_state=seed, max_iter=3000), cv=3, method="sigmoid"), X_tr_comb, X_va_comb, X_te_comb),
        }

        models_out: Dict[str, Any] = {}
        for name, (clf, Xtr, Xva, Xte) in specs.items():
            clf.fit(Xtr, y_tr)
            p_va = clf.predict_proba(Xva)[:, 1]
            thresh_info = select_validation_threshold(y_va, p_va, min_recall=0.90)
            t_sel = thresh_info["selected_threshold"]

            p_te = clf.predict_proba(Xte)[:, 1]
            metrics = compute_full_metrics(y_te, p_te, t_sel, class_names=("ham", "scam_spam"))
            preds_te = (p_te >= t_sel).astype(int)

            # Single-item latency
            latencies = []
            for i in range(min(30, Xte.shape[0])):
                row = Xte[i]
                t0 = time.perf_counter()
                clf.predict_proba(row)
                latencies.append((time.perf_counter() - t0) * 1000.0)

            otp_fp = int(np.sum((preds_te == 1) & otp_mask))
            pers_fp = int(np.sum((preds_te == 1) & personal_ham_mask))
            models_out[name] = {
                **metrics,
                "val_threshold_info": thresh_info,
                "otp_false_positives": otp_fp,
                "otp_total_test": int(np.sum(otp_mask)),
                "personal_ham_false_positives": pers_fp,
                "personal_ham_total_test": int(np.sum(personal_ham_mask)),
                "mean_latency_ms": round(float(np.mean(latencies)), 3),
                "model_size_kb": serialized_size_kb(clf),
            }

        return {
            "split_name": split_name,
            "train_rows": len(tr),
            "val_rows": len(va),
            "test_rows": len(te),
            "train_groups": int(tr["template_group"].nunique()),
            "val_groups": int(va["template_group"].nunique()),
            "test_groups": int(te["template_group"].nunique()),
            "normalized_text_overlap": norm_overlap,
            "template_group_overlap": group_overlap,
            "models": models_out,
        }

    return {
        "dataset_sha256": sha256_file(raw_path),
        "raw_rows": len(df_raw),
        "removed_duplicate_rows": len(df_removed),
        "removed_by_category": df_removed["category"].value_counts().to_dict(),
        "unique_normalized_rows": len(df_clean),
        "unique_template_groups": int(df_clean["template_group"].nunique()),
        "label_conflicts": label_conflicts,
        "clean_category_counts": df_clean["category"].value_counts().to_dict(),
        "split_a_exact_dedup_stratified": run_sms_models(train_a, val_df_a, test_df_a, "Exact-Dedup Stratified 70/15/15"),
        "split_b_template_grouped": run_sms_models(train_b, val_b, test_b, "Near-Dup Template-Grouped 70/15/15"),
    }


def evaluate_url_pipeline(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    raw_path = RAW_DATA_DIR / "url_dataset.csv"
    df_raw = pd.read_csv(raw_path)
    df_raw["norm_url"] = df_raw["url"].map(normalize_url_text)
    dup_mask = df_raw.duplicated(subset=["norm_url"], keep="first")
    df_removed = df_raw[dup_mask].copy()
    df_clean = df_raw[~dup_mask].reset_index(drop=True)

    df_clean.to_csv(DATASETS_OUT_DIR / "url_deduplicated.csv", index=False)
    df_removed.to_csv(DATASETS_OUT_DIR / "url_removed_duplicates.csv", index=False)

    train_df, val_df, test_df = group_split_3way(df_clean, "registered_domain", seed=seed)
    domain_overlap = len(set(train_df["registered_domain"]) & set(test_df["registered_domain"]))

    def featurize(df_part: pd.DataFrame) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
        urls = list(df_part["url"])
        X = URLFeatureExtractor.transform_batch(urls)
        meta = [URLFeatureExtractor.extract_features_and_evidence(u)[0] for u in urls]
        return np.array(X, dtype=np.float32), meta

    X_tr, _ = featurize(train_df)
    X_va, _ = featurize(val_df)
    X_te, meta_te = featurize(test_df)
    y_tr, y_va, y_te = train_df["label"].to_numpy(), val_df["label"].to_numpy(), test_df["label"].to_numpy()

    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_va_s = scaler.transform(X_va)
    X_te_s = scaler.transform(X_te)

    specs = {
        "RandomForest_Calibrated": (CalibratedClassifierCV(RandomForestClassifier(n_estimators=120, max_depth=14, random_state=seed, n_jobs=-1), cv=3, method="sigmoid"), X_tr, X_va, X_te),
        "LogisticRegression": (LogisticRegression(max_iter=1000, C=1.5, random_state=seed), X_tr_s, X_va_s, X_te_s),
        "HistGradientBoosting": (HistGradientBoostingClassifier(max_iter=120, max_depth=6, random_state=seed), X_tr, X_va, X_te),
    }

    subgroups = {
        "punycode": np.array([m.get("has_punycode", 0) == 1 for m in meta_te]),
        "raw_ip": np.array([m.get("has_ip_address", 0) == 1 for m in meta_te]),
        "shortener": np.array([m.get("is_shortener", 0) == 1 for m in meta_te]),
        "suspicious_subdomain": np.array([m.get("subdomain_count", 0) >= 2 for m in meta_te]),
        "brand_impersonation": np.array([m.get("brand_in_subdomain_or_path", 0) == 1 for m in meta_te]),
        "hard_negative_benign": (test_df["category"] == "benign_hard_negative").to_numpy(),
        "stealth_phishing": (test_df["category"] == "stealth_phishing").to_numpy(),
    }

    models_out: Dict[str, Any] = {}
    for name, (clf, Xtr, Xva, Xte) in specs.items():
        clf.fit(Xtr, y_tr)
        p_va = clf.predict_proba(Xva)[:, 1]
        thresh_info = select_validation_threshold(y_va, p_va, min_recall=0.95)
        t_sel = thresh_info["selected_threshold"]

        p_te = clf.predict_proba(Xte)[:, 1]
        metrics = compute_full_metrics(y_te, p_te, t_sel, class_names=("benign", "phishing"))
        preds_te = (p_te >= t_sel).astype(int)

        sub_acc = {}
        for sg_name, mask in subgroups.items():
            if np.sum(mask) > 0:
                sub_acc[sg_name] = {
                    "count": int(np.sum(mask)),
                    "accuracy": round(float(accuracy_score(y_te[mask], preds_te[mask])), 4),
                }

        latencies = []
        for i in range(min(30, len(Xte))):
            t0 = time.perf_counter()
            clf.predict_proba(Xte[i : i + 1])
            latencies.append((time.perf_counter() - t0) * 1000.0)

        models_out[name] = {
            **metrics,
            "val_threshold_info": thresh_info,
            "subgroup_accuracy": sub_acc,
            "mean_latency_ms": round(float(np.mean(latencies)), 3),
            "model_size_kb": serialized_size_kb(clf),
        }

    return {
        "dataset_sha256": sha256_file(raw_path),
        "raw_rows": len(df_raw),
        "removed_duplicate_rows": len(df_removed),
        "unique_normalized_rows": len(df_clean),
        "unique_registered_domains": int(df_clean["registered_domain"].nunique()),
        "train_rows": len(train_df),
        "val_rows": len(val_df),
        "test_rows": len(test_df),
        "domain_overlap": domain_overlap,
        "models": models_out,
    }


def evaluate_network_pipeline(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    raw_path = RAW_DATA_DIR / "network_flows_dataset.csv"
    df_raw = pd.read_csv(raw_path)
    feat_cols = FLOW_FEATURE_NAMES

    corr_matrix = df_raw[feat_cols].corr().abs()
    high_corr_pairs = []
    for i in range(len(feat_cols)):
        for j in range(i + 1, len(feat_cols)):
            val = float(corr_matrix.iloc[i, j])
            if val >= 0.85:
                high_corr_pairs.append({"f1": feat_cols[i], "f2": feat_cols[j], "abs_r": round(val, 4)})

    label_corrs = df_raw[feat_cols].corrwith(df_raw["label"]).abs().sort_values(ascending=False)

    # Split A: Grouped by src_ip
    train_a, val_a, test_a = group_split_3way(df_raw, "src_ip", seed=seed)
    # Split B: Grouped by attack_type scenario (unseen attack/benign scenarios in val/test)
    train_b, val_b, test_b = group_split_3way(df_raw, "attack_type", seed=seed)

    def run_net_models(tr: pd.DataFrame, va: pd.DataFrame, te: pd.DataFrame, split_name: str) -> Dict[str, Any]:
        X_tr = tr[feat_cols].to_numpy(dtype=np.float32)
        X_va = va[feat_cols].to_numpy(dtype=np.float32)
        X_te = te[feat_cols].to_numpy(dtype=np.float32)
        y_tr, y_va, y_te = tr["label"].to_numpy(), va["label"].to_numpy(), te["label"].to_numpy()

        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr)
        X_va_s = scaler.transform(X_va)
        X_te_s = scaler.transform(X_te)

        specs = {
            "RandomForest_Calibrated": (CalibratedClassifierCV(RandomForestClassifier(n_estimators=120, max_depth=14, random_state=seed, n_jobs=-1), cv=3, method="sigmoid"), X_tr, X_va, X_te),
            "HistGradientBoosting": (HistGradientBoostingClassifier(max_iter=120, max_depth=6, random_state=seed), X_tr, X_va, X_te),
            "LogisticRegression": (LogisticRegression(max_iter=1000, C=1.5, random_state=seed), X_tr_s, X_va_s, X_te_s),
        }

        models_out = {}
        for name, (clf, Xtr, Xva, Xte) in specs.items():
            clf.fit(Xtr, y_tr)
            p_va = clf.predict_proba(Xva)[:, 1]
            thresh_info = select_validation_threshold(y_va, p_va, min_recall=0.90)
            t_sel = thresh_info["selected_threshold"]

            p_te = clf.predict_proba(Xte)[:, 1]
            metrics = compute_full_metrics(y_te, p_te, t_sel, class_names=("benign_flow", "anomaly_flow"))

            latencies = []
            for i in range(min(30, len(Xte))):
                t0 = time.perf_counter()
                clf.predict_proba(Xte[i : i + 1])
                latencies.append((time.perf_counter() - t0) * 1000.0)

            models_out[name] = {
                **metrics,
                "val_threshold_info": thresh_info,
                "mean_latency_ms": round(float(np.mean(latencies)), 3),
                "model_size_kb": serialized_size_kb(clf),
            }

        return {
            "split_name": split_name,
            "train_rows": len(tr),
            "val_rows": len(va),
            "test_rows": len(te),
            "test_scenarios": sorted(te["attack_type"].unique().tolist()),
            "models": models_out,
        }

    return {
        "dataset_sha256": sha256_file(raw_path),
        "raw_rows": len(df_raw),
        "exact_duplicates": int(df_raw.duplicated().sum()),
        "attack_type_counts": df_raw["attack_type"].value_counts().to_dict(),
        "top_label_correlations": {k: round(float(v), 4) for k, v in label_corrs.head(6).items()},
        "highly_correlated_feature_pairs": high_corr_pairs,
        "split_a_src_ip_grouped": run_net_models(train_a, val_a, test_a, "SrcIP-Grouped 70/15/15"),
        "split_b_unseen_scenario_grouped": run_net_models(train_b, val_b, test_b, "Unseen-Scenario Grouped (attack_type)"),
    }


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    DATASETS_OUT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "metadata": {
            "random_seed": RANDOM_SEED,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "scikit_learn_version": sklearn.__version__,
            "pandas_version": pd.__version__,
            "numpy_version": np.__version__,
            "note": "All evaluations run strictly on deduplicated/grouped splits of existing project datasets (synthetic/templated origin disclosed).",
        },
        "sms_evaluation": evaluate_sms_pipeline(RANDOM_SEED),
        "url_evaluation": evaluate_url_pipeline(RANDOM_SEED),
        "network_evaluation": evaluate_network_pipeline(RANDOM_SEED),
    }

    out_path = RESULTS_DIR / "reliable_evaluation_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Saved reliable evaluation report to {out_path}")


if __name__ == "__main__":
    main()
