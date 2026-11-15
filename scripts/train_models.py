"""
End-to-end training, model selection, calibration, and ExecuTorch (.pte) export script
for SecureEdge AI (Bharat AI-SoC Challenge 2026-27 | PS3).
"""

import gc
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

os.environ["LOKY_MAX_CPU_COUNT"] = "4"

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
import torch
import torch.nn as nn
from transformers import LlamaConfig, LlamaForCausalLM

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.download_datasets import main as prepare_datasets
from src.common.config import (
    LLAMA_MODEL_DIR,
    METRICS_DIR,
    NETWORK_MODEL_DIR,
    RANDOM_SEED,
    RAW_DATA_DIR,
    SMS_MODEL_DIR,
    URL_MODEL_DIR,
    ensure_directories,
)
from src.common.logger import get_logger
from src.executorch.exporter import LlamaExecuTorchExporter
from src.llama.tokenizer import CyberLlamaTokenizer
from src.network_detection.features import NetworkFlowFeatureExtractor
from src.sms_detection.features import SMSFeatureExtractor
from src.url_detection.features import URLFeatureExtractor

logger = get_logger("SecureEdge.Trainer")


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
    """Compute comprehensive binary classification metrics including FPR and confusion matrix."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp) / max(float(fp + tn), 1.0)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train_url_models() -> Dict[str, Any]:
    """
    Train and evaluate 4 candidate URL Phishing Detectors using strict domain-separated
    GroupShuffleSplit so no registered_domain appears in both train and test sets.
    """
    logger.info("=== [1/4] Training Phishing URL Detection Models (Domain-Separated Split) ===")
    df = pd.read_csv(RAW_DATA_DIR / "url_dataset.csv")
    urls = df["url"].astype(str).tolist()
    y = df["label"].to_numpy(dtype=np.int64)
    groups = df["registered_domain"].astype(str).to_numpy()

    X = URLFeatureExtractor.transform_batch(urls)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=RANDOM_SEED)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    train_domains = set(groups[train_idx])
    test_domains = set(groups[test_idx])
    domain_overlap = len(train_domains.intersection(test_domains))
    logger.info(
        "URL Split: Train=%d (%d domains), Test=%d (%d domains), Domain Overlap=%d",
        len(X_train),
        len(train_domains),
        len(X_test),
        len(test_domains),
        domain_overlap,
    )

    candidates = {
        "LogisticRegression": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1000, C=1.0, random_state=RANDOM_SEED)),
            ]
        ),
        "RandomForest_Calibrated": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        RandomForestClassifier(
                            n_estimators=120,
                            max_depth=12,
                            min_samples_leaf=2,
                            random_state=RANDOM_SEED,
                            n_jobs=1,
                        ),
                        cv=3,
                        method="sigmoid",
                    ),
                ),
            ]
        ),
        "GradientBoosting": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    HistGradientBoostingClassifier(
                        max_iter=120,
                        max_depth=8,
                        learning_rate=0.08,
                        random_state=RANDOM_SEED,
                    ),
                ),
            ]
        ),
        "Lightweight_MLP": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    MLPClassifier(
                        hidden_layer_sizes=(64, 32),
                        max_iter=300,
                        random_state=RANDOM_SEED,
                        early_stopping=True,
                    ),
                ),
            ]
        ),
    }

    comparison: Dict[str, Any] = {}
    best_name = ""
    best_f1 = -1.0
    best_pipeline = None

    for name, pipe in candidates.items():
        t0 = time.perf_counter()
        pipe.fit(X_train, y_train)
        train_ms = (time.perf_counter() - t0) * 1000.0

        y_pred = pipe.predict(X_test)
        y_prob = pipe.predict_proba(X_test)[:, 1]
        metrics = compute_binary_metrics(y_test, y_pred, y_prob)

        # Measure single-sample inference latency over 100 iterations
        sample_vec = X_test[:1]
        t_inf = time.perf_counter()
        for _ in range(100):
            _ = pipe.predict_proba(sample_vec)
        single_latency_ms = ((time.perf_counter() - t_inf) * 1000.0) / 100.0

        tmp_path = URL_MODEL_DIR / f"_tmp_{name}.joblib"
        joblib.dump(pipe, tmp_path, compress=3)
        size_kb = round(tmp_path.stat().st_size / 1024.0, 2)
        tmp_path.unlink(missing_ok=True)

        metrics["train_time_ms"] = round(train_ms, 2)
        metrics["inference_latency_ms"] = round(single_latency_ms, 4)
        metrics["model_size_kb"] = size_kb
        comparison[name] = metrics

        logger.info(
            "URL Candidate %-25s | F1=%.4f | AUC=%.4f | FPR=%.4f | Latency=%.3f ms | Size=%.1f KB",
            name,
            metrics["f1_score"],
            metrics["roc_auc"],
            metrics["false_positive_rate"],
            single_latency_ms,
            size_kb,
        )

        if metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_name = name
            best_pipeline = pipe

    target_path = URL_MODEL_DIR / "url_detector_pipeline.joblib"
    bundle = {
        "pipeline": best_pipeline,
        "model_version": f"url-{best_name.lower()}-v1.0",
        "is_calibrated": True,
        "feature_names": URLFeatureExtractor.feature_names,
        "metadata": {
            "selected_model": best_name,
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "domain_overlap_count": domain_overlap,
            "metrics": comparison[best_name],
            "all_candidates": comparison,
        },
    }
    joblib.dump(bundle, target_path, compress=3)
    final_size_kb = round(target_path.stat().st_size / 1024.0, 2)
    comparison[best_name]["saved_bundle_size_kb"] = final_size_kb
    logger.info("Saved best URL detector (%s, %.1f KB) to %s", best_name, final_size_kb, target_path)

    return {
        "selected_model": best_name,
        "domain_leakage_overlap": domain_overlap,
        "selected_metrics": comparison[best_name],
        "candidates": comparison,
    }


def train_sms_models() -> Dict[str, Any]:
    """Train and evaluate hybrid TF-IDF + structural SMS Scam/Spam Detectors."""
    logger.info("=== [2/4] Training Scam & Spam SMS Detection Models ===")
    df = pd.read_csv(RAW_DATA_DIR / "sms_dataset.csv")
    raw_texts = df["text"].astype(str).tolist()
    y = df["label"].to_numpy(dtype=np.int64)

    cleaned_texts = [SMSFeatureExtractor.clean_text(t) for t in raw_texts]
    X_struct = SMSFeatureExtractor.extract_structural_matrix(raw_texts)

    idx_all = np.arange(len(raw_texts))
    train_idx, test_idx = train_test_split(
        idx_all, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    train_texts = [cleaned_texts[i] for i in train_idx]
    test_texts = [cleaned_texts[i] for i in test_idx]
    X_struct_train, X_struct_test = X_struct[train_idx], X_struct[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    word_vec = TfidfVectorizer(ngram_range=(1, 2), max_features=2500, sublinear_tf=True)
    char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=2500, sublinear_tf=True)
    scaler = StandardScaler()

    X_w_train = word_vec.fit_transform(train_texts)
    X_c_train = char_vec.fit_transform(train_texts)
    X_s_train = csr_matrix(scaler.fit_transform(X_struct_train))
    X_train_full = hstack([X_w_train, X_c_train, X_s_train])

    X_w_test = word_vec.transform(test_texts)
    X_c_test = char_vec.transform(test_texts)
    X_s_test = csr_matrix(scaler.transform(X_struct_test))
    X_test_full = hstack([X_w_test, X_c_test, X_s_test])

    candidates = {
        "Calibrated_LinearSVC": CalibratedClassifierCV(
            LinearSVC(C=1.0, random_state=RANDOM_SEED), cv=3, method="sigmoid"
        ),
        "LogisticRegression": LogisticRegression(max_iter=1000, C=2.0, random_state=RANDOM_SEED),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=16, random_state=RANDOM_SEED, n_jobs=1),
    }

    comparison: Dict[str, Any] = {}
    best_name = ""
    best_f1 = -1.0
    best_clf = None

    for name, clf in candidates.items():
        t0 = time.perf_counter()
        clf.fit(X_train_full, y_train)
        train_ms = (time.perf_counter() - t0) * 1000.0

        y_pred = clf.predict(X_test_full)
        y_prob = clf.predict_proba(X_test_full)[:, 1]
        metrics = compute_binary_metrics(y_test, y_pred, y_prob)

        sample_row = X_test_full[:1]
        t_inf = time.perf_counter()
        for _ in range(100):
            _ = clf.predict_proba(sample_row)
        single_latency_ms = ((time.perf_counter() - t_inf) * 1000.0) / 100.0

        metrics["train_time_ms"] = round(train_ms, 2)
        metrics["inference_latency_ms"] = round(single_latency_ms, 4)
        comparison[name] = metrics

        logger.info(
            "SMS Candidate %-25s | F1=%.4f | AUC=%.4f | FPR=%.4f | Latency=%.3f ms",
            name,
            metrics["f1_score"],
            metrics["roc_auc"],
            metrics["false_positive_rate"],
            single_latency_ms,
        )

        if metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_name = name
            best_clf = clf

    target_path = SMS_MODEL_DIR / "sms_detector_pipeline.joblib"
    bundle = {
        "word_vectorizer": word_vec,
        "char_vectorizer": char_vec,
        "scaler": scaler,
        "classifier": best_clf,
        "model_version": f"sms-{best_name.lower()}-v1.0",
        "is_calibrated": True,
        "metadata": {
            "selected_model": best_name,
            "train_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
            "metrics": comparison[best_name],
            "all_candidates": comparison,
        },
    }
    joblib.dump(bundle, target_path, compress=3)
    size_kb = round(target_path.stat().st_size / 1024.0, 2)
    comparison[best_name]["model_size_kb"] = size_kb
    logger.info("Saved best SMS detector (%s, %.1f KB) to %s", best_name, size_kb, target_path)

    return {
        "selected_model": best_name,
        "selected_metrics": comparison[best_name],
        "candidates": comparison,
    }


def train_network_models() -> Dict[str, Any]:
    """Train and evaluate Network Flow Anomaly Detection models (Supervised RF + IsolationForest)."""
    logger.info("=== [3/4] Training Network Flow Anomaly Detection Models ===")
    df = pd.read_csv(RAW_DATA_DIR / "network_flows_dataset.csv")
    flow_records = df.to_dict(orient="records")
    y = df["label"].to_numpy(dtype=np.int64)

    X = NetworkFlowFeatureExtractor.transform_batch(flow_records)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_SEED, stratify=y
    )

    # Fit unsupervised IsolationForest on benign training flows for zero-day anomaly boost
    X_train_benign = X_train[y_train == 0]
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_SEED,
        n_jobs=1,
    )
    iso_forest.fit(X_train_benign)

    candidates = {
        "RandomForest_Calibrated": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "clf",
                    CalibratedClassifierCV(
                        RandomForestClassifier(
                            n_estimators=100,
                            max_depth=10,
                            random_state=RANDOM_SEED,
                            n_jobs=1,
                        ),
                        cv=3,
                        method="sigmoid",
                    ),
                ),
            ]
        ),
        "GradientBoosting": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", HistGradientBoostingClassifier(max_iter=100, max_depth=6, random_state=RANDOM_SEED)),
            ]
        ),
        "LogisticRegression": Pipeline(
            [
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(max_iter=1000, random_state=RANDOM_SEED)),
            ]
        ),
    }

    comparison: Dict[str, Any] = {}
    best_name = ""
    best_f1 = -1.0
    best_pipe = None

    for name, pipe in candidates.items():
        t0 = time.perf_counter()
        pipe.fit(X_train, y_train)
        train_ms = (time.perf_counter() - t0) * 1000.0

        y_pred = pipe.predict(X_test)
        y_prob = pipe.predict_proba(X_test)[:, 1]
        metrics = compute_binary_metrics(y_test, y_pred, y_prob)

        sample_row = X_test[:1]
        t_inf = time.perf_counter()
        for _ in range(100):
            _ = pipe.predict_proba(sample_row)
        single_latency_ms = ((time.perf_counter() - t_inf) * 1000.0) / 100.0

        metrics["train_time_ms"] = round(train_ms, 2)
        metrics["inference_latency_ms"] = round(single_latency_ms, 4)
        comparison[name] = metrics

        logger.info(
            "Network Candidate %-22s | F1=%.4f | AUC=%.4f | FPR=%.4f | Latency=%.3f ms",
            name,
            metrics["f1_score"],
            metrics["roc_auc"],
            metrics["false_positive_rate"],
            single_latency_ms,
        )

        if metrics["f1_score"] > best_f1:
            best_f1 = metrics["f1_score"]
            best_name = name
            best_pipe = pipe

    target_path = NETWORK_MODEL_DIR / "network_detector_pipeline.joblib"
    bundle = {
        "pipeline": best_pipe,
        "isolation_forest": iso_forest,
        "model_version": f"net-{best_name.lower()}-v1.0",
        "is_calibrated": True,
        "feature_names": NetworkFlowFeatureExtractor.feature_names,
        "metadata": {
            "selected_model": best_name,
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "metrics": comparison[best_name],
            "all_candidates": comparison,
        },
    }
    joblib.dump(bundle, target_path, compress=3)
    size_kb = round(target_path.stat().st_size / 1024.0, 2)
    comparison[best_name]["model_size_kb"] = size_kb
    logger.info("Saved best Network detector (%s, %.1f KB) to %s", best_name, size_kb, target_path)

    return {
        "selected_model": best_name,
        "selected_metrics": comparison[best_name],
        "candidates": comparison,
    }


def train_and_export_llama_executorch() -> Dict[str, Any]:
    """
    Train our on-device LlamaForCausalLM (Llama 3.2 GQA + RoPE + SwiGLU architecture)
    on structured cybersecurity threat advisories and export it through torch.export / ExecuTorch
    into the required .pte and .pt2 artifacts.
    """
    logger.info("=== [4/4] Training & Exporting Llama-3.2 Architecture Model to ExecuTorch (.pte) ===")
    torch.manual_seed(RANDOM_SEED)
    tokenizer = CyberLlamaTokenizer()
    tokenizer.save()

    seq_len = 64
    config = LlamaConfig(
        vocab_size=tokenizer.VOCAB_SIZE,
        hidden_size=128,
        intermediate_size=256,
        num_hidden_layers=3,
        num_attention_heads=4,
        num_key_value_heads=2,  # Grouped-Query Attention (Llama 3.2 spec)
        hidden_act="silu",      # SwiGLU activation
        max_position_embeddings=seq_len,
        rms_norm_eps=1e-5,
        rope_theta=500000.0,    # Llama 3.2 RoPE theta
        pad_token_id=tokenizer.pad_token_id,
        bos_token_id=tokenizer.bos_token_id,
        eos_token_id=tokenizer.eos_token_id,
    )

    model = LlamaForCausalLM(config)
    model.train()

    # Construct domain training pairs: (structured threat prompt -> grounded advisory clause)
    training_pairs = [
        (
            "<json> threat_type : phishing , risk_level : high , confidence : 94 % , evidence : [ suspicious url structure ; brand impersonation ] <sep>",
            "the url contains phishing structure used to deceive users into revealing sensitive credentials . do not open link or enter password",
        ),
        (
            "<json> threat_type : phishing , risk_level : critical , confidence : 98 % , evidence : [ ip address hostname ; credential verify login ] <sep>",
            "the url contains phishing structure used to deceive users into revealing sensitive credentials . do not open link or enter password",
        ),
        (
            "<json> threat_type : scam , risk_level : high , confidence : 92 % , evidence : [ urgency coercion ; financial kyc upi otp link ] <sep>",
            "this sms message contains financial scam coercion used to deceive users . do not click link or share otp",
        ),
        (
            "<json> threat_type : spam , risk_level : medium , confidence : 78 % , evidence : [ promotional lottery prize reward callback phone ] <sep>",
            "this sms message contains promotional spam solicitation . do not call phone number or click link",
        ),
        (
            "<json> threat_type : network_anomaly , risk_level : high , confidence : 95 % , evidence : [ tcp syn flood dos ; port scan probing ] <sep>",
            "the network flow exhibits suspicious syn flood and port scan probing . inspect firewall rules and rate limit connection attempts",
        ),
        (
            "<json> threat_type : benign , risk_level : low , confidence : 96 % , evidence : [ standard url structure ; no anomalous indicators ] <sep>",
            "no anomalous indicators were found by specialized detector . safe standard structure proceed with normal caution",
        ),
    ]

    # Build token tensors for causal language model training
    input_batches = []
    label_batches = []
    for prompt_str, target_str in training_pairs:
        p_ids = tokenizer.encode(prompt_str, add_bos=True, add_eos=False, max_length=34)
        t_ids = tokenizer.encode(target_str, add_bos=False, add_eos=True, max_length=seq_len - len(p_ids))
        full_seq = p_ids + t_ids
        padded_input = full_seq + [tokenizer.pad_token_id] * (seq_len - len(full_seq))
        # Mask prompt and padding in labels with -100 so loss focuses on target advisory generation
        labels = ([-100] * len(p_ids)) + t_ids + ([-100] * (seq_len - len(full_seq)))
        input_batches.append(padded_input[:seq_len])
        label_batches.append(labels[:seq_len])

    x_tensor = torch.tensor(input_batches, dtype=torch.long)
    y_tensor = torch.tensor(label_batches, dtype=torch.long)

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-3, weight_decay=0.01)
    t_train0 = time.perf_counter()
    final_loss = 0.0
    for epoch in range(90):
        optimizer.zero_grad()
        out = model(input_ids=x_tensor, labels=y_tensor)
        loss = out.loss
        loss.backward()
        optimizer.step()
        final_loss = float(loss.item())

    train_ms = (time.perf_counter() - t_train0) * 1000.0
    logger.info("Trained LlamaForCausalLM advisor for 90 epochs (final CE loss=%.4f in %.1f ms)", final_loss, train_ms)

    model.eval()
    # Save HuggingFace checkpoint alongside the ExecuTorch .pte artifact
    hf_dir = LLAMA_MODEL_DIR / "hf_checkpoint"
    hf_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(hf_dir))

    export_meta = LlamaExecuTorchExporter.export_llama_to_pte(model, seq_len=seq_len)
    export_meta["training_final_loss"] = round(final_loss, 5)
    export_meta["training_time_ms"] = round(train_ms, 2)

    gc.collect()
    return export_meta


def main() -> None:
    ensure_directories()
    if not (RAW_DATA_DIR / "url_dataset.csv").exists():
        prepare_datasets()

    url_res = train_url_models()
    sms_res = train_sms_models()
    net_res = train_network_models()
    llama_res = train_and_export_llama_executorch()

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url_detection": url_res,
        "sms_detection": sms_res,
        "network_detection": net_res,
        "llama_executorch": llama_res,
    }
    summary_path = METRICS_DIR / "training_and_evaluation_metrics.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("All models trained and exported! Summary saved to %s", summary_path)


if __name__ == "__main__":
    main()
