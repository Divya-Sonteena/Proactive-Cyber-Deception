#!/usr/bin/env python3
"""
Evaluate the trained DistilBERT attack classifier on the held-out test set.

Outputs reports/distilbert_evaluation.json and prints a human-readable digest.

Usage:
  python scripts/evaluate_distilbert.py
  python scripts/evaluate_distilbert.py --model-dir models/distilbert_attack_classifier
  python scripts/evaluate_distilbert.py --threshold 0.6
  python scripts/evaluate_distilbert.py --also-val
"""

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import DistilBertForSequenceClassification

sys.path.insert(0, str(Path(__file__).parent))
from token_definitions import TOKEN_TO_ID, VOCAB_SIZE, get_category  # noqa: E402

# ── Paths & Defaults ─────────────────────────────────────────────────────────
PROCESSED_DIR   = Path("data/processed")
MODEL_DIR       = Path("models/distilbert_attack_classifier")
REPORTS_DIR     = Path("reports")
DEFAULT_MAX_LEN = 128
DEFAULT_BATCH   = 64
DEFAULT_THRESHOLD = 0.5
N_BOOTSTRAP     = 1000


# ── Utilities ─────────────────────────────────────────────────────────────────

def _clean(obj):
    """Recursively replace NaN/Inf with None for valid JSON serialisation."""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, float) and (np.isnan(obj) or np.isinf(obj)):
        return None
    if isinstance(obj, np.integer):
        return int(obj)
    if isinstance(obj, np.floating):
        return None if (np.isnan(obj) or np.isinf(obj)) else float(obj)
    if isinstance(obj, np.ndarray):
        return _clean(obj.tolist())
    return obj


def _pct(n: int, total: int) -> str:
    return f"{n / total * 100:.1f}%" if total else "—"


def _safe_metrics(y_true, y_pred, y_prob) -> dict:
    """Binary classification metrics including MCC and multi-class F1 variants."""
    try:    auc = round(roc_auc_score(y_true, y_prob), 4)
    except ValueError: auc = None
    try:    mcc = round(float(matthews_corrcoef(y_true, y_pred)), 4)
    except ValueError: mcc = None
    return {
        "accuracy":    round(accuracy_score(y_true, y_pred), 4),
        "precision":   round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall":      round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1":          round(f1_score(y_true, y_pred, zero_division=0), 4),
        "f1_macro":    round(f1_score(y_true, y_pred, average="macro",    zero_division=0), 4),
        "f1_weighted": round(f1_score(y_true, y_pred, average="weighted", zero_division=0), 4),
        "mcc": mcc, "roc_auc": auc, "n_samples": int(len(y_true)),
    }


def _group_breakdown(all_details, group_key, label_key="true_label",
                     pred_key="predicted_int", prob_key="prob_malicious"):
    """Group details by *group_key* and compute per-group metrics."""
    groups: dict[str, dict] = defaultdict(lambda: {"true": [], "pred": [], "prob": []})
    for d in all_details:
        g = groups[d[group_key]]
        g["true"].append(d[label_key])
        g["pred"].append(d[pred_key])
        g["prob"].append(d[prob_key])

    metrics = {}
    for name in sorted(groups):
        g = groups[name]
        metrics[name] = _safe_metrics(np.array(g["true"]),
                                      np.array(g["pred"]),
                                      np.array(g["prob"]))
    return metrics


# ── Sequence encoding & batching ──────────────────────────────────────────────

def encode_sequence(tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
    """Token strings → (input_ids, attention_mask), tail-truncated + right-padded."""
    ids  = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens][-max_len:]
    return ids, [1] * len(ids)


def make_batch(sequences, start, end, max_len, pad_id, device):
    """Collate a slice of sequences into a padded batch tensor dict."""
    chunk = sequences[start:end]
    batch_ids, batch_msk = [], []
    for seq in chunk:
        ids, msk = encode_sequence(seq["tokens"], max_len)
        batch_ids.append(ids)
        batch_msk.append(msk)

    max_b = max(len(ids) for ids in batch_ids)
    for i in range(len(batch_ids)):
        pad = max_b - len(batch_ids[i])
        batch_ids[i] += [pad_id] * pad
        batch_msk[i] += [0] * pad

    return {
        "input_ids":      torch.tensor(batch_ids, dtype=torch.long, device=device),
        "attention_mask": torch.tensor(batch_msk, dtype=torch.long, device=device),
    }


# ── Multi-threshold analysis ─────────────────────────────────────────────────

def threshold_sweep(y_true: np.ndarray, y_prob: np.ndarray) -> dict:
    """Sweep thresholds from 0.05 to 0.95 and return metrics at each."""
    thresholds = np.arange(0.05, 1.0, 0.05)
    results, best_f1, best_t = [], 0.0, 0.5
    for t in thresholds:
        preds = (y_prob >= t).astype(int)
        f1  = f1_score(y_true, preds, zero_division=0)
        mcc = float(matthews_corrcoef(y_true, preds)) if len(set(y_true)) > 1 else 0.0
        results.append({
            "threshold": round(float(t), 2),
            "accuracy":  round(accuracy_score(y_true, preds), 4),
            "precision": round(precision_score(y_true, preds, zero_division=0), 4),
            "recall":    round(recall_score(y_true, preds, zero_division=0), 4),
            "f1":        round(f1, 4),
            "mcc":       round(mcc, 4),
        })
        if f1 > best_f1:
            best_f1, best_t = f1, round(float(t), 2)
    return {"sweep": results, "best_threshold": best_t, "best_f1": round(best_f1, 4)}


# ── PR curve & calibration ───────────────────────────────────────────────────

def pr_curve_analysis(y_true: np.ndarray, y_prob: np.ndarray) -> dict:
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1s = np.where(
        (precisions[:-1] + recalls[:-1]) > 0,
        2 * precisions[:-1] * recalls[:-1] / (precisions[:-1] + recalls[:-1]), 0.0,
    )
    best = int(np.argmax(f1s))
    return {
        "optimal_threshold": round(float(thresholds[best]), 4),
        "optimal_f1":        round(float(f1s[best]), 4),
        "optimal_precision": round(float(precisions[best]), 4),
        "optimal_recall":    round(float(recalls[best]), 4),
        "n_thresholds":      len(thresholds),
    }


def calibration_analysis(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> dict:
    bins, cal_bins, total_ece = np.linspace(0, 1, n_bins + 1), [], 0.0
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (y_prob >= lo) & (y_prob < hi) if i < n_bins - 1 else (y_prob >= lo) & (y_prob <= hi)
        count = int(mask.sum())
        if count == 0:
            cal_bins.append({"bin": f"{lo:.1f}-{hi:.1f}", "n_samples": 0,
                             "mean_predicted": None, "fraction_positive": None, "gap": None})
            continue
        mean_pred, frac_pos = float(y_prob[mask].mean()), float(y_true[mask].mean())
        gap = abs(mean_pred - frac_pos)
        total_ece += gap * count
        cal_bins.append({"bin": f"{lo:.1f}-{hi:.1f}", "n_samples": count,
                         "mean_predicted": round(mean_pred, 4),
                         "fraction_positive": round(frac_pos, 4), "gap": round(gap, 4)})
    return {"ece": round(total_ece / max(len(y_true), 1), 4), "bins": cal_bins}


# ── Bootstrap confidence intervals ───────────────────────────────────────────

def bootstrap_ci(y_true, y_pred, y_prob, n_resamples=N_BOOTSTRAP, alpha=0.05, seed=42):
    rng, n = np.random.RandomState(seed), len(y_true)
    boot: dict[str, list] = {"accuracy": [], "precision": [], "recall": [],
                             "f1": [], "roc_auc": [], "mcc": []}
    for _ in range(n_resamples):
        idx = rng.randint(0, n, size=n)
        yt, yp, yb = y_true[idx], y_pred[idx], y_prob[idx]
        boot["accuracy"].append(accuracy_score(yt, yp))
        boot["precision"].append(precision_score(yt, yp, zero_division=0))
        boot["recall"].append(recall_score(yt, yp, zero_division=0))
        boot["f1"].append(f1_score(yt, yp, zero_division=0))
        try: boot["mcc"].append(float(matthews_corrcoef(yt, yp)))
        except ValueError: pass
        try: boot["roc_auc"].append(roc_auc_score(yt, yb))
        except ValueError: pass

    ci, lo_q, hi_q = {}, alpha / 2, 1 - alpha / 2
    for metric, vals in boot.items():
        if not vals:
            ci[metric] = {"mean": None, "ci_lower": None, "ci_upper": None}
        else:
            arr = np.array(vals)
            ci[metric] = {"mean": round(float(arr.mean()), 4),
                          "ci_lower": round(float(np.percentile(arr, lo_q * 100)), 4),
                          "ci_upper": round(float(np.percentile(arr, hi_q * 100)), 4)}
    return ci


# ── Token-category error analysis ────────────────────────────────────────────

def token_category_errors(all_details: list[dict]) -> dict:
    cat_error, cat_total = Counter(), Counter()
    for d in all_details:
        cats = {get_category(t) for t in d.get("tokens_head", [])}
        for c in cats:
            cat_total[c] += 1
            if not d["correct"]:
                cat_error[c] += 1
    return {
        cat: {"n_sequences": cat_total[cat], "n_errors": cat_error.get(cat, 0),
              "error_rate": round(cat_error.get(cat, 0) / cat_total[cat], 4) if cat_total[cat] else 0.0}
        for cat in sorted(cat_total)
    }


# ── Inference runner ─────────────────────────────────────────────────────────

def run_inference(model, sequences, max_len, batch_size, pad_id, device,
                  threshold, split_name="test"):
    """Run inference; return (y_true, y_pred, y_prob, details, seqs_per_sec)."""
    all_labels, all_preds, all_probs, all_details = [], [], [], []
    n, t_start = len(sequences), time.perf_counter()

    for start in range(0, n, batch_size):
        end   = min(start + batch_size, n)
        batch = make_batch(sequences, start, end, max_len, pad_id, device)
        with torch.no_grad():
            logits = model(**batch).logits
        probs = torch.softmax(logits, dim=-1).cpu().numpy()
        pos_p = probs[:, 1]
        preds = (pos_p >= threshold).astype(int)

        for i, seq in enumerate(sequences[start:end]):
            true_label, pred_label = int(seq["label"]), int(preds[i])
            prob_mal = float(pos_p[i])
            all_labels.append(true_label)
            all_preds.append(pred_label)
            all_probs.append(prob_mal)
            all_details.append({
                "sequence_id":    seq.get("sequence_id", f"seq_{start + i}"),
                "domain":         seq.get("domain", "unknown"),
                "source":         seq.get("source", "unknown"),
                "attack_type":    seq.get("attack_type", "UNKNOWN"),
                "true_label":     true_label,
                "predicted":      "MALICIOUS" if pred_label == 1 else "BENIGN",
                "predicted_int":  pred_label,
                "prob_malicious": round(prob_mal, 4),
                "correct":        bool(pred_label == true_label),
                "tokens_head":    seq.get("tokens", [])[:20],
            })

        if (start // batch_size) % 20 == 0:
            print(f"\r  [{split_name}] {end}/{n} processed …", end="", flush=True)

    elapsed = time.perf_counter() - t_start
    sps = n / elapsed if elapsed > 0 else 0.0
    print(f"\r  [OK] {n:,} {split_name} sequences evaluated in {elapsed:.1f}s "
          f"({sps:,.0f} seq/s)            \n")
    return np.array(all_labels), np.array(all_preds), np.array(all_probs), all_details, sps


# ── Analyse & print a single split ───────────────────────────────────────────

def analyse_split(y_true, y_pred, y_prob, all_details, threshold, seqs_per_sec,
                  split_name="TEST"):
    """Print full analysis for one split and return the report dict."""
    n = len(y_true)
    n_benign, n_mal = int((y_true == 0).sum()), int((y_true == 1).sum())
    dist = {"n_total": n, "n_benign": n_benign, "n_malicious": n_mal,
            "pct_benign": round(n_benign / n * 100, 2) if n else 0.0,
            "pct_malicious": round(n_mal / n * 100, 2) if n else 0.0}

    # ── Overall ────────────────────────────────────────────────────────────
    overall = _safe_metrics(y_true, y_pred, y_prob)
    print("=" * 70)
    print(f"OVERALL RESULTS — {split_name}")
    print("=" * 70)
    print(f"  Sequences    : {n:,}  "
          f"(BENIGN {n_benign:,} = {dist['pct_benign']:.1f}%  |  "
          f"MALICIOUS {n_mal:,} = {dist['pct_malicious']:.1f}%)")
    for k in ("accuracy", "precision", "recall", "f1", "f1_macro", "f1_weighted", "mcc", "roc_auc"):
        print(f"  {k:<14} : {overall[k]}")
    print(f"  {'throughput':<14} : {seqs_per_sec:,.0f} seq/s\n")

    # ── Confusion matrix ──────────────────────────────────────────────────
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (cm[0, 0], 0, 0, cm[-1, -1])
    print("CONFUSION MATRIX  (row=actual, col=predicted)")
    print(f"  {'':15} {'Pred BENIGN':>12} {'Pred MALICIOUS':>14}")
    print(f"  {'Actual BENIGN':15} {tn:>12,} {fp:>14,}  ({_pct(fp, tn+fp)} FPR)")
    print(f"  {'Actual MALICIOUS':15} {fn:>12,} {tp:>14,}  ({_pct(fn, fn+tp)} FNR)\n")

    # ── Per-source & per-attack breakdowns (reusable helper) ──────────────
    source_metrics = _group_breakdown(all_details, "source")
    print("PER-SOURCE BREAKDOWN")
    print(f"  {'Source':<10} {'N':>6} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'MCC':>7} {'AUC':>7}")
    print("  " + "-" * 60)
    for src, m in source_metrics.items():
        auc_s = f"{m['roc_auc']:.4f}" if m["roc_auc"] is not None else "  N/A "
        mcc_s = f"{m['mcc']:.4f}"     if m["mcc"]     is not None else "  N/A "
        print(f"  {src:<10} {m['n_samples']:>6,} {m['accuracy']:>7.4f} "
              f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f} {mcc_s:>7} {auc_s:>7}")
    print()

    attack_metrics = _group_breakdown(all_details, "attack_type")
    print("PER-ATTACK-TYPE BREAKDOWN")
    print(f"  {'Attack Type':<20} {'N':>6} {'Acc':>7} {'Prec':>7} {'Recall':>7} {'F1':>7} {'MCC':>7}")
    print("  " + "-" * 65)
    for at, m in attack_metrics.items():
        mcc_s = f"{m['mcc']:.4f}" if m["mcc"] is not None else "  N/A "
        print(f"  {at:<20} {m['n_samples']:>6,} {m['accuracy']:>7.4f} "
              f"{m['precision']:>7.4f} {m['recall']:>7.4f} {m['f1']:>7.4f} {mcc_s:>7}")
    print()

    # ── Token-category error analysis ─────────────────────────────────────
    cat_errors = token_category_errors(all_details)
    print("TOKEN-CATEGORY ERROR ANALYSIS  (first 20 tokens of each sequence)")
    print(f"  {'Category':<16} {'N seqs':>8} {'Errors':>8} {'Error %':>9}")
    print("  " + "-" * 44)
    for cat, info in sorted(cat_errors.items(), key=lambda x: -x[1]["error_rate"]):
        print(f"  {cat:<16} {info['n_sequences']:>8,} "
              f"{info['n_errors']:>8,} {info['error_rate'] * 100:>8.1f}%")
    print()

    # ── Top misclassifications ────────────────────────────────────────────
    misclassified = sorted([d for d in all_details if not d["correct"]],
                           key=lambda x: abs(x["prob_malicious"] - 0.5), reverse=True)
    print(f"TOP-10 MISCLASSIFICATIONS  ({len(misclassified):,} total errors)")
    print(f"  {'ID':<20} {'Domain':<8} {'Attack Type':<20} {'True':>9} {'Pred':>10} {'P(mal)':>8}")
    print("  " + "-" * 80)
    for d in misclassified[:10]:
        true = "MALICIOUS" if d["true_label"] == 1 else "BENIGN"
        print(f"  {str(d['sequence_id'])[:18]:<20} {d['domain']:<8} {d['attack_type']:<20} "
              f"{true:>9} {d['predicted']:>10} {d['prob_malicious']:>8.4f}")
        tokens_str = " → ".join(d.get("tokens_head", [])[:10])
        if tokens_str:
            print(f"    tokens: {tokens_str}")
    print()

    # ── Threshold sweep ───────────────────────────────────────────────────
    print("-" * 70 + "\nMULTI-THRESHOLD ANALYSIS\n" + "-" * 70)
    sweep = threshold_sweep(y_true, y_prob)
    print(f"  {'Thresh':>7} {'Acc':>7} {'Prec':>7} {'Recall':>7} {'F1':>7} {'MCC':>7}")
    print("  " + "-" * 46)
    for row in sweep["sweep"]:
        marker = "  ◀ best F1" if row["threshold"] == sweep["best_threshold"] else ""
        print(f"  {row['threshold']:>7.2f} {row['accuracy']:>7.4f} {row['precision']:>7.4f} "
              f"{row['recall']:>7.4f} {row['f1']:>7.4f} {row['mcc']:>7.4f}{marker}")
    print(f"\n  ★ Best threshold = {sweep['best_threshold']}  (F1 = {sweep['best_f1']:.4f})\n")

    # ── PR curve ──────────────────────────────────────────────────────────
    print("-" * 70 + "\nPRECISION-RECALL CURVE — OPTIMAL POINT\n" + "-" * 70)
    pr = pr_curve_analysis(y_true, y_prob)
    for k in ("optimal_threshold", "optimal_precision", "optimal_recall", "optimal_f1"):
        print(f"  {k:<20}: {pr[k]:.4f}")
    print(f"  (searched over {pr['n_thresholds']:,} thresholds)\n")

    # ── Calibration ───────────────────────────────────────────────────────
    print("-" * 70 + "\nCONFIDENCE CALIBRATION\n" + "-" * 70)
    cal = calibration_analysis(y_true, y_prob)
    print(f"  Expected Calibration Error (ECE) : {cal['ece']:.4f}")
    print(f"  {'Bin':<12} {'N':>7} {'Mean Pred':>10} {'Frac Pos':>10} {'Gap':>7}")
    print("  " + "-" * 50)
    for b in cal["bins"]:
        if b["n_samples"] == 0:
            print(f"  {b['bin']:<12} {'—':>7}")
        else:
            print(f"  {b['bin']:<12} {b['n_samples']:>7,} {b['mean_predicted']:>10.4f} "
                  f"{b['fraction_positive']:>10.4f} {b['gap']:>7.4f}")
    print()

    # ── Bootstrap CI ──────────────────────────────────────────────────────
    print("-" * 70 + f"\nBOOTSTRAP 95% CONFIDENCE INTERVALS  (n={N_BOOTSTRAP})\n" + "-" * 70)
    ci = bootstrap_ci(y_true, y_pred, y_prob)
    for metric, vals in ci.items():
        if vals["mean"] is None:
            print(f"  {metric:<12} : N/A (single-class resamples)")
        else:
            print(f"  {metric:<12} : {vals['mean']:.4f}  [{vals['ci_lower']:.4f} – {vals['ci_upper']:.4f}]")
    print()

    return {
        "class_distribution": dist, "overall": overall,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "per_source": source_metrics, "per_attack_type": attack_metrics,
        "token_category_errors": cat_errors, "n_misclassified": len(misclassified),
        "threshold_sweep": sweep, "pr_curve": pr, "calibration": cal,
        "bootstrap_ci": ci,
        "runtime": {"seqs_per_sec": round(seqs_per_sec, 1), "n_sequences": n},
    }


# ── Main evaluation ──────────────────────────────────────────────────────────

def evaluate(model_dir: Path, max_len: int, batch_size: int, threshold: float,
             also_val: bool = False) -> None:
    print("=" * 70)
    print("EVALUATING DISTILBERT ATTACK CLASSIFIER")
    print(f"  Model: {model_dir}  |  Threshold: {threshold}  |  "
          f"Vocab: {VOCAB_SIZE}  |  MaxLen: {max_len}  |  Batch: {batch_size}")
    print("=" * 70 + "\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    pad_id = TOKEN_TO_ID.get("PAD", 0)

    # ── Load model ─────────────────────────────────────────────────────────
    print("[*] Loading model …")
    if not model_dir.exists():
        print(f"[ERROR] Model not found at {model_dir}"); sys.exit(1)
    try:
        model = DistilBertForSequenceClassification.from_pretrained(str(model_dir))
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}"); sys.exit(1)
    model.to(device).eval()
    print(f"  [OK] Model loaded on {device}\n")

    # ── Evaluate a split ──────────────────────────────────────────────────
    def _eval_split(split_file: Path, split_name: str) -> dict | None:
        print(f"[*] Loading {split_name} sequences …")
        if not split_file.exists():
            print(f"  [SKIP] {split_file} not found\n"); return None
        with open(split_file, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        sequences = raw.get("sequences", raw)
        print(f"  [OK] {len(sequences):,} {split_name} sequences loaded\n")

        print(f"[*] Running inference on {split_name} …")
        y_true, y_pred, y_prob, details, sps = run_inference(
            model, sequences, max_len, batch_size, pad_id, device, threshold, split_name)
        report = analyse_split(y_true, y_pred, y_prob, details, threshold, sps,
                               split_name.upper())
        report["predictions"] = [
            {"sequence_id": d["sequence_id"], "source": d["source"],
             "domain": d["domain"], "attack_type": d["attack_type"],
             "predicted": d["attack_type"] if d["predicted"] == "MALICIOUS" else "BENIGN",
             "predicted_binary": d["predicted_int"],
             "true_label": d["true_label"], "prob_malicious": d["prob_malicious"]}
            for d in details
        ]
        return report

    # ── Run ────────────────────────────────────────────────────────────────
    test_report = _eval_split(PROCESSED_DIR / "test_sequences.json", "test")
    if test_report is None:
        print("[ERROR] Test data not found."); sys.exit(1)

    val_report = _eval_split(PROCESSED_DIR / "validation_sequences.json", "validation") if also_val else None

    # ── Save report ────────────────────────────────────────────────────────
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    full_report = {
        "model": "DistilBERT Attack Classifier", "model_dir": str(model_dir),
        "vocab_size": VOCAB_SIZE, "threshold": threshold,
        "max_length": max_len, "batch_size": batch_size,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "test": test_report, "predictions": test_report["predictions"],
    }
    if val_report is not None:
        full_report["validation"] = val_report

    report_path = REPORTS_DIR / "distilbert_evaluation.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(_clean(full_report), fh, indent=2)
    print(f"\n[OK] Evaluation report saved → {report_path}")
    print("=" * 70)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate DistilBERT attack classifier")
    p.add_argument("--model-dir",  type=str,   default=str(MODEL_DIR))
    p.add_argument("--max-len",    type=int,   default=DEFAULT_MAX_LEN)
    p.add_argument("--batch-size", type=int,   default=DEFAULT_BATCH)
    p.add_argument("--threshold",  type=float, default=DEFAULT_THRESHOLD)
    p.add_argument("--also-val",   action="store_true")
    args = p.parse_args()
    evaluate(Path(args.model_dir), args.max_len, args.batch_size,
             args.threshold, args.also_val)


if __name__ == "__main__":
    main()
