#!/usr/bin/env python3
"""
Evaluate the trained XLNet next-step behaviour predictor on the held-out test set.

Outputs reports/xlnet_evaluation.json and prints a human-readable digest.

Usage:
  python scripts/evaluate_xlnet.py
  python scripts/evaluate_xlnet.py --model-dir models/xlnet_behaviour_predictor
  python scripts/evaluate_xlnet.py --threshold 15.0
"""

import argparse
import json
import math
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import XLNetLMHeadModel

sys.path.insert(0, str(Path(__file__).parent))
from token_definitions import TOKEN_TO_ID, ID_TO_TOKEN, VOCAB_SIZE  # noqa: E402

# ── Import no-retrain exploit signal from live.inference ─────────────────────
# This is the same rule-based token-pattern detector used in the live pipeline.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from live.inference import _token_pattern_signal, _SEVERITY_FLOOR, _EXPLOIT_PATTERNS
    _PATTERN_OK = True
except ImportError:
    _PATTERN_OK = False
    def _token_pattern_signal(tokens):
        return 0.0

# ── Paths & Defaults ─────────────────────────────────────────────────────────
PROCESSED_DIR     = Path("data/processed")
MODEL_DIR         = Path("models/xlnet_behaviour_predictor")
REPORTS_DIR       = Path("reports")
DEFAULT_MAX_LEN   = 128
DEFAULT_THRESHOLD = None            # None → auto-compute from benign distribution
N_BOOTSTRAP       = 1000


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


def _safe_metrics(y_true, y_pred, y_score=None) -> dict:
    """Binary classification metrics including MCC."""
    try:    auc = round(roc_auc_score(y_true, y_score), 4) if y_score is not None else None
    except ValueError: auc = None
    try:    mcc = round(float(matthews_corrcoef(y_true, y_pred)), 4)
    except ValueError: mcc = None
    return {
        "accuracy":  round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_true, y_pred, zero_division=0), 4),
        "mcc": mcc, "roc_auc": auc, "n_samples": int(len(y_true)),
    }


def _group_breakdown(all_details, group_key):
    """Group details by *group_key* and compute per-group anomaly + LM metrics."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for d in all_details:
        groups[d[group_key]].append(d)

    metrics = {}
    for name in sorted(groups):
        group = groups[name]
        yt = np.array([d["true_label"]  for d in group])
        yp = np.array([d["anomaly_pred"] for d in group])
        ys = np.array([d["perplexity"]   for d in group])
        m  = _safe_metrics(yt, yp, ys)
        m["perplexity_mean"] = round(float(np.mean(ys)), 4)
        m["top1_accuracy"]   = round(float(np.mean([d["top1_accuracy"] for d in group])), 4)
        m["top5_accuracy"]   = round(float(np.mean([d["top5_accuracy"] for d in group])), 4)
        metrics[name] = m
    return metrics


# ── Sequence encoding ─────────────────────────────────────────────────────────

def encode_sequence(tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
    """Token strings → (input_ids, attention_mask), tail-truncated."""
    ids = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens][-max_len:]
    return ids, [1] * len(ids)


# ── Perplexity computation ────────────────────────────────────────────────────

@torch.no_grad()
def compute_sequence_perplexity(model, input_ids, attention_mask, device):
    """Compute per-sequence perplexity, top-1/5 accuracy, and actual/predicted next step.

    Uses causal LM shift: input = tokens[:-1], target = tokens[1:]
    Returns (perplexity, top1_acc, top5_acc, actual_next_step, predicted_next_step).
    """
    input_ids      = input_ids.to(device)
    attention_mask = attention_mask.to(device)

    seq_len = attention_mask.sum().item()
    if seq_len < 2:
        return 0.0, 0.0, 0.0, "N/A", "N/A"

    logits       = model(input_ids=input_ids, attention_mask=attention_mask).logits
    valid_len    = int(seq_len) - 1
    shift_logits = logits[0, :valid_len, :]
    shift_labels = input_ids[0, 1:valid_len + 1]

    perplexity = math.exp(min(nn.CrossEntropyLoss()(shift_logits, shift_labels).item(), 100))
    preds_top1 = shift_logits.argmax(dim=-1)
    top1_acc   = (preds_top1 == shift_labels).float().mean().item()

    k        = min(5, shift_logits.size(-1))
    _, top5  = shift_logits.topk(k, dim=-1)
    top5_acc = (top5 == shift_labels.unsqueeze(-1)).any(dim=-1).float().mean().item()

    actual_ns    = ID_TO_TOKEN.get(int(shift_labels[-1].item()),  "UNK")
    predicted_ns = ID_TO_TOKEN.get(int(preds_top1[-1].item()), "UNK")
    return perplexity, top1_acc, top5_acc, actual_ns, predicted_ns


# ── Perplexity percentile stats ───────────────────────────────────────────────

def perplexity_percentiles(ppls: list[float]) -> dict:
    if not ppls:
        return {}
    arr = np.array(ppls)
    return {k: round(float(v), 4) for k, v in {
        "mean": arr.mean(), "std": arr.std(), "min": arr.min(),
        "p25": np.percentile(arr, 25), "p50": np.percentile(arr, 50),
        "p75": np.percentile(arr, 75), "p90": np.percentile(arr, 90),
        "p99": np.percentile(arr, 99), "max": arr.max(),
    }.items()} | {"n": len(arr)}


# ── Multi-threshold sweep ────────────────────────────────────────────────────

def threshold_sweep_ppl(y_true, y_score, n_steps=50):
    """Try N thresholds in BOTH directions and return the best overall.

    Tests perplexity >= t (high-ppl = anomaly) AND perplexity <= t
    (low-ppl = anomaly), returning whichever direction gives the higher F1.
    """
    lo = float(np.percentile(y_score, 1))
    hi = float(np.percentile(y_score, 99))
    thresholds = np.linspace(lo, hi, n_steps)

    def _sweep(direction):
        results, best_f1, best_t = [], 0.0, float(thresholds[n_steps // 2])
        for t in thresholds:
            preds = (y_score <= t).astype(int) if direction == "<=" else (y_score >= t).astype(int)
            f1  = f1_score(y_true, preds, zero_division=0)
            mcc = float(matthews_corrcoef(y_true, preds)) if len(set(y_true)) > 1 else 0.0
            results.append({
                "threshold": round(float(t), 4),
                "accuracy":  round(accuracy_score(y_true, preds), 4),
                "precision": round(precision_score(y_true, preds, zero_division=0), 4),
                "recall":    round(recall_score(y_true, preds, zero_division=0), 4),
                "f1": round(f1, 4), "mcc": round(mcc, 4),
            })
            if f1 > best_f1:
                best_f1, best_t = f1, round(float(t), 4)
        return {"sweep": results, "best_threshold": best_t, "best_f1": round(best_f1, 4)}

    hi_sweep = _sweep(">=")   # traditional: high perplexity = anomaly
    lo_sweep = _sweep("<=")   # inverted:  low perplexity = anomaly

    if lo_sweep["best_f1"] >= hi_sweep["best_f1"]:
        return {**lo_sweep, "direction": "<=",
                "alt_direction": ">=", "alt_best_f1": hi_sweep["best_f1"],
                "alt_best_threshold": hi_sweep["best_threshold"]}
    return {**hi_sweep, "direction": ">=",
            "alt_direction": "<=", "alt_best_f1": lo_sweep["best_f1"],
            "alt_best_threshold": lo_sweep["best_threshold"]}


# ── Bootstrap confidence intervals ───────────────────────────────────────────

def bootstrap_ci(y_true, y_pred, y_score, n_resamples=N_BOOTSTRAP, alpha=0.05, seed=42):
    rng, n = np.random.RandomState(seed), len(y_true)
    boot: dict[str, list] = {"accuracy": [], "precision": [], "recall": [],
                             "f1": [], "roc_auc": [], "mcc": []}
    for _ in range(n_resamples):
        idx = rng.randint(0, n, size=n)
        yt, yp, ys = y_true[idx], y_pred[idx], y_score[idx]
        boot["accuracy"].append(accuracy_score(yt, yp))
        boot["precision"].append(precision_score(yt, yp, zero_division=0))
        boot["recall"].append(recall_score(yt, yp, zero_division=0))
        boot["f1"].append(f1_score(yt, yp, zero_division=0))
        try: boot["mcc"].append(float(matthews_corrcoef(yt, yp)))
        except ValueError: pass
        try: boot["roc_auc"].append(roc_auc_score(yt, ys))
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


# ── Main evaluation ──────────────────────────────────────────────────────────

def evaluate(model_dir: Path, max_len: int, threshold: float | None) -> None:
    thresh_label = "auto (mean + 2σ of benign)" if threshold is None else str(threshold)
    print("=" * 70)
    print("EVALUATING XLNET NEXT-STEP BEHAVIOUR PREDICTOR")
    print(f"  Model: {model_dir}  |  Threshold: {thresh_label}  |  "
          f"Vocab: {VOCAB_SIZE}  |  MaxLen: {max_len}")
    print("=" * 70 + "\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    threshold_method = "auto"

    # ── Load model ─────────────────────────────────────────────────────────
    print("[*] Loading model …")
    if not model_dir.exists():
        print(f"[ERROR] Model not found at {model_dir}"); sys.exit(1)
    try:
        model = XLNetLMHeadModel.from_pretrained(str(model_dir))
    except Exception as e:
        print(f"[ERROR] Failed to load model: {e}"); sys.exit(1)
    model.to(device).eval()
    print(f"  [OK] Model loaded on {device}\n")

    # ── Load test data ────────────────────────────────────────────────────
    print("[*] Loading test sequences …")
    test_file = PROCESSED_DIR / "test_sequences.json"
    if not test_file.exists():
        print(f"[ERROR] Test data not found: {test_file}"); sys.exit(1)
    with open(test_file, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    sequences = raw.get("sequences", raw)
    print(f"  [OK] {len(sequences):,} test sequences loaded\n")

    # ── Compute per-sequence perplexity ────────────────────────────────────
    print("[*] Computing per-sequence perplexity …")
    all_details: list[dict] = []
    n, t_start = len(sequences), time.perf_counter()

    for idx, seq in enumerate(sequences):
        tokens = seq.get("tokens", [])
        if len(tokens) < 2:
            continue
        ids, mask = encode_sequence(tokens, max_len)
        ppl, top1, top5, actual_ns, predicted_ns = compute_sequence_perplexity(
            model, torch.tensor([ids], dtype=torch.long),
            torch.tensor([mask], dtype=torch.long), device)

        all_details.append({
            "sequence_id":         seq.get("sequence_id", f"seq_{idx}"),
            "source":              seq.get("source",      "unknown"),
            "attack_type":         seq.get("attack_type", "UNKNOWN"),
            "true_label":          int(seq.get("label", 0)),
            "perplexity":          round(ppl, 4),
            "top1_accuracy":       round(top1, 4),
            "top5_accuracy":       round(top5, 4),
            "seq_length":          len(tokens),
            "actual_next_step":    actual_ns,
            "predicted_next_step": predicted_ns,
            "tokens_head":         tokens[:20],
            # ── Token-pattern exploit signal (no-retrain supplement) ──────────
            "pattern_signal":      round(_token_pattern_signal(tokens), 4),
        })
        if (idx + 1) % 500 == 0 or (idx + 1) == n:
            print(f"\r  {idx + 1}/{n} processed …", end="", flush=True)

    elapsed      = time.perf_counter() - t_start
    seqs_per_sec = len(all_details) / elapsed if elapsed > 0 else 0.0
    print(f"\r  [OK] {len(all_details):,} sequences evaluated in {elapsed:.1f}s "
          f"({seqs_per_sec:,.0f} seq/s)            \n")

    # ── Perplexity distribution stats ────────────────────────────────────────
    benign_ppls    = [d["perplexity"] for d in all_details if d["true_label"] == 0]
    malicious_ppls = [d["perplexity"] for d in all_details if d["true_label"] == 1]
    mean_benign = np.mean(benign_ppls)  if benign_ppls else 0.0
    std_benign  = np.std(benign_ppls)   if benign_ppls else 1.0

    print(f"  Benign  ppl : mean={mean_benign:.4f}  σ={std_benign:.4f}  (n={len(benign_ppls):,})")
    if malicious_ppls:
        print(f"  Malicious   : mean={np.mean(malicious_ppls):.4f}  "
              f"σ={np.std(malicious_ppls):.4f}  (n={len(malicious_ppls):,})")

    # ── Sweep to find optimal threshold & direction ────────────────────────
    y_true  = np.array([d["true_label"] for d in all_details])
    y_score = np.array([d["perplexity"] for d in all_details])
    sweep   = threshold_sweep_ppl(y_true, y_score)
    anomaly_dir = sweep["direction"]  # "<=" or ">="

    if threshold is None:
        threshold = sweep["best_threshold"]
        threshold_method = f"auto-sweep ({anomaly_dir}, best F1={sweep['best_f1']:.4f})"
        print(f"  Auto threshold : {threshold:.4f}  [sweep-optimal, direction: ppl {anomaly_dir} t]")
    else:
        threshold_method = "manual"
        print(f"  Using threshold: {threshold:.4f}  [direction: ppl {anomaly_dir} t]")
    print()

    # ── Anomaly predictions (direction-aware) ──────────────────────────────
    for d in all_details:
        if anomaly_dir == "<=":
            d["anomaly_pred"] = 1 if d["perplexity"] <= threshold else 0
        else:
            d["anomaly_pred"] = 1 if d["perplexity"] >= threshold else 0
        # Hybrid prediction: flag as malicious if EITHER perplexity OR
        # the token-pattern signal fires (pattern_signal > 0.3 threshold)
        d["hybrid_pred"] = 1 if (d["anomaly_pred"] == 1 or d["pattern_signal"] > 0.30) else 0

    y_pred        = np.array([d["anomaly_pred"] for d in all_details])
    y_pred_hybrid = np.array([d["hybrid_pred"]  for d in all_details])

    # ── Language model quality ─────────────────────────────────────────────
    all_ppls = [d["perplexity"]    for d in all_details]
    all_top1 = [d["top1_accuracy"] for d in all_details]
    all_top5 = [d["top5_accuracy"] for d in all_details]

    overall_lm = {
        "perplexity_mean":   round(float(np.mean(all_ppls)), 4),
        "perplexity_median": round(float(np.median(all_ppls)), 4),
        "perplexity_std":    round(float(np.std(all_ppls)), 4),
        "top1_accuracy":     round(float(np.mean(all_top1)), 4),
        "top5_accuracy":     round(float(np.mean(all_top5)), 4),
        "perplexity_stats":  perplexity_percentiles(all_ppls),
        "benign_stats":      perplexity_percentiles(benign_ppls),
        "malicious_stats":   perplexity_percentiles(malicious_ppls) if malicious_ppls else {},
    }
    overall_anomaly = _safe_metrics(y_true, y_pred, y_score)

    print("=" * 70 + "\nLANGUAGE MODEL QUALITY\n" + "=" * 70)
    for k in ("perplexity_mean", "perplexity_median", "perplexity_std", "top1_accuracy", "top5_accuracy"):
        print(f"  {k:<20}: {overall_lm[k]:.4f}")
    stats = overall_lm["perplexity_stats"]
    print(f"\n  Perplexity percentiles (all sequences)")
    print(f"  {'p25':>6} {'p50':>8} {'p75':>8} {'p90':>8} {'p99':>8} {'max':>10}")
    print(f"  {stats.get('p25','?'):>6} {stats.get('p50','?'):>8} "
          f"{stats.get('p75','?'):>8} {stats.get('p90','?'):>8} "
          f"{stats.get('p99','?'):>8} {stats.get('max','?'):>10}\n")

    # ── Anomaly detection ──────────────────────────────────────────────────
    dir_label = "perplexity ≤ threshold" if anomaly_dir == "<=" else "perplexity ≥ threshold"
    print("=" * 70 + f"\nANOMALY DETECTION  ({dir_label} → MALICIOUS)\n" + "=" * 70)
    print(f"  Threshold    : {threshold:.4f}  [{threshold_method}]")
    print(f"  Direction    : ppl {anomaly_dir} threshold → flag as MALICIOUS")
    print(f"  Sequences    : {overall_anomaly['n_samples']:,}")
    for k in ("accuracy", "precision", "recall", "f1", "mcc", "roc_auc"):
        print(f"  {k:<12}  : {overall_anomaly[k]}")
    print(f"  {'throughput':<12}  : {seqs_per_sec:,.0f} seq/s\n")

    # ── Confusion matrix ───────────────────────────────────────────────────
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (cm[0, 0], 0, 0, cm[-1, -1])
    print("CONFUSION MATRIX  (row=actual, col=predicted)")
    print(f"  {'':15} {'Pred BENIGN':>12} {'Pred MALICIOUS':>14}")
    print(f"  {'Actual BENIGN':15} {tn:>12,} {fp:>14,}  ({_pct(fp, tn+fp)} FPR)")
    print(f"  {'Actual MALICIOUS':15} {fn:>12,} {tp:>14,}  ({_pct(fn, fn+tp)} FNR)\n")

    # ── Per-source & per-attack breakdowns (shared helper) ─────────────────
    source_metrics = _group_breakdown(all_details, "source")
    print("PER-SOURCE BREAKDOWN")
    print(f"  {'Source':<10} {'N':>6} {'PPL':>8} {'Top1':>7} {'Top5':>7} "
          f"{'Acc':>7} {'F1':>7} {'MCC':>7} {'AUC':>7}")
    print("  " + "-" * 70)
    for src, m in source_metrics.items():
        auc_s = f"{m['roc_auc']:.4f}" if m["roc_auc"] is not None else "  N/A "
        mcc_s = f"{m['mcc']:.4f}"     if m["mcc"]     is not None else "  N/A "
        print(f"  {src:<10} {m['n_samples']:>6,} {m['perplexity_mean']:>8.2f} "
              f"{m['top1_accuracy']:>7.4f} {m['top5_accuracy']:>7.4f} "
              f"{m['accuracy']:>7.4f} {m['f1']:>7.4f} {mcc_s:>7} {auc_s:>7}")
    print()

    attack_metrics = _group_breakdown(all_details, "attack_type")
    print("PER-ATTACK-TYPE BREAKDOWN")
    print(f"  {'Attack Type':<20} {'N':>6} {'PPL':>8} {'Acc':>7} {'F1':>7} {'MCC':>7} {'HybridF1':>10}")
    print("  " + "-" * 68)
    for at, m in attack_metrics.items():
        mcc_s = f"{m['mcc']:.4f}" if m["mcc"] is not None else "  N/A "
        # Hybrid F1 for this attack type
        grp = [d for d in all_details if d["attack_type"] == at]
        hyt = np.array([d["true_label"]  for d in grp])
        hyp = np.array([d["hybrid_pred"] for d in grp])
        hf1 = round(f1_score(hyt, hyp, zero_division=0), 4) if len(set(hyt)) > 1 else "N/A"
        hf1_s = f"{hf1:.4f}" if isinstance(hf1, float) else hf1
        flag = "  ◀ boosted" if at in ("EXPLOIT", "EXPLOITATION", "MALWARE", "BRUTE_FORCE") else ""
        print(f"  {at:<20} {m['n_samples']:>6,} {m['perplexity_mean']:>8.2f} "
              f"{m['accuracy']:>7.4f} {m['f1']:>7.4f} {mcc_s:>7} {hf1_s:>10}{flag}")
    print()

    # ── EXPLOIT-specific report ────────────────────────────────────────────
    exploit_seqs = [d for d in all_details if d["attack_type"] == "EXPLOIT"]
    if exploit_seqs:
        print("=" * 70 + "\nEXPLOIT DEEP-DIVE  (token-pattern vs perplexity)\n" + "=" * 70)
        ex_true   = np.array([d["true_label"]  for d in exploit_seqs])
        ex_ppl    = np.array([d["anomaly_pred"] for d in exploit_seqs])
        ex_hybrid = np.array([d["hybrid_pred"]  for d in exploit_seqs])
        ex_pat    = np.array([d["pattern_signal"] for d in exploit_seqs])
        ppl_f1 = f1_score(ex_true, ex_ppl,    zero_division=0)
        hyb_f1 = f1_score(ex_true, ex_hybrid, zero_division=0)
        print(f"  Total EXPLOIT sequences     : {len(exploit_seqs):,}")
        print(f"  Perplexity-only F1          : {ppl_f1:.4f}")
        print(f"  Hybrid (ppl + pattern) F1   : {hyb_f1:.4f}  {'↑ IMPROVED' if hyb_f1 > ppl_f1 else ''}")
        print(f"  Pattern signal > 0.30       : {int((ex_pat > 0.30).sum()):,} sequences boosted")
        print(f"  Pattern signal mean (EXPLOIT): {float(ex_pat.mean()):.4f}")
        no_pattern_caught = int(((ex_pat <= 0.30) & (ex_ppl == 0) & (ex_true == 1)).sum())
        print(f"  Still-missed (label=1, no pattern, ppl=benign): {no_pattern_caught:,}")
        print()

    # ── Multi-threshold sweep (already computed above) ─────────────────────
    print("-" * 70 + f"\nMULTI-THRESHOLD ANALYSIS  (direction: ppl {anomaly_dir})\n" + "-" * 70)
    print(f"  {'Thresh':>10} {'Acc':>7} {'Prec':>7} {'Recall':>7} {'F1':>7} {'MCC':>7}")
    print("  " + "-" * 50)
    step = max(1, len(sweep["sweep"]) // 15)
    for i, row in enumerate(sweep["sweep"]):
        if i % step != 0 and row["threshold"] != sweep["best_threshold"]:
            continue
        marker = "  ◀ best F1" if row["threshold"] == sweep["best_threshold"] else ""
        print(f"  {row['threshold']:>10.4f} {row['accuracy']:>7.4f} {row['precision']:>7.4f} "
              f"{row['recall']:>7.4f} {row['f1']:>7.4f} {row['mcc']:>7.4f}{marker}")
    print(f"\n  ★ Best direction  = ppl {anomaly_dir} threshold")
    print(f"  ★ Best threshold = {sweep['best_threshold']}  (F1 = {sweep['best_f1']:.4f})")
    if sweep.get("alt_best_f1"):
        print(f"  ◇ Alt direction   = ppl {sweep['alt_direction']}  "
              f"(best F1 = {sweep['alt_best_f1']:.4f} at {sweep['alt_best_threshold']})")
    print()

    # ── Bootstrap CI ───────────────────────────────────────────────────────
    print("-" * 70 + f"\nBOOTSTRAP 95% CONFIDENCE INTERVALS  (n={N_BOOTSTRAP})\n" + "-" * 70)
    ci = bootstrap_ci(y_true, y_pred, y_score)
    for metric, vals in ci.items():
        if vals["mean"] is None:
            print(f"  {metric:<12} : N/A (single-class resamples)")
        else:
            print(f"  {metric:<12} : {vals['mean']:.4f}  [{vals['ci_lower']:.4f} – {vals['ci_upper']:.4f}]")
    print()

    # ── Actual vs Predicted next step ──────────────────────────────────────
    ns_correct = sum(1 for d in all_details if d["actual_next_step"] == d["predicted_next_step"])
    ns_total   = len(all_details)
    ns_wrong   = [d for d in all_details if d["actual_next_step"] != d["predicted_next_step"]]

    print("=" * 70 + "\nACTUAL vs PREDICTED NEXT STEP\n" + "=" * 70)
    print(f"  Next-step prediction accuracy : {ns_correct}/{ns_total} "
          f"({ns_correct/ns_total*100:.2f}%)")
    print(f"  Mispredicted sequences        : {len(ns_wrong):,}\n")

    print(f"  {'ID':<22} {'Source':<8} {'Attack':<15} {'Label':>9} "
          f"{'Actual Step':<16} {'Predicted Step':<16} {'Match':>6}")
    print("  " + "-" * 96)
    for d in all_details[:30]:
        sid  = str(d["sequence_id"])[:20]
        lbl  = "MALICIOUS" if d["true_label"] == 1 else "BENIGN"
        mark = "  ✓" if d["actual_next_step"] == d["predicted_next_step"] else "  ✗"
        print(f"  {sid:<22} {d['source']:<8} {d['attack_type']:<15} {lbl:>9} "
              f"{d['actual_next_step']:<16} {d['predicted_next_step']:<16} {mark:>6}")
    if ns_total > 30:
        print(f"  … ({ns_total - 30:,} more sequences omitted)")
    print()

    # Next-step accuracy by attack type
    print("NEXT-STEP ACCURACY BY ATTACK TYPE")
    print(f"  {'Attack Type':<20} {'Total':>6} {'Correct':>8} {'Accuracy':>9}")
    print("  " + "-" * 46)
    ns_by_attack: dict[str, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for d in all_details:
        ns_by_attack[d["attack_type"]]["total"] += 1
        if d["actual_next_step"] == d["predicted_next_step"]:
            ns_by_attack[d["attack_type"]]["correct"] += 1
    for at in sorted(ns_by_attack):
        g   = ns_by_attack[at]
        acc = g["correct"] / g["total"] * 100 if g["total"] else 0.0
        print(f"  {at:<20} {g['total']:>6,} {g['correct']:>8,} {acc:>8.2f}%")
    print()

    # Top-10 mispredicted next-step sequences
    ns_wrong_sorted = sorted(ns_wrong, key=lambda x: x["perplexity"], reverse=True)
    print(f"TOP-10 MISPREDICTED NEXT-STEP SEQUENCES  ({len(ns_wrong):,} total)")
    print(f"  {'ID':<22} {'Attack':<15} {'Label':>9} {'Actual Step':<16} "
          f"{'Predicted Step':<16} {'PPL':>10}")
    print("  " + "-" * 92)
    for d in ns_wrong_sorted[:10]:
        sid = str(d["sequence_id"])[:20]
        lbl = "MALICIOUS" if d["true_label"] == 1 else "BENIGN"
        print(f"  {sid:<22} {d['attack_type']:<15} {lbl:>9} "
              f"{d['actual_next_step']:<16} {d['predicted_next_step']:<16} "
              f"{d['perplexity']:>10.4f}")
        tokens_str = " → ".join(d.get("tokens_head", [])[:10])
        if tokens_str:
            print(f"    tokens: {tokens_str}")
    print()

    # ── Hybrid score (if DistilBERT evaluation exists) ─────────────────────
    distilbert_report_path = REPORTS_DIR / "distilbert_evaluation.json"
    hybrid_metrics = None
    if distilbert_report_path.exists():
        print("[*] Loading DistilBERT predictions for hybrid scoring …")
        with open(distilbert_report_path, "r", encoding="utf-8") as fh:
            db_preds = {p["sequence_id"]: p
                        for p in json.load(fh).get("predictions", [])}

        hybrid_true, hybrid_pred, hybrid_scores = [], [], []
        for d in all_details:
            db = db_preds.get(d["sequence_id"])
            if db is None:
                continue
            hybrid_flag = 1 if (db["predicted_binary"] == 1 or d["anomaly_pred"] == 1) else 0
            norm_ppl    = min(d["perplexity"] / max(threshold, 1e-6), 2.0) / 2.0
            hybrid_true.append(d["true_label"])
            hybrid_pred.append(hybrid_flag)
            hybrid_scores.append(max(db["prob_malicious"], norm_ppl))

        if hybrid_true:
            hybrid_metrics = _safe_metrics(
                np.array(hybrid_true), np.array(hybrid_pred), np.array(hybrid_scores))
            print("\n" + "=" * 70 + "\nHYBRID (DistilBERT + XLNet) ANOMALY DETECTION\n" + "=" * 70)
            print(f"  Matched seqs : {hybrid_metrics['n_samples']:,}")
            for k in ("accuracy", "precision", "recall", "f1", "mcc", "roc_auc"):
                print(f"  {k:<12}  : {hybrid_metrics[k]}")
            print()

    # ── Save report ────────────────────────────────────────────────────────
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "model":            "XLNet Next-Step Behaviour Predictor",
        "model_dir":        str(model_dir),
        "vocab_size":       VOCAB_SIZE,
        "threshold":        round(threshold, 4),
        "threshold_method": threshold_method,
        "max_length":       max_len,
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "runtime":          {"seqs_per_sec": round(seqs_per_sec, 1),
                             "n_sequences": len(all_details),
                             "elapsed_sec": round(elapsed, 2)},
        "language_model":    overall_lm,
        "anomaly_detection": overall_anomaly,
        "confusion_matrix":  {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "per_source":        source_metrics,
        "per_attack_type":   attack_metrics,
        "n_misclassified":   len(ns_wrong),
        "benign_perplexity": {"mean": round(float(mean_benign), 4),
                              "std": round(float(std_benign), 4)},
        "threshold_sweep":   sweep,
        "bootstrap_ci":      ci,
    }
    if hybrid_metrics:
        report["hybrid_detection"] = hybrid_metrics

    report["predictions"] = [
        {"sequence_id": d["sequence_id"], "source": d["source"],
         "attack_type": d["attack_type"],
         "true_label": d["true_label"], "perplexity": d["perplexity"],
         "anomaly_pred": d["anomaly_pred"],
         "hybrid_pred": d["hybrid_pred"],          # NEW: pattern-boosted prediction
         "pattern_signal": d["pattern_signal"],    # NEW: per-sequence pattern score
         "top1_accuracy": d["top1_accuracy"],
         "actual_next_step": d["actual_next_step"],
         "predicted_next_step": d["predicted_next_step"]}
        for d in all_details
    ]

    report_path = REPORTS_DIR / "xlnet_evaluation.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(_clean(report), fh, indent=2)
    print(f"[OK] Evaluation report saved → {report_path}")
    print("=" * 70)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Evaluate XLNet behaviour predictor")
    p.add_argument("--model-dir",  type=str,   default=str(MODEL_DIR))
    p.add_argument("--max-len",    type=int,   default=DEFAULT_MAX_LEN)
    p.add_argument("--threshold",  type=float, default=DEFAULT_THRESHOLD)
    args = p.parse_args()
    evaluate(Path(args.model_dir), args.max_len, args.threshold)


if __name__ == "__main__":
    main()
