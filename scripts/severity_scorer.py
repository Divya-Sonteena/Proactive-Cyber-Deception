#!/usr/bin/env python3
"""
Severity Scorer — assigns risk levels to sequences using both trained models
(DistilBERT attack classifier + XLNet behaviour predictor).

Scoring:
  anomaly_score = 1 - norm_ppl  (low perplexity = predictable = suspicious)
  combined = token_sev_scaled * 0.25 + attack_prob * 1.50 + anomaly_score * 1.25
  Risk:  < 0.5 → LOW  |  < 1.2 → MEDIUM  |  < 2.0 → HIGH  |  ≥ 2.0 → CRITICAL

Usage:
  python scripts/severity_scorer.py
  python scripts/severity_scorer.py --input data/processed/test_sequences.json
"""

import argparse
import json
import math
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from transformers import DistilBertForSequenceClassification, XLNetLMHeadModel

sys.path.insert(0, str(Path(__file__).parent))
from token_definitions import TOKEN_TO_ID, VOCAB_SIZE, get_severity  # noqa: E402

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_INPUT  = Path("data/processed/test_sequences.json")
DEFAULT_OUTPUT = Path("reports/severity_report.json")
DISTILBERT_DIR = Path("models/distilbert_attack_classifier")
XLNET_DIR      = Path("models/xlnet_behaviour_predictor")
MAX_LEN        = 128
SEVERITY_MAP   = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0, "UNKNOWN": 1.0}
RISK_THRESHOLDS = [(2.0, "CRITICAL"), (1.2, "HIGH"), (0.5, "MEDIUM"), (0.0, "LOW")]


# ── Utilities ─────────────────────────────────────────────────────────────────

def encode(tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
    """Token strings → (input_ids, attention_mask), tail-truncated."""
    ids = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens][-max_len:]
    return ids, [1] * len(ids)


def risk_label(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def _clean(obj):
    """Recursively sanitise NaN/Inf for valid JSON output."""
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


# ── DistilBERT inference (batched) ────────────────────────────────────────────

def distilbert_predict(model, sequences, device, batch_size=64):
    """Return list of {sequence_id, attack_prob, predicted_binary} dicts."""
    pad_id, results, n = TOKEN_TO_ID.get("PAD", 0), [], len(sequences)

    for start in range(0, n, batch_size):
        chunk     = sequences[start : start + batch_size]
        batch_ids, batch_msk = [], []

        for seq in chunk:
            ids, msk = encode(seq["tokens"], MAX_LEN)
            batch_ids.append(ids)
            batch_msk.append(msk)

        # Pad to longest in batch
        max_b = max(len(x) for x in batch_ids)
        for i in range(len(batch_ids)):
            diff = max_b - len(batch_ids[i])
            batch_ids[i] += [pad_id] * diff
            batch_msk[i] += [0]      * diff

        with torch.no_grad():
            logits = model(input_ids=torch.tensor(batch_ids, dtype=torch.long, device=device),
                           attention_mask=torch.tensor(batch_msk, dtype=torch.long, device=device)).logits
            probs = torch.softmax(logits, dim=-1).cpu().numpy()

        for i, seq in enumerate(chunk):
            results.append({
                "sequence_id":      seq.get("sequence_id", f"seq_{start + i}"),
                "attack_prob":      round(float(probs[i, 1]), 4),
                "predicted_binary": int(probs[i, 1] >= 0.5),
            })

        if (start // batch_size) % 20 == 0:
            print(f"\r  [DistilBERT] {min(start + batch_size, n)}/{n} …", end="", flush=True)

    print(f"\r  [DistilBERT] {n:,} sequences scored              ")
    return results


# ── XLNet perplexity (sequence-by-sequence) ───────────────────────────────────

@torch.no_grad()
def xlnet_perplexity(model, tokens, device):
    """Compute sequence perplexity using XLNet LM head (causal shift)."""
    ids, mask = encode(tokens, MAX_LEN)
    if len(ids) < 2:
        return 0.0
    input_ids_t = torch.tensor([ids],  dtype=torch.long, device=device)
    mask_t      = torch.tensor([mask], dtype=torch.long, device=device)

    logits       = model(input_ids=input_ids_t, attention_mask=mask_t).logits
    valid_len    = len(ids) - 1
    shift_logits = logits[0, :valid_len, :]
    shift_labels = input_ids_t[0, 1:valid_len + 1]

    return round(math.exp(min(nn.CrossEntropyLoss()(shift_logits, shift_labels).item(), 100)), 4)


# ── Main scoring ─────────────────────────────────────────────────────────────

def score(input_path: Path, output_path: Path) -> None:
    print("=" * 70)
    print("SEVERITY SCORER  (DistilBERT + XLNet on test set)")
    print(f"  Input: {input_path}  |  Output: {output_path}")
    print("=" * 70 + "\n")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Using device: {device}\n")

    # ── Load models ────────────────────────────────────────────────────────
    for label, path, loader in [
        ("DistilBERT", DISTILBERT_DIR,
         lambda p: DistilBertForSequenceClassification.from_pretrained(str(p))),
        ("XLNet",      XLNET_DIR,
         lambda p: XLNetLMHeadModel.from_pretrained(str(p))),
    ]:
        if not path.exists():
            print(f"[ERROR] {label} model not found: {path}"); sys.exit(1)

    print("[*] Loading DistilBERT …")
    d_model = DistilBertForSequenceClassification.from_pretrained(
        str(DISTILBERT_DIR)).to(device).eval()
    print(f"  [OK] DistilBERT loaded  (vocab={VOCAB_SIZE})")

    print("[*] Loading XLNet …")
    x_model = XLNetLMHeadModel.from_pretrained(str(XLNET_DIR)).to(device).eval()
    print("  [OK] XLNet loaded\n")

    # ── Load sequences ─────────────────────────────────────────────────────
    print(f"[*] Loading sequences from {input_path} …")
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}"); sys.exit(1)
    with open(input_path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    sequences = raw.get("sequences", raw)
    print(f"  [OK] {len(sequences):,} sequences loaded\n")

    # ── Step 1: DistilBERT batch inference ────────────────────────────────
    print("[*] Running DistilBERT inference …")
    t0 = time.perf_counter()
    db_lookup = {r["sequence_id"]: r for r in distilbert_predict(d_model, sequences, device)}
    print(f"  Done in {time.perf_counter() - t0:.1f}s\n")

    # ── Step 2: XLNet perplexity ──────────────────────────────────────────
    print("[*] Running XLNet perplexity …")
    n, t1 = len(sequences), time.perf_counter()
    all_ppls = []
    for idx, seq in enumerate(sequences):
        tokens = seq.get("tokens", [])
        all_ppls.append(xlnet_perplexity(x_model, tokens, device) if len(tokens) >= 2 else 0.0)
        if (idx + 1) % 200 == 0 or (idx + 1) == n:
            print(f"\r  [XLNet] {idx + 1}/{n} …", end="", flush=True)

    ppl_p99 = max(float(np.percentile(all_ppls, 99)), 1e-6) if all_ppls else 1.0
    print(f"\r  [XLNet] {n:,} perplexities computed in {time.perf_counter() - t1:.1f}s")
    print(f"  Perplexity p99 = {ppl_p99:.4f}  (used for normalisation)\n")

    # ── Step 3: Combine scores ────────────────────────────────────────────
    results: list[dict] = []
    for idx, seq in enumerate(sequences):
        sid    = seq.get("sequence_id", f"seq_{idx}")
        tokens = seq.get("tokens", [])

        # Token severity (1–4 range)
        sev_scores = [SEVERITY_MAP.get(get_severity(t), 1.0) for t in tokens]
        token_sev  = float(np.mean(sev_scores)) if sev_scores else 1.0

        # DistilBERT
        db          = db_lookup.get(sid, {})
        attack_prob = db.get("attack_prob", 0.0)
        db_flag     = db.get("predicted_binary", 0)

        # XLNet anomaly score: LOW perplexity = predictable = suspicious
        # Invert so that low-ppl attacks score HIGH anomaly
        ppl          = all_ppls[idx]
        norm_ppl     = min(ppl / ppl_p99, 1.0)
        anomaly_score = 1.0 - norm_ppl       # low ppl → high score
        xlnet_flag   = 1 if anomaly_score > 0.5 else 0

        # Combined severity
        combined = ((token_sev - 1.0) / 3.0) * 0.25 + attack_prob * 1.50 + anomaly_score * 1.25
        risk     = risk_label(combined)

        # Model agreement
        agreement = ("both_malicious" if db_flag == 1 and xlnet_flag == 1 else
                     "both_benign"    if db_flag == 0 and xlnet_flag == 0 else
                     "distilbert_only" if db_flag == 1 else "xlnet_only")

        results.append({
            "sequence_id":        sid,
            "source":             seq.get("source", "unknown"),
            "attack_type":        seq.get("attack_type", "UNKNOWN"),
            "true_label":         int(seq.get("label", 0)),
            "risk_level":         risk,
            "combined_severity":  round(combined, 4),
            "attack_prob":        round(attack_prob, 4),
            "anomaly_score":      round(anomaly_score, 4),
            "token_severity_mean":round(token_sev, 4),
            "perplexity":         ppl,
            "model_agreement":    agreement,
        })

    elapsed = time.perf_counter() - t0
    print(f"\n[*] Scoring complete  ({len(results):,} sequences in {elapsed:.1f}s)\n")

    # ── Per-sequence severity display ───────────────────────────────────
    total = len(results)
    print("=" * 100)
    print("PER-SEQUENCE SEVERITY SCORES")
    print("=" * 100)
    print(f"  {'ID':<24} {'Source':<8} {'Attack':<15} {'Label':>9} "
          f"{'Risk':<10} {'Score':>6} {'AtkProb':>7} {'Anomaly':>7} {'TokSev':>6} {'Agreement'}")
    print("  " + "-" * 98)
    for r in results[:30]:
        sid = str(r["sequence_id"])[:22]
        lbl = "MALICIOUS" if r["true_label"] == 1 else "BENIGN"
        print(f"  {sid:<24} {r['source']:<8} {r['attack_type']:<15} {lbl:>9} "
              f"{r['risk_level']:<10} {r['combined_severity']:>6.3f} {r['attack_prob']:>7.4f} "
              f"{r['anomaly_score']:>7.4f} {r['token_severity_mean']:>6.2f} {r['model_agreement']}")
    if total > 30:
        print(f"  … ({total - 30:,} more sequences omitted)")
    print()

    # ── Summary statistics ────────────────────────────────────────────────
    risk_counts  = Counter(r["risk_level"]      for r in results)
    agree_counts = Counter(r["model_agreement"] for r in results)
    source_risk: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        source_risk[r["source"]][r["risk_level"]] += 1

    print("=" * 60 + "\nRISK DISTRIBUTION\n" + "=" * 60)
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = risk_counts.get(lvl, 0)
        bar = "█" * int(c / total * 40) if total else ""
        print(f"  {lvl:<10} {c:>6,}  ({c / total * 100:.1f}%)  {bar}")

    print(f"\nMODEL AGREEMENT\n" + "-" * 40)
    for key, count in sorted(agree_counts.items(), key=lambda x: -x[1]):
        print(f"  {key:<24} {count:>6,}  ({count / total * 100:.1f}%)")

    print(f"\nPER-SOURCE RISK BREAKDOWN")
    print(f"  {'Source':<12} {'LOW':>6} {'MED':>6} {'HIGH':>6} {'CRIT':>6}  Total")
    print("  " + "-" * 50)
    for src in sorted(source_risk):
        sc = source_risk[src]
        print(f"  {src:<12} {sc.get('LOW',0):>6,} {sc.get('MEDIUM',0):>6,} "
              f"{sc.get('HIGH',0):>6,} {sc.get('CRITICAL',0):>6,}  {sum(sc.values()):>6,}")

    # Quick accuracy proxy
    n_mal = sum(1 for r in results if r["true_label"] == 1)
    if n_mal:
        tp = sum(1 for r in results if r["true_label"] == 1 and r["risk_level"] in ("CRITICAL", "HIGH"))
        print(f"\n  HIGH + CRITICAL recall on malicious: {tp}/{n_mal} = {tp / n_mal * 100:.1f}%")
    print()

    # ── Save report ────────────────────────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "input_file":       str(input_path),
        "distilbert_model": str(DISTILBERT_DIR),
        "xlnet_model":      str(XLNET_DIR),
        "n_sequences":      total,
        "ppl_p99_norm":     round(ppl_p99, 4),
        "elapsed_sec":      round(elapsed, 2),
        "risk_distribution": {k: int(v) for k, v in risk_counts.items()},
        "model_agreement":   {k: int(v) for k, v in agree_counts.items()},
        "per_source_risk":   {src: {k: int(v) for k, v in ctr.items()}
                              for src, ctr in source_risk.items()},
        "sequences": results,
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(_clean(report), fh, indent=2)

    print(f"[OK] Severity report saved → {output_path}")
    print("=" * 70)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Score sequences with combined severity")
    p.add_argument("--input",  type=str, default=str(DEFAULT_INPUT))
    p.add_argument("--output", type=str, default=str(DEFAULT_OUTPUT))
    args = p.parse_args()
    score(Path(args.input), Path(args.output))


if __name__ == "__main__":
    main()
