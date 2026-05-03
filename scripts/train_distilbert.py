#!/usr/bin/env python3
"""
Train a custom DistilBERT model for binary attack classification.

Architecture
-----------
  - From-scratch DistilBERT (no pre-trained weights; custom 49-token vocabulary)
  - dim=256, n_layers=4, n_heads=4, hidden_dim=1024
  - Binary classification head  (0 = BENIGN, 1 = MALICIOUS)

Data
----
  Input  : data/processed/train_sequences.json  (56 k sequences, balanced 50/50)
  Val    : data/processed/validation_sequences.json  (3.5 k, 27:1 imbalance)
  Fields : tokens (list[str]), label (0 or 1)

Output
------
  models/distilbert_attack_classifier/   — best checkpoint (highest val-F1)
  reports/distilbert_training.json       — per-epoch metrics log

Usage
-----
  python scripts/train_distilbert.py
  python scripts/train_distilbert.py --epochs 10 --batch-size 64 --lr 3e-4
"""

import argparse
import json
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import (
    DistilBertConfig,
    DistilBertForSequenceClassification,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
)

# Add scripts/ to path so token_definitions can be imported when running from
# the project root (e.g.  python scripts/train_distilbert.py)
sys.path.insert(0, str(Path(__file__).parent))
from token_definitions import TOKEN_TO_ID, VOCAB_SIZE  # noqa: E402

# ── Paths ─────────────────────────────────────────────────────────────────────
PROCESSED_DIR = Path("data/processed")
MODEL_DIR     = Path("models/distilbert_attack_classifier")
REPORTS_DIR   = Path("reports")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_EPOCHS          = 10
DEFAULT_BATCH           = 32
DEFAULT_LR              = 3e-4
DEFAULT_MAX_LEN         = 128
DEFAULT_WARMUP          = 0.1   # fraction of total steps used for LR warm-up
DEFAULT_WEIGHT_DEC      = 0.01
DEFAULT_PATIENCE        = 3     # early-stopping: epochs without val-F1 improvement
DEFAULT_LOG_STEPS       = 200   # log every N steps (not just once per epoch)


# ── Reproducibility ───────────────────────────────────────────────────────────

def set_seed(seed: int = 42) -> None:
    """Fix all RNG sources for reproducible runs."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


# ── Dataset helper ────────────────────────────────────────────────────────────

class SequenceDataset:
    """Loads a *_sequences.json split and converts tokens → integer IDs."""

    PAD_ID = TOKEN_TO_ID.get("PAD", 0)

    def __init__(self, filepath: Path, max_len: int = DEFAULT_MAX_LEN):
        if not filepath.exists():
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)

        with open(filepath, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        sequences = raw.get("sequences", raw)   # tolerate both formats
        self.max_len  = max_len
        self.records  = sequences
        print(f"  [OK] {filepath.name}: {len(sequences):,} sequences loaded")

        # Print label distribution for visibility
        from collections import Counter
        lc = Counter(r.get("label") for r in sequences)
        total = len(sequences)
        print(f"       Label dist: { {k: f'{v:,} ({100*v/total:.1f}%)' for k,v in sorted(lc.items())} }")

    # ---- internal helpers -----------------------------------------------

    def _encode(self, tokens: list[str]) -> tuple[list[int], list[int]]:
        ids = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens]
        # Truncate (keep TAIL — most recent events are more diagnostic)
        ids = ids[-self.max_len :]
        # Pad (right-pad to kept length; Trainer collates dynamically)
        mask = [1] * len(ids)
        return ids, mask

    # ---- public API ------------------------------------------------------

    def as_hf_dataset(self) -> Dataset:
        """Return a Hugging Face Dataset with input_ids, attention_mask, labels."""
        input_ids, attention_masks, labels = [], [], []
        for rec in self.records:
            ids, mask = self._encode(rec["tokens"])
            input_ids.append(ids)
            attention_masks.append(mask)
            labels.append(int(rec["label"]))

        return Dataset.from_dict(
            {
                "input_ids":      input_ids,
                "attention_mask": attention_masks,
                "labels":         labels,
            }
        )


# ── Data collator (pad to batch's longest sequence) ──────────────────────────

def make_collator(pad_id: int = TOKEN_TO_ID.get("PAD", 0)):
    """Return a data-collator that right-pads variable-length sequences."""

    def collate(features: list[dict]) -> dict[str, torch.Tensor]:
        max_len = max(len(f["input_ids"]) for f in features)
        batch_size = len(features)

        input_ids      = torch.full((batch_size, max_len), pad_id, dtype=torch.long)
        attention_mask = torch.zeros((batch_size, max_len), dtype=torch.long)
        labels         = torch.zeros(batch_size, dtype=torch.long)

        for i, f in enumerate(features):
            seq_len = len(f["input_ids"])
            input_ids[i, :seq_len]      = torch.tensor(f["input_ids"],      dtype=torch.long)
            attention_mask[i, :seq_len] = torch.tensor(f["attention_mask"], dtype=torch.long)
            labels[i]                   = f["labels"]

        return {
            "input_ids":      input_ids,
            "attention_mask": attention_mask,
            "labels":         labels,
        }

    return collate


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(eval_pred):
    """
    Hugging Face Trainer callback.
    Returns accuracy, precision, recall, F1, and ROC-AUC for binary labels.
    NOTE: val set is 27:1 imbalanced — F1 on the MALICIOUS class is the gold metric.
    """
    logits, labels = eval_pred
    probs      = torch.softmax(torch.tensor(logits, dtype=torch.float32), dim=-1).numpy()
    preds      = np.argmax(logits, axis=-1)

    # Use malicious-class (index 1) probability for AUC
    pos_probs  = probs[:, 1]

    try:
        auc = roc_auc_score(labels, pos_probs)
    except ValueError:
        auc = 0.0   # only one class present in eval batch

    return {
        "accuracy":  round(accuracy_score(labels, preds), 4),
        "precision": round(precision_score(labels, preds, zero_division=0), 4),
        "recall":    round(recall_score(labels, preds, zero_division=0), 4),
        "f1":        round(f1_score(labels, preds, zero_division=0), 4),
        "roc_auc":   round(auc, 4),
    }


# ── Model factory ─────────────────────────────────────────────────────────────

def build_model(max_len: int = DEFAULT_MAX_LEN) -> DistilBertForSequenceClassification:
    """Build a fresh DistilBERT binary-classification model from scratch."""
    config = DistilBertConfig(
        vocab_size             = VOCAB_SIZE,
        # Match position embeddings to actual max sequence length (no wasted params)
        max_position_embeddings= max_len,
        dim                    = 256,
        n_layers               = 4,
        n_heads                = 4,
        hidden_dim             = 1024,
        dropout                = 0.1,
        attention_dropout      = 0.1,
        seq_classif_dropout    = 0.2,
        num_labels             = 2,
        pad_token_id           = TOKEN_TO_ID.get("PAD", 0),
        sinusoidal_pos_embds   = False,
        problem_type           = "single_label_classification",
        id2label               = {0: "BENIGN", 1: "MALICIOUS"},
        label2id               = {"BENIGN": 0, "MALICIOUS": 1},
    )
    model = DistilBertForSequenceClassification(config)
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  [OK] Model built  (vocab={VOCAB_SIZE}, max_pos={max_len}, params={n_params:,})")
    return model


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train DistilBERT attack classifier")
    p.add_argument("--epochs",      type=int,   default=DEFAULT_EPOCHS,      help="Training epochs")
    p.add_argument("--batch-size",  type=int,   default=DEFAULT_BATCH,       help="Per-device batch size")
    p.add_argument("--lr",          type=float, default=DEFAULT_LR,          help="Peak learning rate")
    p.add_argument("--max-len",     type=int,   default=DEFAULT_MAX_LEN,     help="Max token sequence length")
    p.add_argument("--warmup",      type=float, default=DEFAULT_WARMUP,      help="Warm-up fraction of total steps")
    p.add_argument("--weight-decay",type=float, default=DEFAULT_WEIGHT_DEC,  help="AdamW weight decay")
    p.add_argument("--output-dir",  type=str,   default=str(MODEL_DIR),      help="Model output directory")
    p.add_argument("--fp16",        action="store_true",                     help="Enable mixed-precision (FP16)")
    p.add_argument("--patience",    type=int,   default=DEFAULT_PATIENCE,    help="Early-stopping patience (epochs)")
    p.add_argument("--log-steps",   type=int,   default=DEFAULT_LOG_STEPS,   help="Log every N steps")
    p.add_argument("--seed",        type=int,   default=42,                  help="Random seed for reproducibility")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # ── Fix all RNG sources before anything else ──────────────────────────
    set_seed(args.seed)

    print("=" * 70)
    print("TRAINING DISTILBERT ATTACK CLASSIFIER")
    print(f"  Epochs     : {args.epochs}  (early-stop patience={args.patience})")
    print(f"  Batch size : {args.batch_size}")
    print(f"  LR         : {args.lr}")
    print(f"  Max length : {args.max_len}")
    print(f"  Log steps  : every {args.log_steps} steps")
    print(f"  Vocab size : {VOCAB_SIZE}")
    print(f"  Seed       : {args.seed}")
    print(f"  Device     : {'cuda' if torch.cuda.is_available() else 'cpu'}")
    print("=" * 70 + "\n")

    # ── 1. Load data ──────────────────────────────────────────────────────
    print("[1/4] Loading datasets")
    train_ds = SequenceDataset(PROCESSED_DIR / "train_sequences.json",      args.max_len).as_hf_dataset()
    val_ds   = SequenceDataset(PROCESSED_DIR / "validation_sequences.json", args.max_len).as_hf_dataset()
    print(f"  Train : {len(train_ds):,}  |  Val : {len(val_ds):,}\n")

    # ── 2. Build model ────────────────────────────────────────────────────
    print("[2/4] Building model")
    model = build_model(max_len=args.max_len)
    print()

    # ── 3. Training arguments ─────────────────────────────────────────────
    print("[3/4] Configuring trainer")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    total_steps   = (len(train_ds) // args.batch_size) * args.epochs
    warmup_steps  = int(total_steps * args.warmup)

    training_args = TrainingArguments(
        output_dir                  = str(output_dir),
        num_train_epochs            = args.epochs,
        per_device_train_batch_size = args.batch_size,
        per_device_eval_batch_size  = args.batch_size * 2,
        learning_rate               = args.lr,
        weight_decay                = args.weight_decay,
        warmup_steps                = warmup_steps,
        lr_scheduler_type           = "cosine",
        # Eval & save every epoch; log every N steps for finer visibility
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        logging_strategy            = "steps",
        logging_steps               = args.log_steps,
        load_best_model_at_end      = True,
        metric_for_best_model       = "f1",
        greater_is_better           = True,
        save_total_limit            = 3,
        overwrite_output_dir        = True,
        remove_unused_columns       = False,
        fp16                        = args.fp16 and torch.cuda.is_available(),
        dataloader_num_workers      = 0,          # safe on Windows
        dataloader_pin_memory       = False,      # suppress pin_memory warning on CPU
        report_to                   = "none",
        seed                        = args.seed,
    )
    print(f"  Total steps  : {total_steps:,}")
    print(f"  Warm-up steps: {warmup_steps:,}\n")

    trainer = Trainer(
        model            = model,
        args             = training_args,
        train_dataset    = train_ds,
        eval_dataset     = val_ds,
        data_collator    = make_collator(),
        compute_metrics  = compute_metrics,
        # Stop early if val-F1 doesn't improve for `patience` consecutive epochs
        callbacks        = [EarlyStoppingCallback(early_stopping_patience=args.patience)],
    )

    # ── 4. Train ──────────────────────────────────────────────────────────
    print("[4/4] Training …")
    t0 = time.time()
    result = trainer.train()
    elapsed = time.time() - t0

    print(f"\n[OK] Training complete in {elapsed/60:.1f} min")
    print(f"     Train loss : {result.training_loss:.4f}")

    # ── Save best model ───────────────────────────────────────────────────
    trainer.save_model(str(output_dir))
    print(f"[OK] Best model saved → {output_dir}\n")

    # ── Per-epoch metrics log ─────────────────────────────────────────────
    epoch_logs = [
        {k: round(v, 4) if isinstance(v, float) else v for k, v in log.items()}
        for log in trainer.state.log_history
    ]

    # Final eval on validation set
    print("[*] Running final evaluation on validation set …")
    final_metrics = trainer.evaluate()
    print()
    print("  Validation metrics:")
    for k, v in final_metrics.items():
        if isinstance(v, float):
            print(f"    {k:<25}: {v:.4f}")

    report = {
        "model":             "DistilBERT Attack Classifier",
        "vocab_size":        VOCAB_SIZE,
        "epochs_requested":  args.epochs,
        "epochs_trained":    int(trainer.state.epoch),
        "batch_size":        args.batch_size,
        "learning_rate":     args.lr,
        "max_length":        args.max_len,
        "seed":              args.seed,
        "early_stop_patience": args.patience,
        "train_samples":     len(train_ds),
        "val_samples":       len(val_ds),
        "train_loss":        round(result.training_loss, 4),
        "training_time_min": round(elapsed / 60, 2),
        "final_val_metrics": {k: round(v, 4) if isinstance(v, float) else v
                              for k, v in final_metrics.items()},
        "epoch_logs":        epoch_logs,
    }

    report_path = REPORTS_DIR / "distilbert_training.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[OK] Training report saved → {report_path}")

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("TRAINING SUMMARY")
    print("=" * 70)
    vm = final_metrics
    print(f"  Epochs trained: {int(trainer.state.epoch)} / {args.epochs}")
    print(f"  Accuracy  : {vm.get('eval_accuracy',  0):.4f}")
    print(f"  Precision : {vm.get('eval_precision', 0):.4f}")
    print(f"  Recall    : {vm.get('eval_recall',    0):.4f}")
    print(f"  F1        : {vm.get('eval_f1',        0):.4f}")
    print(f"  ROC-AUC   : {vm.get('eval_roc_auc',   0):.4f}")
    print(f"  Model dir : {output_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
