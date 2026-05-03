#!/usr/bin/env python3
"""
Train a custom XLNet model for next-step behaviour prediction (causal LM).

Architecture
-----------
  - From-scratch XLNet (no pre-trained weights; custom 49-token vocabulary)
  - d_model=256, n_layer=4, n_head=4, d_inner=1024
  - Causal language-modelling head  (predict next behaviour token)

Purpose
-------
  Learn the conditional distribution of "what happens next" in a behaviour
  sequence.  At inference, sequences whose observed tokens are *unlikely*
  under the learned model (high perplexity) are flagged as anomalous.
  This complements DistilBERT's supervised binary classifier.

Data
----
  Input  : data/processed/train_sequences.json  (56 k sequences, balanced)
  Val    : data/processed/validation_sequences.json
  Fields : tokens (list[str])  — domain prefix + behaviour tokens

Output
------
  models/xlnet_behaviour_predictor/  — best checkpoint (lowest val-loss)
  reports/xlnet_training.json        — per-epoch metrics log

Usage
-----
  python scripts/train_xlnet.py
  python scripts/train_xlnet.py --epochs 10 --batch-size 64 --lr 3e-4
"""

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from datasets import Dataset
from transformers import (
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
    XLNetConfig,
    XLNetLMHeadModel,
)

# Allow running from the project root
sys.path.insert(0, str(Path(__file__).parent))
from token_definitions import TOKEN_TO_ID, VOCAB_SIZE  # noqa: E402

# ── Paths ─────────────────────────────────────────────────────────────────────
PROCESSED_DIR = Path("data/processed")
MODEL_DIR     = Path("models/xlnet_behaviour_predictor")
REPORTS_DIR   = Path("reports")

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_EPOCHS      = 10
DEFAULT_BATCH       = 32
DEFAULT_LR          = 3e-4
DEFAULT_MAX_LEN     = 128
DEFAULT_WARMUP      = 0.1
DEFAULT_WEIGHT_DEC  = 0.01
DEFAULT_PATIENCE    = 3
DEFAULT_LOG_STEPS   = 200


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
    """Loads a *_sequences.json split and converts tokens → integer IDs.

    For causal LM training we shift the sequence:
      input_ids = tokens[:-1]      (context prefix)
      labels    = tokens[1:]       (next-token targets)
    """

    PAD_ID = TOKEN_TO_ID.get("PAD", 0)

    def __init__(self, filepath: Path, max_len: int = DEFAULT_MAX_LEN):
        if not filepath.exists():
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)

        with open(filepath, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        sequences = raw.get("sequences", raw)
        self.max_len  = max_len
        self.records  = sequences
        print(f"  [OK] {filepath.name}: {len(sequences):,} sequences loaded")

    # ---- internal helpers -----------------------------------------------

    def _encode(self, tokens: list[str]) -> tuple[list[int], list[int], list[int]]:
        """Encode tokens into input_ids (prefix) and labels (shifted targets)."""
        ids = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens]
        # Tail-truncate to max_len (keep most recent events)
        ids = ids[-self.max_len:]

        if len(ids) < 2:
            # Need at least 2 tokens for input→target pair
            ids = ids + [self.PAD_ID] * (2 - len(ids))

        # Causal LM shift: input = all-but-last, labels = all-but-first
        input_ids = ids[:-1]
        labels    = ids[1:]
        mask      = [1] * len(input_ids)

        return input_ids, mask, labels

    # ---- public API ------------------------------------------------------

    def as_hf_dataset(self) -> Dataset:
        """Return a Hugging Face Dataset with input_ids, attention_mask, labels."""
        all_input_ids, all_masks, all_labels = [], [], []
        skipped = 0

        for rec in self.records:
            tokens = rec.get("tokens", [])
            if len(tokens) < 2:
                skipped += 1
                continue

            input_ids, mask, labels = self._encode(tokens)
            all_input_ids.append(input_ids)
            all_masks.append(mask)
            all_labels.append(labels)

        if skipped:
            print(f"  [!] Skipped {skipped} sequences with < 2 tokens")

        return Dataset.from_dict(
            {
                "input_ids":      all_input_ids,
                "attention_mask": all_masks,
                "labels":         all_labels,
            }
        )


# ── Data collator (pad to batch's longest sequence) ──────────────────────────

def make_collator(pad_id: int = TOKEN_TO_ID.get("PAD", 0)):
    """Return a data-collator that right-pads variable-length sequences.

    Labels are padded with -100 so CrossEntropyLoss ignores padding positions.
    Includes a causal `perm_mask` so XLNet attends only to left context
    (avoids the in-place broadcast bug with attn_type='uni').
    """

    def collate(features: list[dict]) -> dict[str, torch.Tensor]:
        max_len    = max(len(f["input_ids"]) for f in features)
        batch_size = len(features)

        input_ids      = torch.full((batch_size, max_len), pad_id,  dtype=torch.long)
        attention_mask = torch.zeros((batch_size, max_len),          dtype=torch.long)
        labels         = torch.full((batch_size, max_len), -100,    dtype=torch.long)

        for i, f in enumerate(features):
            seq_len = len(f["input_ids"])
            input_ids[i, :seq_len]      = torch.tensor(f["input_ids"],      dtype=torch.long)
            attention_mask[i, :seq_len] = torch.tensor(f["attention_mask"], dtype=torch.long)
            labels[i, :seq_len]         = torch.tensor(f["labels"],         dtype=torch.long)

        # Causal perm_mask: (batch, seq_len, seq_len)
        # perm_mask[b][i][j] = 1  → token i CANNOT attend to token j
        # Upper-triangular (excluding diagonal) → each token sees only itself + left
        causal = torch.triu(torch.ones(max_len, max_len), diagonal=1)
        perm_mask = causal.unsqueeze(0).expand(batch_size, -1, -1).float()

        return {
            "input_ids":      input_ids,
            "attention_mask": attention_mask,
            "perm_mask":      perm_mask,
            "labels":         labels,
        }

    return collate


# ── Metrics ───────────────────────────────────────────────────────────────────

def compute_metrics(eval_pred):
    """
    Trainer callback: computes perplexity and top-K accuracy for LM evaluation.
    """
    logits, labels = eval_pred     # logits: (N, seq_len, vocab), labels: (N, seq_len)

    # Flatten
    logits_flat = torch.tensor(logits, dtype=torch.float32)
    labels_flat = torch.tensor(labels, dtype=torch.long)

    # Mask out padding (-100)
    valid = labels_flat.view(-1) != -100
    logits_valid = logits_flat.view(-1, logits_flat.size(-1))[valid]
    labels_valid = labels_flat.view(-1)[valid]

    # Perplexity from cross-entropy
    ce_loss = nn.CrossEntropyLoss()(logits_valid, labels_valid)
    perplexity = math.exp(min(ce_loss.item(), 100))   # cap to prevent overflow

    # Top-K accuracy
    preds_top1 = logits_valid.argmax(dim=-1)
    top1_acc = (preds_top1 == labels_valid).float().mean().item()

    _, top5_preds = logits_valid.topk(min(5, logits_valid.size(-1)), dim=-1)
    top5_acc = (top5_preds == labels_valid.unsqueeze(-1)).any(dim=-1).float().mean().item()

    return {
        "perplexity":   round(perplexity, 4),
        "top1_accuracy": round(top1_acc, 4),
        "top5_accuracy": round(top5_acc, 4),
    }


# ── Model factory ─────────────────────────────────────────────────────────────

def build_model(max_len: int = DEFAULT_MAX_LEN) -> XLNetLMHeadModel:
    """Build a fresh XLNet causal language model from scratch."""
    config = XLNetConfig(
        vocab_size  = VOCAB_SIZE,
        d_model     = 256,
        n_layer     = 4,
        n_head      = 4,
        d_inner     = 1024,
        dropout     = 0.1,
        # Causal masking is enforced via perm_mask in the data collator
        # (attn_type="uni" triggers an in-place broadcast bug with batch>1)
        bi_data     = False,
        clamp_len   = max_len,
        mem_len     = 0,           # no transformer-XL memory segments
        # Misc
        pad_token_id = TOKEN_TO_ID.get("PAD", 0),
    )
    model = XLNetLMHeadModel(config)
    n_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  [OK] XLNet model built  (vocab={VOCAB_SIZE}, max_len={max_len}, params={n_params:,})")
    return model


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train XLNet next-step behaviour predictor")
    p.add_argument("--epochs",       type=int,   default=DEFAULT_EPOCHS,      help="Training epochs")
    p.add_argument("--batch-size",   type=int,   default=DEFAULT_BATCH,       help="Per-device batch size")
    p.add_argument("--lr",           type=float, default=DEFAULT_LR,          help="Peak learning rate")
    p.add_argument("--max-len",      type=int,   default=DEFAULT_MAX_LEN,     help="Max token sequence length")
    p.add_argument("--warmup",       type=float, default=DEFAULT_WARMUP,      help="Warm-up fraction")
    p.add_argument("--weight-decay", type=float, default=DEFAULT_WEIGHT_DEC,  help="AdamW weight decay")
    p.add_argument("--output-dir",   type=str,   default=str(MODEL_DIR),      help="Model output directory")
    p.add_argument("--fp16",         action="store_true",                     help="Enable mixed-precision (FP16)")
    p.add_argument("--patience",     type=int,   default=DEFAULT_PATIENCE,    help="Early-stopping patience")
    p.add_argument("--log-steps",    type=int,   default=DEFAULT_LOG_STEPS,   help="Log every N steps")
    p.add_argument("--seed",         type=int,   default=42,                  help="Random seed")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    set_seed(args.seed)

    print("=" * 70)
    print("TRAINING XLNET NEXT-STEP BEHAVIOUR PREDICTOR")
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

    total_steps  = (len(train_ds) // args.batch_size) * args.epochs
    warmup_steps = int(total_steps * args.warmup)

    training_args = TrainingArguments(
        output_dir                  = str(output_dir),
        num_train_epochs            = args.epochs,
        per_device_train_batch_size = args.batch_size,
        per_device_eval_batch_size  = args.batch_size * 2,
        learning_rate               = args.lr,
        weight_decay                = args.weight_decay,
        warmup_steps                = warmup_steps,
        lr_scheduler_type           = "cosine",
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        logging_strategy            = "steps",
        logging_steps               = args.log_steps,
        load_best_model_at_end      = True,
        metric_for_best_model       = "perplexity",
        greater_is_better           = False,          # lower perplexity = better
        save_total_limit            = 3,
        overwrite_output_dir        = True,
        remove_unused_columns       = False,
        fp16                        = args.fp16 and torch.cuda.is_available(),
        dataloader_num_workers      = 0,
        dataloader_pin_memory       = False,
        report_to                   = "none",
        seed                        = args.seed,
    )
    print(f"  Total steps  : {total_steps:,}")
    print(f"  Warm-up steps: {warmup_steps:,}\n")

    trainer = Trainer(
        model           = model,
        args            = training_args,
        train_dataset   = train_ds,
        eval_dataset    = val_ds,
        data_collator   = make_collator(),
        compute_metrics = compute_metrics,
        callbacks       = [EarlyStoppingCallback(early_stopping_patience=args.patience)],
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
        "model":              "XLNet Next-Step Behaviour Predictor",
        "vocab_size":         VOCAB_SIZE,
        "epochs_requested":   args.epochs,
        "epochs_trained":     int(trainer.state.epoch),
        "batch_size":         args.batch_size,
        "learning_rate":      args.lr,
        "max_length":         args.max_len,
        "seed":               args.seed,
        "early_stop_patience": args.patience,
        "train_samples":      len(train_ds),
        "val_samples":        len(val_ds),
        "train_loss":         round(result.training_loss, 4),
        "training_time_min":  round(elapsed / 60, 2),
        "final_val_metrics":  {k: round(v, 4) if isinstance(v, float) else v
                               for k, v in final_metrics.items()},
        "epoch_logs":         epoch_logs,
    }

    report_path = REPORTS_DIR / "xlnet_training.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[OK] Training report saved → {report_path}")

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("TRAINING SUMMARY")
    print("=" * 70)
    vm = final_metrics
    print(f"  Epochs trained   : {int(trainer.state.epoch)} / {args.epochs}")
    print(f"  Perplexity       : {vm.get('eval_perplexity',   0):.4f}")
    print(f"  Top-1 accuracy   : {vm.get('eval_top1_accuracy', 0):.4f}")
    print(f"  Top-5 accuracy   : {vm.get('eval_top5_accuracy', 0):.4f}")
    print(f"  Model dir        : {output_dir}")
    print("=" * 70)


if __name__ == "__main__":
    main()
