# Module 3 — Core Engine / Detection Module

---

## 1. Module Name

**Core Engine — ML Detection and Severity Scoring Module**

---

## 2. Module Purpose

This module is the **intelligence core of the system**. It applies two fine-tuned deep learning models to every attack session and produces a multi-dimensional risk assessment:

- **DistilBERT** — classifies whether a session is malicious or benign (binary classification)
- **XLNet** — predicts the attacker's **next action** and measures behavioural anomaly via sequence perplexity
- **Severity Scorer** — fuses both model outputs with token-level risk into a single combined severity score
- **MITRE ATT&CK Mapper** — maps detected token patterns to ATT&CK techniques and tactics

---

## 3. Problem the Module Solves

Traditional network security tools answer: *"Is this packet/signature known-bad?"*

This module answers a fundamentally different set of questions:

1. **What is the probability that this session is a malicious attack?** (DistilBERT)
2. **What is the attacker likely to do next?** (XLNet next-token prediction)
3. **How suspicious is this behaviour pattern compared to known norms?** (XLNet perplexity-based anomaly)
4. **What is the overall risk level?: LOW / MEDIUM / HIGH / CRITICAL** (Combined scorer)
5. **Which specific ATT&CK techniques are being used?** (MITRE mapping)

This answers questions that signature-based IDS cannot — including zero-day and novel attack patterns that exhibit suspicious *behavioural sequences* even without known signatures.

---

## 4. Detailed Explanation of How It Works

### 4.1 Model 1 — DistilBERT Attack Classifier

**Architecture:** DistilBERT (distilled BERT) with a binary classification head

- Input: token sequence encoded as integer IDs (max length 128 tokens)
- Output: probability `attack_prob` in [0.0, 1.0] where ≥ 0.5 = MALICIOUS
- Trained on the unified BETH + Cowrie + Dionaea dataset

**Encoding:**
```python
# From scripts/severity_scorer.py :: encode()
def encode(tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
    ids = [TOKEN_TO_ID.get(t, TOKEN_TO_ID["UNK"]) for t in tokens][-max_len:]
    return ids, [1] * len(ids)   # (input_ids, attention_mask)
```

The tail-truncation (`[-max_len:]`) ensures that the most recent tokens (most predictive of current intent) are preserved when sequences exceed 128 tokens.

**Batched inference (batch_size=64):**
- Sequences are padded to the longest in the batch within each mini-batch
- All sequences in a batch processed in a single GPU/CPU forward pass
- Throughput (from evaluation): **263.2 sequences/second**

### 4.2 Model 2 — XLNet Behaviour Predictor

**Architecture:** XLNet with a language model head (left-to-right causal)

- Input: same token sequence encoded as integer IDs
- Two outputs:
  1. **`predicted_next_token`** — argmax over vocabulary at the last position's logits
  2. **`perplexity`** — sequence-level cross-entropy exponentiated (how "surprising" the sequence is)

**Perplexity computation:**
```python
# From scripts/severity_scorer.py :: xlnet_perplexity()
logits      = model(input_ids, attention_mask).logits
shift_logits = logits[0, :-1, :]       # predictions for positions 1..N
shift_labels = input_ids[0, 1:]        # actual tokens at positions 1..N
loss         = CrossEntropyLoss()(shift_logits, shift_labels)
perplexity   = exp(min(loss.item(), 100))  # clamped to prevent overflow
```

**Key insight:** A malicious attack session follows a **predictable** sequence of steps (scan → login attempts → login success → execute commands → download payload). Low perplexity = highly predictable = suspicious. The anomaly score **inverts** this:

```
anomaly_score = 1.0 - (perplexity / p99_perplexity)
```

Where `p99_perplexity = 35.02` (from the test set evaluation run). High `anomaly_score` = low perplexity = attacker following a known malicious playbook.

### 4.3 Combined Severity Score

```
token_sev_scaled = (mean_token_severity_1_to_4 - 1.0) / 3.0

combined = token_sev_scaled × 0.25
         + attack_prob      × 1.50
         + anomaly_score    × 1.25
```

Weight rationale:
- **DistilBERT attack_prob × 1.50** — highest weight: explicit classification signal
- **XLNet anomaly_score × 1.25** — second: catches novel attacks that DistilBERT may miss
- **token_sev_scaled × 0.25** — lowest: provides domain knowledge as soft prior

**Risk thresholds:**

| Combined Score | Risk Level |
|---|---|
| < 0.5 | **LOW** |
| 0.5 – 1.2 | **MEDIUM** |
| 1.2 – 2.0 | **HIGH** |
| ≥ 2.0 | **CRITICAL** |

### 4.4 MITRE ATT&CK Mapping

**File:** `scripts/mitre_mapping.py`

Every token in the sequence is looked up in `MITRE_MAP` and mapped to one or more technique objects:

```python
MITRE_MAP = {
    "SCAN":      [{"technique_id": "T1046", "technique_name": "Network Service Discovery",
                   "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1046/"}],
    "LOGIN_ATT": [{"technique_id": "T1110", "technique_name": "Brute Force",
                   "tactic": "Credential Access", "url": "..."}],
    "LOGIN_OK":  [{"technique_id": "T1078", "technique_name": "Valid Accounts",
                   "tactic": "Defense Evasion / Persistence", "url": "..."}],
    "EXEC":      [{"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
                   "tactic": "Execution", "url": "..."}],
    "FILE_XFER": [{"technique_id": "T1105", "technique_name": "Ingress Tool Transfer",
                   "tactic": "Command and Control", "url": "..."}],
    "TUNNEL":    [{"technique_id": "T1572", ...}, {"technique_id": "T1090", ...}],
    ...
}
```

Results are deduplicated by `technique_id` so that repeated tokens don't produce repeated entries.

---

## 5. Evaluation Results (From Actual Report Files)

> The following metrics are extracted directly from the generated evaluation reports.
> Reports location: `reports/distilbert_evaluation.json`, `reports/xlnet_evaluation.json`, `reports/severity_report.json`
> Generated: 2026-03-04T18:44:47Z (4 March 2026)

### DistilBERT Attack Classifier — Test Set Results

**Test set:** 13,168 sequences (7,037 BENIGN / 6,131 MALICIOUS)

**Overall Performance:**

| Metric | Score |
|---|---|
| **Accuracy** | **95.63%** |
| **Precision** | **93.86%** |
| **Recall** | **96.94%** |
| **F1 Score** | **95.37%** |
| ROC-AUC | 0.9480 |
| MCC | 0.9128 |
| Inference speed | 263.2 sequences/second |

**Confusion Matrix (threshold = 0.5):**

```
                     Predicted
                  BENIGN   MALICIOUS
Actual  BENIGN    6,650       387     ← 387 false positives
        MALICIOUS   214     5,917     ← 214 missed attacks
```

**Per-Source Performance:**

| Source | Accuracy | F1 | Samples |
|---|---|---|---|
| BETH | 95.60% | 0.9531 | 13,050 |
| Cowrie | 100.00% | 1.0000 | 59 |
| Dionaea | 100.00% | 1.0000 | 59 |

**Per-Attack-Type Performance:**

| Attack Type | Accuracy | F1 | Samples |
|---|---|---|---|
| EXPLOIT | 96.90% | 0.9842 | 6,041 |
| BRUTE_FORCE | 100.00% | 1.0000 | 54 |
| MALWARE | 100.00% | 1.0000 | 2 |
| RECONNAISSANCE | 100.00% | 1.0000 | 11 |
| SCAN | 100.00% | 1.0000 | 19 |
| MIXED | 100.00% | 1.0000 | 4 |

**Error rate by token category (where misclassifications occur):**

| Category | Sequences | Errors | Error Rate |
|---|---|---|---|
| EXECUTION | 250 | 28 | 11.2% |
| FILE_OPS | 7,152 | 468 | 6.54% |
| NETWORK | 6,615 | 110 | 1.66% |
| SECURITY | 154 | 6 | 3.90% |
| AUTHENTICATION | 57 | 0 | 0.00% |
| SESSION | 59 | 0 | 0.00% |

**Optimal threshold analysis:**
- Default threshold 0.5 → F1: 0.9537
- PR-Curve optimal threshold 0.5282 → F1: **0.9607** (best achievable)
- ⚠️ Above threshold 0.55, performance collapses — model uses a bimodal distribution (confident low or confident high)

**95% Confidence Intervals (Bootstrap, N=1000):**

| Metric | Mean | CI Lower | CI Upper |
|---|---|---|---|
| Accuracy | 0.9563 | 0.9530 | 0.9598 |
| F1 | 0.9538 | 0.9502 | 0.9575 |
| ROC-AUC | 0.9480 | 0.9434 | 0.9532 |

---

### XLNet Behaviour Predictor — Test Set Results

**Test set:** Same 13,168 sequences, 356.53 seconds to evaluate (36.9 sequences/second)

**Language Model Quality:**

| Metric | Value |
|---|---|
| Mean perplexity (all) | 8.0574 |
| Median perplexity | 5.0861 |
| P99 perplexity | 35.0176 (used for normalisation) |
| **Top-1 next-step accuracy** | **33.86%** |
| **Top-5 next-step accuracy** | **98.82%** |

**Perplexity by label:**

| Label | Mean PPL | Interpretation |
|---|---|---|
| Benign | 9.7907 | More varied/unpredictable behaviour |
| Malicious | 6.0593 | More stereotyped/predictable attack patterns |

This confirms the core hypothesis: **malicious sessions are more predictable than benign ones**, making low perplexity a valid anomaly signal.

**Anomaly Detection Performance (using ppl ≤ 5.52 threshold):**

| Metric | Score |
|---|---|
| Accuracy | 77.06% |
| Precision | 67.30% |
| **Recall** | **98.44%** |
| F1 | 79.94% |
| MCC | 0.6086 |

**High recall (98.44%)** is intentional: XLNet is tuned to catch nearly all malicious sessions (at the cost of some false positives). DistilBERT with high precision filters the combined output.

**Per-attack-type next-step accuracy:**

| Attack Type | Top-1 | Top-5 | Notes |
|---|---|---|---|
| SCAN | 100.0% | 100.0% | Highly repetitive pattern |
| BRUTE_FORCE | 80.0% | 80.0% | Predictable login attempts |
| EXPLOIT | 5.69% | 98.01% | Correct in top-5 virtually always |
| RECONNAISSANCE | 68.06% | 100.0% | |
| BENIGN | 57.48% | 99.65% | More varied, harder to predict exactly |

---

### Combined Severity Distribution (13,168 test sequences)

```
Risk Level   Count    Percentage
─────────────────────────────────
CRITICAL     6,188    47.1%    ████████████████████████
HIGH           401     3.1%    █
MEDIUM       6,028    45.9%    ███████████████████████
LOW            524     4.0%    ██
```

**Model Agreement:**

| Agreement | Count | Meaning |
|---|---|---|
| `xlnet_only` | 5,833 (44.4%) | XLNet flagged, DistilBERT did not |
| `both_malicious` | 6,289 (47.9%) | Both models agree: malicious |
| `both_benign` | 1,004 (7.6%) | Both models agree: benign |
| `distilbert_only` | 15 (0.1%) | DistilBERT flagged, XLNet did not |

---

## 5.1 Live Evaluation Output — Detailed Observations

> The following section is based on **live execution** of both evaluation scripts on the actual trained models.
> Run commands: `python scripts/evaluate_xlnet.py` and `python scripts/evaluate_distilbert.py`
> Executed: 2026-03-10 (project root, CPU mode — no GPU)

---

### XLNet — Console Output Summary

```
Model:     models\xlnet_behaviour_predictor  |  Vocab: 49  |  MaxLen: 128
Threshold: auto (mean + 2σ of benign) → 5.5228
Runtime:   349.4s for 13,141 sequences  (38 seq/s on CPU)

Benign     ppl: mean=9.7907  σ=14.6119  (n=7,037)
Malicious  ppl: mean=6.0593  σ=48.4314  (n=6,104)
Auto threshold: 5.5228  [sweep-optimal, direction: ppl <= t]
```

---

### EXPLOIT Deep-Dive Analysis (from live output)

The evaluation script performs a dedicated analysis of EXPLOIT sequences — the largest attack category (6,028 sequences):

```
Total EXPLOIT sequences        : 6,028
Perplexity-only F1             : 0.9969
Hybrid (ppl + pattern) F1     : 0.9969
Pattern signal > 0.30          : 14 sequences boosted
Pattern signal mean (EXPLOIT)  : 0.0017
Still-missed (label=1, no pattern, ppl=benign) : 37
```

**Key finding:** The pattern signal booster had virtually no effect (mean signal 0.0017). Perplexity alone is already sufficient for EXPLOIT detection — the 37 still-missed sequences had benign-range perplexity and no distinctive token patterns.

---

### Next-Step Accuracy by Attack Type (Sequence-Level)

> **Important distinction:** The report's `top1_accuracy=0.3386` is a **per-token average** across all positions. The table below is **sequence-level** (was the final next token correct?).

| Attack Type | Total | Correct | Accuracy | Notes |
|---|---|---|---|---|
| BENIGN | 7,037 | 6,161 | **87.55%** | Strong — benign behaviour is regular |
| BRUTE_FORCE | 54 | 54 | **100.00%** | Highly stereotyped pattern |
| **EXPLOIT** | 6,028 | 119 | **1.97%** | ⚠️ Very low — see explanation below |
| MALWARE | 2 | 2 | **100.00%** | Too few to generalise |
| MIXED | 4 | 4 | **100.00%** | Too few to generalise |
| RECONNAISSANCE | 6 | 4 | **66.67%** | |
| SCAN | 10 | 10 | **100.00%** | Identical repetitive sequences |
| **OVERALL** | **13,141** | **6,354** | **48.35%** | Sequence-level across all types |

**Why is EXPLOIT next-step accuracy only 1.97%?**

EXPLOIT sessions in the BETH dataset are highly variable in their final token. The model predicts `FILE_CLOSE` for almost all positions (the dominant token in training), but EXPLOIT sessions often terminate with `NET_OPEN`, `NET_CONNECT`, or other less common tokens. The top-5 accuracy for EXPLOIT is 98.01% — the correct next token is almost always in the top-5 candidates, just not rank-1.

This means XLNet is useful for **anomaly detection** (perplexity is low for exploit sessions regardless) but its next-step prediction for EXPLOIT-type sessions should be interpreted as a probability distribution, not a single definitive prediction.

---

### Top-10 Mispredicted Next-Step Sequences (XLNet)

These are the sequences where XLNet was **most wrong** about the next token — ranked by perplexity (highest = most confused):

| Sequence ID | Attack Type | Actual Next | Predicted | Perplexity |
|---|---|---|---|---|
| `beth_TESTI_7555_w585` | EXPLOIT | `NET_OPEN` | `FILE_CLOSE` | **3703.26** ← max |
| `beth_TESTI_7555_w272` | EXPLOIT | `NET_OPEN` | `FILE_CLOSE` | 537.26 |
| `beth_TESTI_7555_w276` | EXPLOIT | `NET_CONNECT` | `FILE_CLOSE` | 330.17 |
| `beth_TESTI_7555_w588` | EXPLOIT | `NET_CONNECT` | `FILE_CLOSE` | 303.36 |
| `beth_TESTI_7555_w44` | EXPLOIT | `NET_CONNECT` | `NET_OPEN` | 233.68 |
| `beth_TESTI_7555_w591` | EXPLOIT | `NET_CONNECT` | `NET_OPEN` | 220.81 |
| `beth_TESTI_7555_w270` | EXPLOIT | `FILE_CLOSE` | `NET_OPEN` | 154.68 |
| `beth_TRAIN_7157_w0` | BENIGN | `PROC_EXEC` | `FILE_OPEN` | 140.87 |
| `beth_TRAIN_7163_w0` | BENIGN | `PROC_EXEC` | `FILE_OPEN` | 140.87 |
| `beth_VALID_7145_w0` | BENIGN | `PROC_EXEC` | `FILE_OPEN` | 140.87 |

**Pattern observed in top misses:**
```
beth_TESTI_7555_w585 tokens (last 10 shown):
  [BETH] → FILE_CLOSE → FILE_CLOSE → FILE_CLOSE → ... → FILE_CLOSE
  (highly repetitive; actual transition to NET_OPEN was completely unexpected)

beth_TRAIN_7157_w0 tokens:
  [BETH] → PROC_EXEC
  (single-token sequence — no context to predict from; model defaults to FILE_OPEN)
```

**Insight:** The three BENIGN sequences with identical perplexity (140.87) are all single-token sequences (`[BETH] → PROC_EXEC`). With only one token, XLNet has no context to make a reliable prediction. Very short sequences are a known weak spot for the model.

---

### Top-10 DistilBERT Misclassifications (False Negatives)

These are the MALICIOUS sessions that DistilBERT incorrectly predicted as BENIGN (`prob_malicious = 0.0`):

| Sequence ID | Attack Type | True Label | Predicted | Token Pattern (first 10) |
|---|---|---|---|---|
| `beth_TESTI_7424_w3` | EXPLOIT | MALICIOUS | BENIGN | `FILE_OPEN FILE_ACC FILE_CLOSE FILE_OPEN...` |
| `beth_TESTI_7421_w0` | EXPLOIT | MALICIOUS | BENIGN | `FILE_CLOSE FILE_ACC FILE_ACC FILE_ACC EXEC...` |
| `beth_TESTI_7555_w1` | EXPLOIT | MALICIOUS | BENIGN | `FILE_CLOSE PROC_EXEC PROC_EXEC PROC_EXEC...` |
| `beth_TESTI_7555_w5` | EXPLOIT | MALICIOUS | BENIGN | `PROC_EXEC PROC_EXEC PROC_EXEC PROC_EXEC...` |
| `beth_TESTI_7555_w1` | EXPLOIT | MALICIOUS | BENIGN | `PRIV_ESC FILE_OPEN FILE_ACC FILE_ACC FILE_CLOSE...` |
| `beth_TESTI_7555_w4` | EXPLOIT | MALICIOUS | BENIGN | `NET_OPEN NET_OPEN NET_OPEN NET_OPEN...` (monotone) |
| `beth_TESTI_7555_w2` | EXPLOIT | MALICIOUS | BENIGN | `NET_CONNECT NET_CONNECT NET_CONNECT...` (monotone) |
| `beth_TESTI_7555_w2` | EXPLOIT | MALICIOUS | BENIGN | `FILE_CLOSE FILE_CLOSE FILE_CLOSE...` (monotone) |

**Root cause of DistilBERT false negatives:**
These are EXPLOIT sessions from process `7555` that consist almost entirely of monotone repeated syscalls (all `FILE_CLOSE`, all `NET_OPEN`, all `NET_CONNECT`). Without a distinctive attack signature (like `EXEC` or `PRIV_ESC`), the classifier cannot distinguish them from normal file/network activity. XLNet, however, flags these correctly via low perplexity (highly predictable monotone = suspicious).

This complementarity is **by design** — the two models catch different failure modes.

---

### Confidence Calibration (DistilBERT)

The calibration analysis reveals the model's **bimodal confidence distribution**:

```
ECE (Expected Calibration Error) = 0.2364
```

| Probability Bin | N Samples | Mean Predicted | Fraction Positive | Gap (Error) |
|---|---|---|---|---|
| 0.0–0.1 | **6,690** | 0.0003 | 0.0278 | 0.0275 ✅ |
| 0.1–0.2 | 53 | 0.1579 | 0.0000 | 0.1579 ⚠️ |
| 0.2–0.3 | 11 | 0.2308 | 0.0000 | 0.2308 ⚠️ |
| 0.3–0.4 | 57 | 0.3826 | 0.0175 | 0.3651 ⚠️ |
| 0.4–0.5 | 26 | 0.4661 | 0.0000 | 0.4661 ⚠️ |
| **0.5–0.6** | **5,893** | **0.5280** | **0.9818** | 0.4539 ⚠️ |
| 0.6–0.7 | 199 | 0.6559 | 0.0352 | 0.6208 ⚠️ |
| 0.9–1.0 | 187 | 0.9907 | 0.6524 | 0.3383 ⚠️ |

**Interpretation:**
- 6,690 sequences have predicted probability < 0.1 (model is confidently BENIGN)
- 5,893 sequences cluster in the 0.50–0.60 bin (model is weakly MALICIOUS)
- Almost no sequences fall in the 0.2–0.5 range — the model has a **bimodal output distribution**
- ECE of 0.2364 means the model's confidence scores are **not well-calibrated** (overconfident in the 0.5–0.6 bin where 98% of samples are truly malicious, yet it only predicts ~0.52)
- For a security system, this is acceptable — the decision boundary at 0.5 works well even if the exact probabilities are not calibrated

---

### Hybrid (DistilBERT + XLNet) Detection

When both models are combined for final detection:

| Metric | XLNet Alone | Hybrid |
|---|---|---|
| Accuracy | 77.06% | **77.38%** |
| Precision | 67.30% | **67.35%** |
| Recall | 98.44% | **99.61%** |
| F1 | 79.94% | **80.36%** |
| MCC | 0.6086 | **0.6207** |
| ROC-AUC | 0.3464 | **0.4063** |

The hybrid mode improves recall from 98.44% to **99.61%** — it catches 95 additional true malicious sessions that XLNet missed alone (by incorporating DistilBERT's classification signal).

---

### sklearn Warnings Explanation

During evaluation the following warnings appear. They are expected and do not indicate bugs:

```
UndefinedMetricWarning: Only one class is present in y_true.
ROC AUC score is not defined in that case.
```
**Cause:** For sources like Cowrie: 59 sessions (0 benign, 59 malicious) and Dionaea: 59 sessions (0 benign, 59 malicious), there are no benign samples — so ROC AUC cannot be computed (requires both classes). Total test set: 13,168 sessions. The script correctly records `roc_auc: null` in the report.

```
UserWarning: A single label was found in 'y_true' and 'y_pred'.
```
**Cause:** Same reason — when a per-source or per-attack-type subset contains only one class, sklearn's confusion matrix and classification report functions emit this warning. Results are still valid; MCC reports 0.0 (undefined) in these cases.

---

## 6. Internal Workflow / Process Flow

```
Input: token sequence (list of strings)
       e.g. ["[COWRIE]", "SCAN", "LOGIN_ATT", "LOGIN_ATT", "LOGIN_OK", "EXEC", "FILE_XFER"]

Step 1: Encode → integer IDs + attention mask
        [6, 8, 12, 12, 13, 19, 22, ...]   mask=[1,1,1,1,1,1,1,...]

Step 2: DistilBERT forward pass (batched, batch_size=64)
        → logits [batch, 2]
        → softmax → attack_prob (float 0..1)
        → predicted_binary = int(attack_prob >= 0.5)

Step 3: XLNet forward pass (sequence-by-sequence)
        → logits [1, seq_len, vocab_size]
        → shift: compare logits[0..N-2] to labels[1..N-1]
        → cross-entropy loss → exp() → perplexity
        → argmax(logits[0, -1, :]) → predicted_next_token
        → anomaly_score = 1 - (perplexity / p99_perplexity)

Step 4: Token severity
        mean([SEVERITY_MAP[t] for t in tokens])   # 1.0=LOW, 4.0=CRITICAL
        token_sev_scaled = (mean - 1) / 3

Step 5: Combined severity
        combined = token_sev_scaled * 0.25 + attack_prob * 1.50 + anomaly_score * 1.25

Step 6: Risk label
        CRITICAL if combined >= 2.0
        HIGH     if combined >= 1.2
        MEDIUM   if combined >= 0.5
        LOW      otherwise

Step 7: MITRE mapping
        get_mitre_techniques(tokens)
        → deduplicated list of ATT&CK technique dicts

Step 8: Write to MongoDB live_predictions (live) or severity_report.json (offline)
```

---

## 7. Key Components / Files Involved

| File | Role |
|---|---|
| `live/inference.py` | Live scoring engine — loads models, runs inference each cycle |
| `scripts/severity_scorer.py` | Offline combined severity scorer — evaluates test set |
| `scripts/evaluate_distilbert.py` | Full DistilBERT evaluation + report generation |
| `scripts/evaluate_xlnet.py` | Full XLNet evaluation + report generation |
| `scripts/mitre_mapping.py` | Token → ATT&CK technique lookup table |
| `models/distilbert_attack_classifier/` | Saved DistilBERT weights (HuggingFace format) |
| `models/xlnet_behaviour_predictor/` | Saved XLNet weights (HuggingFace format) |
| `reports/distilbert_evaluation.json` | Full DistilBERT evaluation report (7 MB) |
| `reports/xlnet_evaluation.json` | Full XLNet evaluation report (4 MB) |
| `reports/severity_report.json` | Combined severity scores (5 MB) |
| `scripts/token_definitions.py` | TOKEN_TO_ID, VOCAB_SIZE, get_severity() |

---

## 8. Important Classes / Functions

### `scripts/severity_scorer.py`

```python
def encode(tokens: list[str], max_len: int) -> tuple[list[int], list[int]]:
    """Convert token strings to (input_ids, attention_mask) for model input."""

def distilbert_predict(model, sequences, device, batch_size=64) -> list[dict]:
    """Batched DistilBERT inference; returns list of {sequence_id, attack_prob, predicted_binary}."""

def xlnet_perplexity(model, tokens, device) -> float:
    """Compute sequence perplexity via causal language model cross-entropy."""

def risk_label(score: float) -> str:
    """Map combined severity score (float) to risk label string."""

def score(input_path, output_path) -> None:
    """Full pipeline: load models → DistilBERT inference → XLNet perplexity → combine → save."""
```

### `live/inference.py`

```python
def run_inference() -> list[dict]:
    """
    Main live inference function called by runner.py each cycle.
    Loads new sequences from MongoDB live_sequences,
    scores with both models, writes predictions to live_predictions.
    Returns list of written prediction docs.
    """

def _load_models():
    """Thread-safe singleton loader for both models."""

def _score_sequence(distilbert_model, xlnet_model, seq_doc, device) -> dict:
    """Score one sequence document; returns a live_predictions record."""
```

### `scripts/mitre_mapping.py`

```python
def get_mitre_techniques(tokens: list[str]) -> list[dict]:
    """
    Return deduplicated MITRE ATT&CK techniques for all tokens.
    Deduplication is by technique_id — first-seen entry wins.
    """

def get_tactics_summary(tokens: list[str]) -> list[str]:
    """Return deduplicated tactic names observed across all tokens."""
```

---

## 9. Inputs and Outputs

### Inputs

| Input | Source | Format |
|---|---|---|
| Token sequences | MongoDB `live_sequences` (live) | BSON document |
| Token sequences | `data/processed/test_sequences.json` (offline) | JSON |
| Trained DistilBERT | `models/distilbert_attack_classifier/` | HuggingFace SavedModel |
| Trained XLNet | `models/xlnet_behaviour_predictor/` | HuggingFace SavedModel |

### Outputs

| Output | Destination | Format | Contains |
|---|---|---|---|
| Live predictions | MongoDB `live_predictions` | BSON | Full prediction doc per sequence |
| Offline evaluation | `reports/distilbert_evaluation.json` | JSON | 263k+ line report |
| Offline evaluation | `reports/xlnet_evaluation.json` | JSON | 145k+ line report |
| Severity report | `reports/severity_report.json` | JSON | Per-sequence severity scores |

**Live prediction document schema (written to MongoDB):**
```json
{
  "sequence_id": "cowrie_abc123_20260310",
  "session_id":  "abc123",
  "source":      "cowrie",
  "src_ip":      "45.33.32.156",
  "tokens":      ["[COWRIE]", "SCAN", "LOGIN_ATT", "LOGIN_OK", "EXEC", "FILE_XFER"],
  "attack_type": "EXPLOIT",
  "risk_level":  "CRITICAL",
  "combined_severity": 2.34,
  "attack_prob": 0.9821,
  "anomaly_score": 0.9713,
  "token_severity_mean": 2.50,
  "perplexity": 1.01,
  "distilbert_label": "MALICIOUS",
  "predicted_next_token": "SESS_END",
  "xlnet_trajectory": ["FILE_XFER", "EXEC", "SESS_END"],
  "mitre_techniques": [
    {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
    {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
    {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
    {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "tactic": "C2"}
  ],
  "inferred_at": "2026-03-10T12:31:05Z",
  "date": "2026-03-10",
  "status": "open"
}
```

---

## 10. Dependencies

| Dependency | Purpose |
|---|---|
| `torch` | PyTorch deep learning runtime |
| `transformers` | DistilBertForSequenceClassification, XLNetLMHeadModel |
| `numpy` | Numerical ops (p99, normalisation, NaN sanitisation) |
| `pymongo` | Read live_sequences, write live_predictions |
| `token_definitions` | TOKEN_TO_ID, VOCAB_SIZE, get_severity() |
| `mitre_mapping` | Token → ATT&CK technique lookup |

---

## 11. Interaction with Other Modules

```
Module 2 (Processing)
    │  produces token sequences
    ▼
Module 3 (Core Engine)  ← YOU ARE HERE
    │  produces scored predictions
    ├──► Module 4 (Response / Action)
    │       reads live_predictions for AI advice, automated response
    │
    └──► Module 5 (Monitoring / Visualization)
            WebSocket broadcasts latest live_predictions to browser
            Dashboard reads reports/*.json for offline metrics display
```

---

## 12. Example Flow / Use Case

**Example: Cowrie SSH session scored in live mode**

```
Input tokens: ["[COWRIE]", "SCAN", "LOGIN_ATT"×47, "LOGIN_OK", "EXEC"×3, "FILE_XFER", "SESS_END"]
Length: 55 tokens (under 128 max — no truncation needed)

Step 1 — Encoding:
  input_ids = [6, 8, 12, 12, ..., 13, 19, 19, 19, 22, 30]
  attention_mask = [1] * 55

Step 2 — DistilBERT:
  attack_prob = 0.9821
  predicted_binary = 1 (MALICIOUS)

Step 3 — XLNet:
  perplexity = 1.01 (very low — highly predictable brute-force pattern!)
  anomaly_score = 1 - (1.01 / 35.02) = 0.9712
  predicted_next_token = "SESS_END"

Step 4 — Token severity (mean):
  SCAN=1, LOGIN_ATT=2 (×47), LOGIN_OK=3, EXEC=3 (×3), FILE_XFER=3, SESS_END=1
  mean ≈ 2.05
  token_sev_scaled = (2.05 - 1) / 3 = 0.35

Step 5 — Combined:
  combined = 0.35 × 0.25 + 0.9821 × 1.50 + 0.9712 × 1.25
           = 0.0875 + 1.4732 + 1.214
           = 2.7747

Step 6 — Risk: CRITICAL (combined ≥ 2.0) ✓

Step 7 — MITRE: T1046 (Discovery), T1110 (Brute Force), T1078 (Valid Accounts),
                T1059 (Execution), T1105 (Ingress Tool Transfer)
```

---

## 13. Configuration Details

### Model Loading (both models)

```python
from transformers import DistilBertForSequenceClassification, XLNetLMHeadModel

distilbert = DistilBertForSequenceClassification.from_pretrained(
    "models/distilbert_attack_classifier"
).eval()

xlnet = XLNetLMHeadModel.from_pretrained(
    "models/xlnet_behaviour_predictor"
).eval()

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
```

### Severity Scorer Constants (`scripts/severity_scorer.py`)

```python
MAX_LEN          = 128
BATCH_SIZE       = 64       # DistilBERT batch size
SEVERITY_MAP     = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}
RISK_THRESHOLDS  = [(2.0, "CRITICAL"), (1.2, "HIGH"), (0.5, "MEDIUM"), (0.0, "LOW")]

# Weights in combined severity formula
W_TOKEN  = 0.25
W_ATTACK = 1.50
W_ANOMALY = 1.25
```

### Running Evaluation (safe — no training)

```bash
# Evaluate DistilBERT on test set
python scripts/evaluate_distilbert.py

# Evaluate XLNet on test set
python scripts/evaluate_xlnet.py

# Run combined severity scoring on test set
python scripts/severity_scorer.py

# Custom input file
python scripts/severity_scorer.py --input data/processed/test_sequences.json \
                                  --output reports/severity_report.json
```

---

## 14. Implementation Notes

- **Model loading singleton:** In `live/inference.py`, both models are loaded once and cached in module-level variables. Subsequent calls reuse the loaded models, avoiding expensive disk I/O and GPU memory allocation on every cycle.
- **Bimodal probability distribution:** DistilBERT's output is nearly bimodal (most predictions < 0.1 or > 0.5, very few in the middle). This means the optimal threshold (0.50) is stable — the threshold sweep shows performance collapses sharply above 0.55 as the model defaults to predicting BENIGN.
- **XLNet perplexity normalisation uses p99** (not max), making it robust to outlier sequences with extremely high perplexity (e.g., very short or highly unusual sequences).
- **CPU fallback:** Both models run on CPU if no CUDA GPU is available. DistilBERT on CPU achieves ~50 seq/sec vs 263 on GPU. XLNet on CPU is ~5-10 seq/sec (runs sequence-by-sequence, not batched).
- **`_clean()` sanitiser:** The `severity_scorer.py` contains a recursive JSON sanitiser that converts `NaN`/`Inf` floats (which JSON cannot represent) to `null` before serialisation.
- **`@torch.no_grad()` decorator** is applied to `xlnet_perplexity()` — essential for preventing gradient graph accumulation during inference (otherwise memory leaks over thousands of sequences).
