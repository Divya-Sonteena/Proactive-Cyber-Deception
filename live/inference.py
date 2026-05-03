#!/usr/bin/env python3
"""
live/inference.py — Live ML inference engine.

Loads the trained DistilBERT (attack classifier) and XLNet (behaviour
predictor) models once and processes all unscored sequences from:
    data/live_processed/sequences/YYYY-MM-DD.json

For each new sequence it computes:
  - attack_prob       (DistilBERT)
  - predicted_binary  (DistilBERT threshold 0.5)
  - anomaly_score     (XLNet perplexity, inverted)
  - predicted_next_token (XLNet argmax over next position)
  - combined_severity (fusion formula — same as offline severity_scorer)
  - risk_level        (LOW / MEDIUM / HIGH / CRITICAL)

Results are appended idempotently to:
    data/live_processed/predictions/YYYY-MM-DD.json

Models are loaded as module-level singletons on first import to avoid
reloading weights on every call.
"""

import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

import torch  # type: ignore[import]
import torch.nn as nn  # type: ignore[import]
import numpy as np  # type: ignore[import]
from transformers import DistilBertForSequenceClassification, XLNetLMHeadModel  # type: ignore[import]

ROOT         = Path(__file__).resolve().parent.parent
DISTILBERT_DIR = ROOT / "models" / "distilbert_attack_classifier"
XLNET_DIR      = ROOT / "models" / "xlnet_behaviour_predictor"

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared_db import get_collection  # type: ignore[import]

sys.path.insert(0, str(ROOT / "scripts"))
from token_definitions import TOKEN_TO_ID, ID_TO_TOKEN, VOCAB_SIZE, get_severity  # noqa: E402  # type: ignore[import]
from mitre_mapping import get_mitre_techniques  # noqa: E402  # type: ignore[import]
# Import scoring constants from their authoritative source (severity_scorer.py)
from severity_scorer import RISK_THRESHOLDS, SEVERITY_MAP  # noqa: E402  # type: ignore[import]

# ── Optional AI prevention (Groq) ───────────────────────────────────────────
try:
    sys.path.insert(0, str(ROOT / "flask_app"))
    from ai_prevention import get_ai_prevention as _get_ai_prevention  # type: ignore[import]
    _AI_PREVENTION_OK = True
except Exception:
    _AI_PREVENTION_OK = False
    def _get_ai_prevention(doc: dict) -> dict:  # type: ignore
        return {"prevention_summary": "", "source": "unavailable"}


# Scoring constants imported from scripts/severity_scorer.py (single source of truth)
# RISK_THRESHOLDS = [(2.0, "CRITICAL"), (1.2, "HIGH"), (0.5, "MEDIUM"), (0.0, "LOW")]
# SEVERITY_MAP    = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}
MAX_LEN       = 128

# ── Attack-type rule tables (module-level constants, not re-created per call) ──
# Attack types that are definitionally non-malicious (no auth, no payload).
_ALWAYS_BENIGN = frozenset({
    "SCAN", "RECON_PASSIVE", "RECON_FINGERPRINT", "RECON_PROBE", "RECON_TUNNEL",
    "RECONNAISSANCE", "PORT_SCAN", "SERVICE_PROBE", "MIXED",
})

# Maximum risk each capped attack type can ever be assigned.
_RISK_CEILING: dict[str, tuple[str, float]] = {
    "SCAN":              ("LOW",    0.40),
    "PORT_SCAN":         ("LOW",    0.40),
    "SERVICE_PROBE":     ("LOW",    0.40),
    "RECON_PASSIVE":     ("MEDIUM", 1.10),
    "RECON_FINGERPRINT": ("MEDIUM", 1.10),
    "RECON_PROBE":       ("MEDIUM", 1.10),
    "RECON_TUNNEL":      ("MEDIUM", 1.10),
    "RECONNAISSANCE":    ("MEDIUM", 1.10),
    "MIXED":             ("MEDIUM", 1.10),
}
_RISK_ORDER           = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_BENIGN_ATTACK_TYPES  = frozenset(_RISK_CEILING.keys())

# ── Severity FLOOR: minimum guaranteed risk for confirmed-malicious types ──────
# XLNet perplexity alone is not reliable for EXPLOIT/BRUTE_FORCE/MALWARE because
# their syscall token sequences look identical to benign BETH traces on perplexity.
# Applying a floor ensures they are never classified LOW/MEDIUM.
_SEVERITY_FLOOR: dict[str, tuple[str, float]] = {
    # attack_type       → (min_risk_level,  min_combined_severity)
    "EXPLOIT":           ("HIGH",     1.25),  # always ≥ HIGH
    "BRUTE_FORCE":       ("HIGH",     1.25),  # many login attempts
    "MALWARE":           ("CRITICAL", 2.05),  # malware payload
    "EXPLOITATION":      ("HIGH",     1.25),  # Dionaea exploitation
    "LATERAL":           ("HIGH",     1.25),  # lateral movement
    "POST_EXPLOIT":      ("CRITICAL", 2.05),  # post-exploitation
    "RANSOMWARE":        ("CRITICAL", 2.05),  # ransomware
}

# ── Token-pattern exploit signal (no-retrain supplement to XLNet) ──────────────
# Token combos that reliably indicate exploitation even when XLNet assigns low
# perplexity (repetitive BETH syscall traces). Each matching pattern adds weight;
# result is clamped to 1.0 to stay within the anomaly_score range.
_EXPLOIT_PATTERNS: list[tuple[frozenset, float]] = [
    (frozenset({"MEM_PROT",  "EXEC"}),                    0.40),  # shellcode injection
    (frozenset({"MEM_PROT",  "PROC_EXEC"}),               0.40),
    (frozenset({"PRIV_ESC",  "NET_CONNECT"}),              0.40),  # priv-esc + C2
    (frozenset({"PRIV_ESC",  "NET_SEND"}),                 0.35),
    (frozenset({"MEM_MAP",   "EXEC"}),                     0.30),  # code injection / ROP
    (frozenset({"MEM_MAP",   "PROC_EXEC"}),                0.30),
    (frozenset({"EXPLOITATION"}),                          0.55),  # Dionaea explicit
    (frozenset({"FILE_WRITE","FILE_DEL","EXEC"}),           0.45),  # dropper pattern
    (frozenset({"FILE_WRITE","FILE_DEL","PROC_EXEC"}),      0.45),
    (frozenset({"NET_RECV",  "FILE_WRITE"}),               0.30),  # exfil / download
    (frozenset({"PRIV_CHG",  "FILE_DEL"}),                 0.30),  # anti-forensics
    (frozenset({"PRIV_ESC"}),                              0.20),  # priv escalation alone
    (frozenset({"MALWARE"}),                               0.55),  # Dionaea malware token
]


def _token_pattern_signal(tokens: list[str]) -> float:
    """Return a 0–1 exploit signal from rule-based token-pattern matching.

    OPTIMIZED: Early termination when max score reached.
    Supplements XLNet perplexity: catches EXPLOIT sequences whose perplexity
    is indistinguishable from benign (repetitive BETH syscall traces).
    Each matching pattern contributes an additive weight; result is clamped to 1.0.
    """
    token_set = frozenset(tokens)
    score = 0.0
    
    # Process patterns sorted by weight (descending) for early termination
    # When high-weight patterns match, we can exit early since score ≥ 1.0
    for pattern, weight in _EXPLOIT_PATTERNS:
        if pattern.issubset(token_set):
            score += weight
            # Early termination: if we've hit max, no need to check remaining patterns
            if score >= 1.0:
                return 1.0
    
    return score


# ── Tokens that must NEVER be predicted as next-token ────────────────────────
# Structural / padding tokens are artefacts of the training format, not steps.
_EXCLUDED_NEXT_TOKENS = frozenset({
    "PAD", "UNK", "CLS", "SEP",
    "[BETH]", "[COWRIE]", "[DIONAEA]",
    "SESS_END",   # session-end is structural, not a real next step
})

# Source-aware vocab: only predict tokens that make sense per source.
_COWRIE_VALID_NEXT = frozenset({
    "SCAN", "RECON", "LOGIN_ATT", "LOGIN_OK",
    "EXEC", "EXEC_FAIL", "FILE_XFER", "TUNNEL",
})
_DIONAEA_VALID_NEXT = frozenset({
    "SCAN", "RECON", "EXPLOITATION", "MALWARE", "FILE_XFER",
})
# Full fallback: any non-excluded token
_ALL_VALID_NEXT = frozenset(ID_TO_TOKEN.values()) - _EXCLUDED_NEXT_TOKENS

# ── Device ────────────────────────────────────────────────────────────────
_DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ── Model singletons (loaded on first call) ────────────────────────────────
_distilbert: DistilBertForSequenceClassification | None = None
_xlnet: XLNetLMHeadModel | None = None
_cached_ppl_p99: float | None = None


def _get_models():
    global _distilbert, _xlnet
    if _distilbert is None:
        if not DISTILBERT_DIR.exists():
            raise FileNotFoundError(f"DistilBERT model not found: {DISTILBERT_DIR}")
        _distilbert = (
            DistilBertForSequenceClassification.from_pretrained(str(DISTILBERT_DIR))
            .to(_DEVICE).eval()
        )
    if _xlnet is None:
        if not XLNET_DIR.exists():
            raise FileNotFoundError(f"XLNet model not found: {XLNET_DIR}")
        _xlnet = (
            XLNetLMHeadModel.from_pretrained(str(XLNET_DIR))
            .to(_DEVICE).eval()
        )
    return _distilbert, _xlnet


def models_loaded() -> bool:
    """Health-check: return True if both models are loaded into memory.

    Called by runner.py before starting the pipeline loop to confirm
    both DistilBERT and XLNet are loaded and on the correct device.
    """
    return _distilbert is not None and _xlnet is not None


# ── Utilities ─────────────────────────────────────────────────────────────

def _encode(tokens: list[str]) -> tuple[list[int], list[int]]:
    """Token strings → (input_ids, attention_mask), tail-truncated to MAX_LEN."""
    unk = TOKEN_TO_ID.get("UNK", 0)
    ids = [TOKEN_TO_ID.get(t, unk) for t in tokens][-MAX_LEN:]
    return ids, [1] * len(ids)


def _risk_label(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


# ── DistilBERT inference ───────────────────────────────────────────────────

@torch.no_grad()
def _distilbert_score(model, tokens: list[str]) -> tuple[float, int]:
    """Return (attack_prob, predicted_binary) for one token sequence.

    Uses temperature=5.0 to soften overconfident predictions, and a
    raised threshold of 0.65 (not 0.5) to counteract training-label bias.
    """
    ids, mask = _encode(tokens)
    if not ids:
        return 0.0, 0
    t_ids    = torch.tensor([ids],  dtype=torch.long, device=_DEVICE)
    t_mask   = torch.tensor([mask], dtype=torch.long, device=_DEVICE)
    logits   = model(input_ids=t_ids, attention_mask=t_mask).logits
    # Temperature scaling softens overconfident 0%/100% predictions
    temperature = 5.0
    probs    = torch.softmax(logits / temperature, dim=-1).cpu().numpy()[0]  # type: ignore
    prob     = float(probs[1])
    # Raised threshold: model was trained on over-aggressive labels
    # (SCAN+LOGIN_OK was mislabelled EXPLOIT=malicious), so 0.65 is fairer
    return round(prob, 4), int(prob >= 0.65)


# ── XLNet perplexity + next-token prediction ──────────────────────────────

@torch.no_grad()
def _xlnet_score(model, tokens: list[str], source: str = "unknown") -> tuple[float, str]:
    """Return (perplexity, predicted_next_token) for one token sequence.

    Strips trailing SESS_END so XLNet predicts what comes *during* an active
    session. Next-token uses temperature-scaled top-k sampling restricted to
    source-appropriate tokens to avoid argmax always collapsing to EXEC/SCAN.
    """
    # Remove trailing SESS_END
    active_tokens = list(tokens)
    while active_tokens and active_tokens[-1] == "SESS_END":
        active_tokens.pop()

    if not active_tokens:
        return 0.0, "SCAN"

    ids, mask = _encode(active_tokens)
    if len(ids) < 2:
        # Single-token sequence: next step via heuristic (not model)
        last = active_tokens[-1]
        heuristic = {
            "SCAN": "RECON", "RECON": "LOGIN_ATT",
            "LOGIN_ATT": "LOGIN_ATT", "LOGIN_OK": "EXEC",
            "EXEC": "FILE_XFER", "EXEC_FAIL": "EXEC_FAIL",
            "FILE_XFER": "EXEC", "EXPLOITATION": "MALWARE",
        }
        return 0.0, heuristic.get(last, last)

    t_ids  = torch.tensor([ids],  dtype=torch.long, device=_DEVICE)
    t_mask = torch.tensor([mask], dtype=torch.long, device=_DEVICE)
    logits = model(input_ids=t_ids, attention_mask=t_mask).logits  # (1, seq, vocab)

    # Perplexity (causal shift)
    valid_len    = len(ids) - 1
    shift_logits = logits[0, :valid_len, :]
    shift_labels = t_ids[0, 1:valid_len + 1]
    loss         = nn.CrossEntropyLoss()(shift_logits, shift_labels).item()
    ppl          = round(math.exp(min(loss, 100)), 4)  # type: ignore

    # ── Next-token: temperature top-k over source-valid tokens ────────────
    if source == "cowrie":
        valid_set = _COWRIE_VALID_NEXT
    elif source == "dionaea":
        valid_set = _DIONAEA_VALID_NEXT
    else:
        valid_set = _ALL_VALID_NEXT

    temperature = 1.5   # soften so argmax doesn't always win
    next_probs  = torch.softmax(logits[0, -1, :].float() / temperature, dim=-1).cpu()

    # Zero out excluded / out-of-source-vocab tokens
    mask_t = torch.zeros(len(ID_TO_TOKEN))
    for tid, tok in ID_TO_TOKEN.items():
        if tok in valid_set:
            mask_t[tid] = next_probs[tid]

    if mask_t.sum() == 0:  # fallback: any non-excluded token
        for tid, tok in ID_TO_TOKEN.items():
            if tok not in _EXCLUDED_NEXT_TOKENS:
                mask_t[tid] = next_probs[tid]

    # Top-k (k=5); skip tokens identical to last observed to enforce diversity
    last_obs = active_tokens[-1]
    k = min(5, int((mask_t > 0).sum().item()))
    top_vals, top_ids_t = torch.topk(mask_t, k)
    next_token = "SCAN"  # safe fallback
    for i in range(k):
        candidate = ID_TO_TOKEN.get(int(top_ids_t[i].item()), "UNK")
        if candidate != last_obs and candidate not in _EXCLUDED_NEXT_TOKENS:
            next_token = candidate
            break
    else:
        # All candidates same as last obs; just take highest valid
        next_token = ID_TO_TOKEN.get(int(top_ids_t[0].item()), "SCAN")

    return ppl, next_token


def _load_predictions(date: str) -> dict:
    pred_col = get_collection("live_predictions")
    return {"date": date, "predictions": list(pred_col.find({"date": date}, {"_id": 0}))}  # type: ignore


# ── Main inference function ────────────────────────────────────────────────

def run_inference(date: str | None = None, ppl_p99: float | None = None) -> list[dict]:
    """
    Score all un-processed sequences from today's sequences file.

    Args:
        date    : YYYY-MM-DD  (defaults to today UTC)
        ppl_p99 : normalisation constant for perplexity (computed if None)

    Returns:
        List of newly added prediction dicts.
    """
    date      = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    seq_col = get_collection("live_sequences")
    all_seqs = list(seq_col.find({"date": date}, {"_id": 0}))
    if not all_seqs:
        return []

    pred_data    = _load_predictions(date)
    existing_ids = {p["sequence_id"] for p in pred_data.get("predictions", [])}
    new_seqs     = [s for s in all_seqs if s["sequence_id"] not in existing_ids]

    if not new_seqs:
        return []

    d_model, x_model = _get_models()

    # Compute all perplexities first for p99 normalisation
    ppls: list[float] = []
    for seq in new_seqs:
        ppl, _ = _xlnet_score(x_model, seq.get("tokens", []), source=seq.get("source", "unknown"))
        ppls.append(ppl)

    global _cached_ppl_p99
    if ppl_p99 is None:
        if _cached_ppl_p99 is None:
            try:
                report_path = ROOT / "reports" / "severity_report.json"
                if report_path.exists():
                    with open(report_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        _cached_ppl_p99 = data.get("ppl_p99_norm")
            except Exception:
                pass
        
        if _cached_ppl_p99 is not None:
            ppl_p99 = _cached_ppl_p99
        else:
            # Fallback if report missing (will likely be 0.0 anomaly for batch size 1)
            ppl_p99 = max(float(np.percentile(ppls, 99)) if ppls else 1.0, 1e-6)  # type: ignore

    new_predictions: list[dict] = []
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for idx, seq in enumerate(new_seqs):
        tokens     = seq.get("tokens", [])
        sid        = seq.get("sequence_id", f"seq_{idx}")

        # DistilBERT
        attack_prob, db_flag = _distilbert_score(d_model, tokens)

        # Rule-based label from sequence_builder (0=benign, 1=malicious)
        # Uses the corrected _classify() logic — accurate now.
        seq_label = seq.get("label", 1)  # default malicious if unknown

        atk_type = seq.get("attack_type", "UNKNOWN")
        if atk_type in _ALWAYS_BENIGN:
            db_flag     = 0       # force BENIGN
            attack_prob = min(attack_prob, 0.35)  # keep numeric consistent with label

        # XLNet — pass source for source-aware next-token prediction
        source_type = seq.get("source", "unknown")
        ppl, next_token = _xlnet_score(x_model, tokens, source=source_type)

        # Anomaly score: low perplexity = predictable = more suspicious.
        # Down-weight very short sequences because their low perplexity is a
        # length artefact, NOT genuine suspicious predictability.
        active_len  = len([t for t in tokens if t != "SESS_END"])
        norm_ppl    = min(ppl / ppl_p99, 1.0)
        raw_anomaly = 1.0 - norm_ppl
        length_weight = min(active_len / 3.0, 1.0)  # 0..1 ramp over first 3 tokens
        anomaly_score = round(raw_anomaly * length_weight, 4)
        xlnet_flag    = 1 if anomaly_score > 0.5 else 0

        # Token severity mean — exclude SESS_END (structural, not behavioural)
        sev_scores = [SEVERITY_MAP.get(get_severity(t), 1.0) for t in tokens
                      if t != "SESS_END"]
        token_sev  = float(np.mean(sev_scores)) if sev_scores else 1.0  # type: ignore

        # Fusion (mirrors severity_scorer.py)
        combined = ((token_sev - 1.0) / 3.0) * 0.25 + attack_prob * 1.50 + anomaly_score * 1.25

        # ── Token-pattern exploit signal (no-retrain supplement) ────────────────
        # XLNet perplexity is unreliable for EXPLOIT/BETH sequences because
        # their syscall token sequences look identical to benign on perplexity.
        # We add a rule-based token-pattern score blended at weight 1.0
        # (same weight as anomaly_score) so exploit-indicative combos lift the
        # combined severity even when the model says low anomaly.
        pattern_signal = _token_pattern_signal(tokens)
        if pattern_signal > 0:
            combined = combined + pattern_signal * 1.0

        risk = _risk_label(combined)

        # ── Attack-type → risk ceiling ────────────────────────────────────────
        if atk_type in _RISK_CEILING:
            ceil_risk, ceil_combined = _RISK_CEILING[atk_type]
            if _RISK_ORDER.index(risk) > _RISK_ORDER.index(ceil_risk):
                risk     = ceil_risk
                combined = min(combined, ceil_combined)
            db_flag     = 0
            attack_prob = min(attack_prob, 0.35)

        # ── Severity FLOOR: EXPLOIT / MALWARE / BRUTE_FORCE always ≥ HIGH ──────
        # Applies AFTER the ceiling so recon types are never accidentally floored.
        if atk_type in _SEVERITY_FLOOR:
            floor_risk, floor_combined = _SEVERITY_FLOOR[atk_type]
            if _RISK_ORDER.index(risk) < _RISK_ORDER.index(floor_risk):
                risk     = floor_risk
                combined = max(combined, floor_combined)  # type: ignore
            # Force malicious flags consistent with the floor
            if floor_risk in ("HIGH", "CRITICAL"):
                db_flag = 1
                attack_prob = max(attack_prob, 0.60)

        # ── Binary label derived from FINAL risk ──────────────────────────────
        _BENIGN_RISK_LEVELS  = {"LOW"}
        if risk in _BENIGN_RISK_LEVELS or atk_type in _BENIGN_ATTACK_TYPES:
            db_flag = 0
        distilbert_label = "MALICIOUS" if db_flag == 1 else "BENIGN"


        # XLNet trajectory — what the next predicted token implies about attacker intent
        _TRAJECTORY_MAP = {
            "FILE_XFER":  "→ Malware download",
            "EXEC":       "→ Command execution",
            "EXEC_FAIL":  "→ Probing commands",
            "LOGIN_ATT":  "→ More brute-force",
            "LOGIN_OK":   "→ Login imminent",
            "TUNNEL":     "→ Pivot/tunnelling",
            "SESS_END":   "→ Session closing",
            "RECON":      "→ Fingerprinting",
            "SCAN":       "→ Port scanning",
        }
        xlnet_trajectory = _TRAJECTORY_MAP.get(next_token, f"→ {next_token}")

        # ── Model agreement label (mirrors severity_scorer.py) ────────────────
        if db_flag == 1 and xlnet_flag == 1:
            agreement = "both_malicious"
        elif db_flag == 0 and xlnet_flag == 0:
            agreement = "both_benign"
        elif xlnet_flag == 1:
            agreement = "xlnet_only"
        else:
            agreement = "distilbert_only"

        prediction = {
            "sequence_id":          sid,
            "session_id":           seq.get("session_id"),
            "date":                 date,
            "source":               seq.get("source", "unknown"),
            "attack_type":          seq.get("attack_type", "UNKNOWN"),
            "src_ip":               seq.get("src_ip"),
            "start_time":           seq.get("start_time"),
            "inferred_at":          now_iso,
            "tokens":               tokens,
            "attack_prob":          round(attack_prob, 4),  # type: ignore
            "predicted_binary":     db_flag,
            "distilbert_label":     distilbert_label,
            "anomaly_score":        anomaly_score,
            "agreement":            agreement,
            "predicted_next_token": next_token,
            "xlnet_trajectory":     xlnet_trajectory,
            "perplexity":           ppl,
            "token_severity_mean":  round(token_sev, 4),
            "combined_severity":    round(combined, 4),  # type: ignore
            "risk_level":           risk,
            "is_live":              True,
            "mitre_techniques":     get_mitre_techniques(tokens),
        }
        new_predictions.append(prediction)


    # ── AI prevention summary (Groq LLaMA) ─────────────────────────────────────────
    # Called after all scoring is done so we can batch and avoid blocking.
    # Each prediction gets a short prevention_summary for the live monitor
    # table and a full prevention dict for the sequence detail page.
    for pred in new_predictions:
        try:
            ai_result = _get_ai_prevention(pred)
            pred["prevention_summary"] = ai_result.get("prevention_summary", "")
            pred["prevention"]         = ai_result
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                "[INF] AI prevention failed for %s: %s", pred.get('sequence_id'), e
            )
            pred["prevention_summary"] = ""
            pred["prevention"]         = {}

    if new_predictions:
        pred_col = get_collection("live_predictions")
        for pred in new_predictions:
            pred_col.update_one({"sequence_id": pred["sequence_id"]}, {"$set": pred}, upsert=True)

    return new_predictions


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    _log = _logging.getLogger("inference")
    preds = run_inference()
    _log.info("Scored %d new sequence(s)", len(preds))
    for p in preds:
        _log.info("  %-30s  risk=%-8s  atk_prob=%.3f  next=%s",
                  p['sequence_id'], p['risk_level'], p['attack_prob'], p['predicted_next_token'])
