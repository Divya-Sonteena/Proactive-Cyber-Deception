#!/usr/bin/env python3
"""
Build behaviour-sequence datasets for DistilBERT (attack classification)
and XLNet (next-token / next-step prediction).

Both models consume the SAME three output files:
  train_sequences.json  — 70 % BETH  + 80 % Cowrie + 80 % Dionaea (oversampled)
  val_sequences.json    — 10 % BETH  + 10 % Cowrie + 10 % Dionaea
  test_sequences.json   — 20 % BETH  + 10 % Cowrie + 10 % Dionaea

Per-sequence fields:
  tokens       : list[str]  — behavioural token sequence (domain prefix first)
  label        : int        — 0 BENIGN / 1 MALICIOUS  → DistilBERT
  attack_type  : str        — fine-grained category   → dashboard / analysis
  domain       : str        — 'beth' | 'cowrie' | 'dionaea'
  source       : str        — same as domain (kept for backward compat)
  sequence_id  : str
  length       : int

Splits are performed on GROUP-IDs (process_id for BETH, session_id for
honeypots) so that sliding-window chunks of the same process never span
split boundaries — preventing data leakage.

Domain prefix tokens ([BETH], [COWRIE], [DIONAEA]) are prepended to every
sequence so XLNet can learn domain-conditional next-step distributions.
"""

import json
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from token_definitions import get_token, VOCAB_SIZE

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_SEQ_LEN = 512
RANDOM_SEED = 42

# Split ratios (train / val / test) per data source
BETH_SPLIT = (0.70, 0.10, 0.20)   # BETH: more test data for fair evaluation
HON_SPLIT  = (0.80, 0.10, 0.10)   # Honeypot (Cowrie + Dionaea)

PROCESSED_DIR = Path('data/processed')

# Domain prefix prepended to every sequence so XLNet can condition
# its next-step predictions on which honeypot / dataset produced the data.
DOMAIN_PREFIX = {
    'beth':    '[BETH]',
    'cowrie':  '[COWRIE]',
    'dionaea': '[DIONAEA]',
}

# ── Attack type normalisation ─────────────────────────────────────────────────
# Different parsers produce different attack_type strings for the same class.
# This map collapses them to the 8 canonical labels expected by the models.
# Applied once in _load_sessions so the JSON outputs are already normalised.
ATTACK_NORMALISE: dict[str, str] = {
    # ── BENIGN ───────────────────────────────────────────────────────────────
    'BENIGN':            'BENIGN',

    # ── BRUTE_FORCE ──────────────────────────────────────────────────────────
    'BRUTE_FORCE':       'BRUTE_FORCE',

    # ── SCAN ─────────────────────────────────────────────────────────────────
    'SCAN':              'SCAN',

    # ── RECONNAISSANCE ───────────────────────────────────────────────────────
    # Cowrie produces fine-grained RECON_* subtypes; all collapse to this class.
    'RECONNAISSANCE':       'RECONNAISSANCE',
    'RECON_FINGERPRINT':    'RECONNAISSANCE',
    'RECON_TUNNEL':         'RECONNAISSANCE',
    'RECON_PROBE':          'RECONNAISSANCE',
    'RECON_PASSIVE':        'RECONNAISSANCE',

    # ── EXPLOIT ──────────────────────────────────────────────────────────────
    # BETH and Dionaea use EXPLOITATION; Cowrie uses EXPLOIT.
    'EXPLOIT':           'EXPLOIT',
    'EXPLOITATION':      'EXPLOIT',    # Dionaea / BETH alias
    'MALICIOUS':         'EXPLOIT',    # BETH generic malicious → best bucket

    # ── MALWARE ──────────────────────────────────────────────────────────────
    'MALWARE':           'MALWARE',

    # ── MIXED ────────────────────────────────────────────────────────────────
    'MIXED':             'MIXED',
    'FILE_TRANSFER':     'MIXED',      # Dionaea file-only sessions
}


# ── Loaders ───────────────────────────────────────────────────────────────────

def _load_sessions(filepath: Path, source: str) -> list[dict]:
    """Load sessions from a *_events.json file.

    Returns a flat list of sequence dicts, each containing:
      tokens, label, attack_type, domain, source, sequence_id,
      length, group_id (used for leak-free splitting).

    group_id for BETH   = process_group_id  (ties all windows of one process)
    group_id for others = session_id        (each session is independent)
    """
    if not filepath.exists():
        print(f'  [!] {filepath.name} not found — skipping')
        return []

    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    results = []
    for session in data.get('sessions', []):
        tokens = session.get('event_tokens', [])

        # Cowrie fallback: older format may store event_types instead of tokens
        if not tokens:
            tokens = [get_token(e) for e in session.get('event_types', [])]

        if not tokens:
            continue

        # Truncate to model max, keeping the TAIL (most recent events matter
        # more for attack classification than the beginning of a session)
        if len(tokens) > MAX_SEQ_LEN - 1:   # -1 reserves slot for domain prefix
            tokens = tokens[-(MAX_SEQ_LEN - 1):]

        tokens = [DOMAIN_PREFIX[source]] + tokens   # prepend domain token

        # Binary label: BETH has explicit label; honeypot sessions are all attacks
        label = int(session['label']) if 'label' in session else 1

        # group_id ties sliding-window chunks of the same process together
        # so they always land in the same split (no leakage)
        group_id = session.get('process_group_id') or session.get('session_id')

        seq = {
            'sequence_id': session.get('session_id'),
            'group_id':    group_id,
            'domain':      source,
            'source':      source,
            'tokens':      tokens,
            'length':      len(tokens),
            'label':       label,
            'attack_type': ATTACK_NORMALISE.get(
                session.get('attack_type', 'UNKNOWN'),
                session.get('attack_type', 'UNKNOWN'),  # passthrough if not in map
            ),
        }

        if 'src_ip' in session:
            seq['src_ip'] = session['src_ip']

        results.append(seq)

    print(f'  [OK] {filepath.name}: {len(results)} sequences loaded')
    return results


# ── Splitting ─────────────────────────────────────────────────────────────────

def _split_by_group(
    sequences: list[dict],
    ratios:    tuple[float, float, float],
    seed:      int = RANDOM_SEED,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Stratified, leak-free split by group_id.

    Groups are shuffled then divided so that all chunks (windows) of the
    same process always land in the same split.  The per-label ratio is
    preserved where possible (stratified split).

    Args:
        sequences : flat list of session dicts (all have group_id + label)
        ratios    : (train_frac, val_frac, test_frac) — must sum to 1.0
        seed      : random seed for reproducibility
    Returns:
        (train, val, test) — three lists of sequence dicts
    """
    train_r, val_r, _ = ratios

    # Group sequences by group_id
    groups: dict[str, list[dict]] = defaultdict(list)
    for seq in sequences:
        groups[seq['group_id']].append(seq)

    # Separate groups by their majority label for stratification
    label0_groups = [gid for gid, seqs in groups.items()
                     if sum(s['label'] for s in seqs) == 0]
    label1_groups = [gid for gid, seqs in groups.items()
                     if sum(s['label'] for s in seqs) > 0]

    rng = random.Random(seed)
    rng.shuffle(label0_groups)
    rng.shuffle(label1_groups)

    def _split_list(lst: list) -> tuple[list, list, list]:
        n     = len(lst)
        n_tr  = round(n * train_r)
        n_val = round(n * val_r)
        return lst[:n_tr], lst[n_tr:n_tr + n_val], lst[n_tr + n_val:]

    tr0, v0, te0 = _split_list(label0_groups)
    tr1, v1, te1 = _split_list(label1_groups)

    def _collect(gids: list) -> list[dict]:
        out = []
        for gid in gids:
            out.extend(groups[gid])
        return out

    return _collect(tr0 + tr1), _collect(v0 + v1), _collect(te0 + te1)


# ── Class balancing ───────────────────────────────────────────────────────────

def _oversample(sequences: list[dict], seed: int = RANDOM_SEED) -> list[dict]:
    """Balance binary classes by oversampling the minority to match the majority.

    Applied to the TRAINING set only — val/test sets remain unmodified so
    evaluation metrics reflect the natural class distribution.
    """
    benign    = [s for s in sequences if s['label'] == 0]
    malicious = [s for s in sequences if s['label'] == 1]

    if not benign or not malicious:
        return sequences   # nothing to balance (degenerate split)

    majority = max(len(benign), len(malicious))
    rng      = random.Random(seed)

    def _upsample(items: list, target: int) -> list:
        if len(items) >= target:
            return items
        shortfall = target - len(items)
        extras    = [items[i % len(items)] for i in range(shortfall)]
        rng.shuffle(extras)
        return items + extras

    balanced = _upsample(benign, majority) + _upsample(malicious, majority)
    rng.shuffle(balanced)
    return balanced


# ── Statistics wrapper ────────────────────────────────────────────────────────

def _build_output(sequences: list[dict], split_name: str) -> dict:
    """Wrap a list of sequences with descriptive statistics for the split."""
    lengths = [seq['length'] for seq in sequences]
    return {
        'split':      split_name,
        'sequences':  sequences,
        'statistics': {
            'total_sequences':      len(sequences),
            'total_tokens':         sum(lengths),
            'average_length':       round(statistics.mean(lengths), 1) if lengths else 0,
            'min_length':           min(lengths) if lengths else 0,
            'max_length':           max(lengths) if lengths else 0,
            'vocab_size':           VOCAB_SIZE,
            'label_distribution':   dict(Counter(s['label']       for s in sequences)),
            'attack_distribution':  dict(Counter(s['attack_type'] for s in sequences)),
            'source_distribution':  dict(Counter(s['source']      for s in sequences)),
            'domain_distribution':  dict(Counter(s['domain']      for s in sequences)),
        },
    }


def _save(output: dict, filepath: Path) -> None:
    """Write *output* as JSON and log the resulting file size."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
    size_mb = filepath.stat().st_size / 1_048_576
    print(f'  [OK] Saved → {filepath.name}  ({size_mb:.1f} MB)')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print(f"{'=' * 70}")
    print('BUILDING BEHAVIOUR SEQUENCES  (DistilBERT + XLNet)')
    print(f"{'=' * 70}\n")

    # ── 1. Load all sources ───────────────────────────────────────────────
    print('[1/4] Loading data sources')
    beth    = _load_sessions(PROCESSED_DIR / 'beth_events.json',    'beth')
    cowrie  = _load_sessions(PROCESSED_DIR / 'cowrie_events.json',  'cowrie')
    dionaea = _load_sessions(PROCESSED_DIR / 'dionaea_events.json', 'dionaea')

    if not beth and not cowrie and not dionaea:
        print('[!] No data found — aborting')
        return

    # ── 2. Stratified, leak-free splits per source ────────────────────────
    # BETH groups by process_group_id so sliding-window chunks of the same
    # process always land in the same split (prevents target leakage).
    # Honeypot sessions are independent so they split on session_id.
    print('\n[2/4] Splitting by group (leak-free, stratified)')
    b_tr, b_val, b_te = _split_by_group(beth,    BETH_SPLIT)
    c_tr, c_val, c_te = _split_by_group(cowrie,  HON_SPLIT)
    d_tr, d_val, d_te = _split_by_group(dionaea, HON_SPLIT)

    print(f'  BETH    → train {len(b_tr):5,}  val {len(b_val):4,}  test {len(b_te):4,}')
    print(f'  Cowrie  → train {len(c_tr):5,}  val {len(c_val):4,}  test {len(c_te):4,}')
    print(f'  Dionaea → train {len(d_tr):5,}  val {len(d_val):4,}  test {len(d_te):4,}')

    # ── 3. Merge splits ───────────────────────────────────────────────────
    train_raw = b_tr  + c_tr  + d_tr
    val_seqs  = b_val + c_val + d_val
    test_seqs = b_te  + c_te  + d_te

    # ── 4. Oversample minority class in TRAINING only ─────────────────────
    print('\n[3/4] Balancing training set')
    pre = Counter(s['label'] for s in train_raw)
    print(f'  Before: BENIGN={pre[0]:,}  MALICIOUS={pre[1]:,}')
    train_seqs = _oversample(train_raw)
    post = Counter(s['label'] for s in train_seqs)
    print(f'  After : BENIGN={post[0]:,}  MALICIOUS={post[1]:,}')

    # ── 5. Save ───────────────────────────────────────────────────────────
    print('\n[4/4] Saving splits')
    train_out = _build_output(train_seqs, 'train')
    val_out   = _build_output(val_seqs,   'val')
    test_out  = _build_output(test_seqs,  'test')

    _save(train_out, PROCESSED_DIR / 'train_sequences.json')
    _save(val_out,   PROCESSED_DIR / 'val_sequences.json')
    _save(val_out,   PROCESSED_DIR / 'validation_sequences.json')  # alias expected by training scripts
    _save(test_out,  PROCESSED_DIR / 'test_sequences.json')

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print('DONE — unified splits ready for DistilBERT + XLNet')
    print(f"{'=' * 70}")
    print(f'  Vocabulary size  : {VOCAB_SIZE}')
    print(f'  Max seq length   : {MAX_SEQ_LEN}  (domain prefix included)')
    print()

    for name, out in [('TRAIN', train_out), ('VAL', val_out), ('TEST', test_out)]:
        st = out['statistics']
        print(f'  {name}')
        print(f"    sequences  : {st['total_sequences']:,}")
        print(f"    labels     : {st['label_distribution']}")
        print(f"    sources    : {st['source_distribution']}")
        print(f"    attacks    : {st['attack_distribution']}")
        print()

    print('  Both models use the same files:')
    print('    DistilBERT  →  reads  label       (0/1 classification)')
    print('    XLNet       →  reads  tokens      (next-step prediction)')
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
