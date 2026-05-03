#!/usr/bin/env python3
"""
Parse BETH dataset CSV logs and extract structured process-level events.

Reads the labelled BETH CSV files and:
- Groups syscall events into sessions by processId
- Maps each syscall to a behavioural token via SYSCALL_TO_TOKEN (imported
  from token_definitions — single source of truth, no duplication)
- Classifies each process session as MALICIOUS or BENIGN
- Applies sliding-window chunking for long sessions
- Generates structured output matching the cowrie_events.json /
  dionaea_events.json schema for unified ML training

Input:  data/beth/raw/labelled_*.csv
Output: data/processed/beth_events.json
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd

from token_definitions import SYSCALL_TO_TOKEN

# Only the columns we actually use — speeds up read_csv on large files
_REQUIRED_COLS = ['processId', 'eventName', 'timestamp', 'evil']
_OPTIONAL_COLS = ['sus', 'parentProcessId', 'userId']

# BETH CSV files to process (order: train → val → test)
BETH_CSV_FILES = [
    'labelled_training_data.csv',
    'labelled_validation_data.csv',
    'labelled_testing_data.csv',
]

# Sliding-window parameters for long process sessions
WINDOW_SIZE = 50   # events per sequence
STRIDE      = 25   # step between windows (50 % overlap)


def _epoch_to_iso(epoch: float) -> str:
    """Convert a Unix epoch float to an ISO 8601 UTC string.

    BETH timestamps are relative seconds from capture start, not absolute
    epoch values, so they are anchored to a fixed base date for consistency.
    """
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except (OSError, OverflowError, ValueError):
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        return (base + timedelta(seconds=float(epoch))).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def classify_attack_type(tokens: list[str], label: int) -> str:
    """Classify a process session into an attack category.

    Uses the ground-truth ``evil`` label from BETH, supplemented by
    behavioural signals for finer granularity.  Categories are aligned
    with the Cowrie / Dionaea labels used elsewhere in the pipeline.
    """
    if label == 0:
        return 'BENIGN'

    token_set = set(tokens)
    if 'PRIV_ESC' in token_set or 'EXEC' in token_set or 'PROC_EXEC' in token_set:
        return 'EXPLOITATION'
    if 'NET_CONNECT' in token_set or 'NET_SEND' in token_set:
        return 'RECONNAISSANCE'
    if 'FILE_DEL' in token_set or 'FILE_WRITE' in token_set:
        return 'MALWARE'
    return 'MALICIOUS'


def load_and_aggregate(data_dir: Path) -> tuple[dict, dict]:
    """Load all BETH CSV files and group syscall events by processId.

    Long sessions are split into overlapping sliding windows:
      - WINDOW_SIZE = 50 events per sequence
      - STRIDE      = 25 events (50 % overlap)

    Performance notes:
      - Only required columns are read from CSV (usecols) to minimise I/O
      - groupby(sort=False) skips pandas' internal sort; each group is sorted
        by timestamp individually, which is faster for large groups
      - Syscall → token mapping is vectorised via pd.Series.map() (C-speed)
      - Optional column presence is checked once per file, not per group
      - ISO timestamps are computed once per process and shared across chunks

    Returns:
        sessions    : dict keyed by session_id with session data
        skip_counts : dict mapping csv_name → number of unmapped syscalls
    """
    sessions:    dict[str, dict] = {}
    skip_counts: dict[str, int]  = {}
    total_records = 0

    for csv_name in BETH_CSV_FILES:
        csv_path = data_dir / csv_name
        if not csv_path.exists():
            print(f'[!] Skipping {csv_name} — not found')
            continue

        print(f'[INFO] Loading {csv_name} …', end=' ', flush=True)

        # Read only the columns we need; let pandas skip everything else
        avail    = set(pd.read_csv(csv_path, nrows=0).columns)
        use_cols = _REQUIRED_COLS + [c for c in _OPTIONAL_COLS if c in avail]
        df       = pd.read_csv(csv_path, usecols=use_cols, low_memory=False).drop_duplicates()
        print(f'{len(df):,} rows')
        total_records += len(df)

        tag = csv_name.split('_')[1].upper()[:5]   # TRAIN / VALID / TESTI

        # Check optional column availability once per file (not per group)
        has_sus    = 'sus'             in df.columns
        has_parent = 'parentProcessId' in df.columns
        has_user   = 'userId'          in df.columns

        # ── Vectorised syscall → token mapping ───────────────────────────────
        # pd.Series.map() runs at C speed; NaN = unmapped syscall (skipped)
        mapped   = df['eventName'].astype(str).str.strip().map(SYSCALL_TO_TOKEN)
        df       = df.assign(token=mapped)
        skipped  = int(mapped.isna().sum())

        # Drop rows with no token so groupby only iterates valid syscalls
        df_valid = df.dropna(subset=['token'])

        # sort=False avoids an extra O(n log n) pass — we sort within each
        # group by timestamp, which handles ordering correctly
        for process_id, group in df_valid.groupby('processId', sort=False):
            group  = group.sort_values('timestamp')
            tokens = group['token'].tolist()   # pre-filtered, no NaN

            if not tokens:
                continue

            label       = int(group['evil'].iat[0])
            sus_score   = float(group['sus'].iat[0])           if has_sus    else 0.0
            parent_pid  = int(group['parentProcessId'].iat[0]) if has_parent else None
            user_id     = int(group['userId'].iat[0])          if has_user   else None
            start_ts    = float(group['timestamp'].iat[0])
            end_ts      = float(group['timestamp'].iat[-1])
            duration    = round(end_ts - start_ts, 6)
            attack_type = classify_attack_type(tokens, label)
            group_id    = f'{csv_name}::{process_id}'

            # Convert timestamps once per process; reuse in every chunk
            iso_start = _epoch_to_iso(start_ts)
            iso_end   = _epoch_to_iso(end_ts)
            num_rows  = len(group)

            # ── Sliding-window chunking ───────────────────────────────────────
            n = len(tokens)
            if n <= WINDOW_SIZE:
                chunks = [tokens]
            else:
                chunks = [tokens[s:s + WINDOW_SIZE]
                          for s in range(0, n - WINDOW_SIZE + 1, STRIDE)]
                # Capture any tail events not covered by an exact stride
                if (n - WINDOW_SIZE) % STRIDE != 0:
                    chunks.append(tokens[n - WINDOW_SIZE:])

            for chunk_idx, chunk in enumerate(chunks):
                session_id = f'beth_{tag}_{process_id}_w{chunk_idx}'
                sessions[session_id] = {
                    'session_id':        session_id,
                    'process_id':        int(process_id),
                    'process_group_id':  group_id,
                    'parent_process_id': parent_pid,
                    'user_id':           user_id,
                    'start_time':        iso_start,   # shared across chunks
                    'end_time':          iso_end,
                    'duration_seconds':  duration,
                    'num_events':        len(chunk),
                    'num_syscalls':      num_rows,
                    'event_tokens':      chunk,
                    'attack_type':       attack_type,
                    'label':             label,
                    'sus_score':         sus_score,
                    'source_file':       csv_name,
                }

        skip_counts[csv_name] = skipped

    print(f'[OK] Loaded {total_records:,} total records → {len(sessions):,} sessions (windowed)')
    return sessions, skip_counts


def generate_report(sessions: dict, skip_counts: dict) -> dict:
    """Build the final structured report matching the cowrie_events.json schema.

    Top-level keys:
      parsed_at, total_sessions, total_events, malicious_sessions,
      benign_sessions, attack_distribution, skipped_syscalls, sessions[]

    Uses a single pass over sessions to compute all aggregates at once,
    avoiding multiple list comprehensions over the same data.
    """
    attack_counts: dict[str, int] = {}
    total_events = 0
    malicious = benign = 0
    sus_total = sus_max = 0.0

    for s in sessions.values():
        total_events += s['num_events']
        attack_counts[s['attack_type']] = attack_counts.get(s['attack_type'], 0) + 1
        sc = s['sus_score']
        sus_total += sc
        if sc > sus_max:
            sus_max = sc
        if s['label'] == 1:
            malicious += 1
        else:
            benign += 1

    return {
        'parsed_at':           datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'total_sessions':      len(sessions),
        'total_events':        total_events,
        'malicious_sessions':  malicious,
        'benign_sessions':     benign,
        'attack_distribution': attack_counts,
        'skipped_syscalls':    skip_counts,
        'sessions':            sorted(sessions.values(), key=lambda s: s['start_time']),
    }


def main():
    """
    Pipeline entry point:
      1. Read raw BETH CSV files from data/beth/raw/
      2. Aggregate syscalls into process sessions (sliding window)
      3. Save structured output to data/processed/beth_events.json
    """
    raw_dir     = Path(__file__).parent.parent / 'data' / 'beth' / 'raw'
    output_file = Path(__file__).parent.parent / 'data' / 'processed' / 'beth_events.json'
    output_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"{'=' * 70}")
    print('PROCESSING BETH DATASET')
    print(f"{'=' * 70}\n")

    sessions, skip_counts = load_and_aggregate(raw_dir)

    if not sessions:
        print('[!] No sessions found — check CSV paths')
        return

    report = generate_report(sessions, skip_counts)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    size_mb = output_file.stat().st_size / 1_048_576
    print(f'\n[OK] Saved → {output_file.name}  ({size_mb:.1f} MB)')
    print('\nSummary:')
    print(f"  Total sessions  : {report['total_sessions']:,}")
    print(f"  Total events    : {report['total_events']:,}")
    print(f"  Malicious       : {report['malicious_sessions']:,}")
    print(f"  Benign          : {report['benign_sessions']:,}")
    print(f"  Attack types    : {report['attack_distribution']}")
    print(f"  Skipped syscalls: {report['skipped_syscalls']}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
