#!/usr/bin/env python3
"""
live/sequence_builder.py — Incremental token sequence builder.

Reads newly parsed events from data/live_processed/events/YYYY-MM-DD.json,
maintains an in-memory (and JSON-backed) per-session token buffer, and
emits a finished sequence when:
  - The session contains a SESS_END token, OR
  - The session buffer is older than SESSION_TIMEOUT_SEC seconds.

Emitted sequences are appended to:
    data/live_processed/sequences/YYYY-MM-DD.json

Idempotent: already-emitted session IDs are tracked and never re-emitted.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT          = Path(__file__).resolve().parent.parent
EVENTS_DIR    = ROOT / "data" / "live_processed" / "events"
STATE_FILE    = ROOT / "data" / "live_processed" / ".session_buffers.json"

sys.path.insert(0, str(ROOT))
from shared_db import get_collection

sys.path.insert(0, str(ROOT / "scripts"))
from token_definitions import get_token  # noqa: E402

# Seconds before a buffered session is force-emitted regardless of SESS_END
SESSION_TIMEOUT_SEC = 60


# ── Persistent state helpers ───────────────────────────────────────────────

def _load_state() -> dict:
    """Load session buffer state from JSON file."""
    if STATE_FILE.exists():
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                pass
    return {"buffers": {}, "emitted": []}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def _load_sequences(date: str) -> dict:
    seq_col = get_collection("live_sequences")
    return {"date": date, "sequences": list(seq_col.find({"date": date}, {"_id": 0}))}


# ── Main builder function ──────────────────────────────────────────────────

def build_sequences(date: str | None = None) -> list[dict]:
    """
    Process today's live events and emit complete sequences.

    Returns:
        List of newly emitted sequence dicts.
    """
    date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    events_col = get_collection("live_events")
    all_events = list(events_col.find({"date": date}, {"_id": 0}))
    if not all_events:
        return []

    state          = _load_state()
    buffers: dict  = state.get("buffers", {})
    emitted: list  = state.get("emitted", [])
    emitted_set    = set(emitted)
    now_ts         = datetime.now(timezone.utc).timestamp()
    new_sequences: list[dict] = []

    # ── Update buffers from events ──────────────────────────────────────
    for ev in all_events:
        sid = ev.get("session_id", "")
        if not sid or sid in emitted_set:
            continue

        if sid not in buffers:
            buffers[sid] = {
                "session_id":   sid,
                "source":       ev.get("source", "unknown"),
                "attack_type":  ev.get("attack_type", "UNKNOWN"),
                "tokens":       [],
                "created_at":   now_ts,
                "src_ip":       ev.get("src_ip"),
                "start_time":   ev.get("start_time"),
            }

        buf = buffers[sid]
        # Merge new tokens (avoid full duplicates, but allow repeat meaningful tokens)
        for tok in ev.get("event_tokens", []):
            buf["tokens"].append(tok)
        # Update attack type if more specific
        if ev.get("attack_type", "UNKNOWN") != "SCAN":
            buf["attack_type"] = ev["attack_type"]

    # ── Emit ready sessions ─────────────────────────────────────────────
    for sid, buf in list(buffers.items()):
        if sid in emitted_set:
            del buffers[sid]
            continue

        tokens     = buf.get("tokens", [])
        session_ended = "SESS_END" in tokens
        age_sec    = now_ts - buf.get("created_at", now_ts)
        timed_out  = age_sec >= SESSION_TIMEOUT_SEC

        if not (session_ended or timed_out) or not tokens:
            continue

        seq_id = f"live_{sid}_{date}"
        # Determine binary label: malicious if attack_type indicates it
        is_malicious = buf.get("attack_type", "SCAN") not in ("SCAN", "RECON_PASSIVE")

        sequence = {
            "sequence_id": seq_id,
            "session_id":  sid,
            "date":        date,
            "source":      buf.get("source", "unknown"),
            "tokens":      tokens,
            "attack_type": buf.get("attack_type", "UNKNOWN"),
            "label":       1 if is_malicious else 0,
            "src_ip":      buf.get("src_ip"),
            "start_time":  buf.get("start_time"),
            "emitted_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "is_live":     True,
            "emit_reason": "session_end" if session_ended else "timeout",
        }
        new_sequences.append(sequence)
        emitted.append(sid)
        emitted_set.add(sid)
        del buffers[sid]

    if new_sequences:
        seq_col = get_collection("live_sequences")
        for seq in new_sequences:
            seq_col.update_one({"sequence_id": seq["sequence_id"]}, {"$set": seq}, upsert=True)

    _save_state({"buffers": buffers, "emitted": emitted})
    return new_sequences


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    _log = _logging.getLogger("sequence_builder")
    seqs = build_sequences()
    _log.info("Emitted %d new sequence(s)", len(seqs))
