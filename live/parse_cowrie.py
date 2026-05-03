#!/usr/bin/env python3
"""
live/parse_cowrie.py — Incremental Cowrie log parser for live raw files.

Reads only *new* lines from today's live_raw/cowrie/YYYY-MM-DD.json
(JSON-Lines format) using a byte-offset tracker, converts each session's
events to canonical tokens, classifies attack type, and appends structured
events to data/live_processed/events/YYYY-MM-DD.json.

This is standalone — it does NOT import scripts/parse_cowrie.py so that
the offline pipeline remains unchanged.
"""

import json
import uuid
from collections import defaultdict
from typing import Any
from datetime import datetime, timezone
from pathlib import Path

# Add shared_db to path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared_db import get_collection  # type: ignore[import]

# ── Paths ─────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).resolve().parent.parent
RAW_DIR       = ROOT / "data" / "live_raw" / "cowrie"
OFFSETS_DIR   = ROOT / "data" / "live_processed" / ".offsets"

# Import token helpers and shared parsing logic from the scripts/ package.
sys.path.insert(0, str(ROOT / "scripts"))
from token_definitions import get_token  # noqa: E402  # type: ignore[import]
from parse_cowrie import COWRIE_EVENT_TYPES, _recon_signals, classify_attack_type  # noqa: E402  # type: ignore[import]

def _date_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _offset_file(date: str) -> Path:
    OFFSETS_DIR.mkdir(parents=True, exist_ok=True)
    return OFFSETS_DIR / f"cowrie_{date}.offset"


def _read_offset(date: str) -> int:
    f = _offset_file(date)
    return int(f.read_text()) if f.exists() else 0


def _write_offset(date: str, offset: int) -> None:
    _offset_file(date).write_text(str(offset))

# ── Main parse function ────────────────────────────────────────────────────


def parse_new_events(date: str | None = None) -> list[dict]:
    """
    Parse only new lines in today's Cowrie raw log and return structured events.
    Appends results to data/live_processed/events/YYYY-MM-DD.json.

    Returns:
        List of newly parsed session event dicts.
    """
    date       = date or _date_str()
    raw_file   = RAW_DIR / f"{date}.json"

    if not raw_file.exists():
        return []

    # ── Read from last known byte offset ──────────────────────────────────
    start_offset = _read_offset(date)
    new_lines: list[str] = []

    with open(raw_file, "rb") as fh:
        fh.seek(start_offset)
        new_lines = [line.decode("utf-8").strip() for line in fh if line.strip()]
        end_offset = fh.tell()

    if not new_lines:
        return []

    # ── Group events by session ────────────────────────────────────────────
    sessions: dict[str, Any] = defaultdict(lambda: {
        "events": [], "tokens": [], "src_ip": None,
        "timestamps": [], "commands": [], "attempted_creds": [],
        "hassh": None, "arch": None, "success": False, "username": None,
    })

    for line in new_lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        sid = ev.get("session")
        if not sid:
            continue

        s  = sessions[sid]
        ts = ev.get("timestamp")
        if ts:
            s["timestamps"].append(ts)
        if s["src_ip"] is None:
            s["src_ip"] = ev.get("src_ip")

        eid  = ev.get("eventid", "")
        etype = COWRIE_EVENT_TYPES.get(eid)
        if etype:
            already_ended = (etype == "SESSION_END"
                            and any(e["type"] == "SESSION_END" for e in s["events"]))
            if not already_ended:
                s["events"].append({"type": etype, "timestamp": ts})
                tok = get_token(etype)
                if tok != "SESS_END" or "SESS_END" not in s["tokens"]:
                    s["tokens"].append(tok)

        # Metadata extraction
        if eid == "cowrie.login.success":
            s["username"] = ev.get("username")
            s["success"]  = True
        elif eid == "cowrie.login.failed":
            uname = ev.get("username")
            if uname:
                s["attempted_creds"].append(
                    {"username": uname, "password": ev.get("password")}
                )
        elif eid == "cowrie.command.input":
            cmd = ev.get("input", "").strip()
            if cmd:
                s["commands"].append(cmd)
        elif eid == "cowrie.client.kex" and s["hassh"] is None:
            s["hassh"] = ev.get("hassh")
        elif eid == "cowrie.session.params" and s["arch"] is None:
            s["arch"] = ev.get("arch")

    # ── Build output records ──────────────────────────────────────────────
    new_records: list[dict] = []
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for sid, s in sessions.items():
        tss = s["timestamps"]
        record = {
            "date":            date,
            "event_id":        f"cowrie_{sid}_{date}",
            "session_id":      sid,
            "source":          "cowrie",
            "parsed_at":       now_iso,
            "src_ip":          s["src_ip"],
            "start_time":      min(tss) if tss else None,
            "end_time":        max(tss) if tss else None,
            "username":        s["username"],
            "login_success":   s["success"],
            "hassh":           s["hassh"],
            "arch":            s["arch"],
            "commands":        s["commands"],
            "attempted_creds": s["attempted_creds"],
            "event_tokens":    s["tokens"],
            "attack_type":     classify_attack_type(s),
            "num_events":      len(s["events"]),
            "is_live":         True,
        }
        new_records.append(record)

    # ── Insert into MongoDB ─────────────────────────────────────────────
    if new_records:
        events_col = get_collection("live_events")
        # Upsert by event_id to prevent duplicates
        for rec in new_records:
            events_col.update_one({"event_id": rec["event_id"]}, {"$set": rec}, upsert=True)

    _write_offset(date, end_offset)
    return new_records


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    _log = _logging.getLogger("parse_cowrie")
    records = parse_new_events()
    _log.info("Parsed %d new session(s) for %s", len(records), _date_str())
