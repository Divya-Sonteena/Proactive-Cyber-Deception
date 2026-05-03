#!/usr/bin/env python3
"""
live/parse_dionaea.py — Incremental Dionaea log parser for live raw files.

Reads only new lines from data/live_raw/dionaea/YYYY-MM-DD.json using
byte-offset tracking.  Classification logic mirrors scripts/parse_dionaea.py
exactly (3-tier incident→port→keyword priority + session-level classify).

Events tagged source="dionaea" are inserted into the live_events collection.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared_db import get_collection  # type: ignore[import]

# ── Paths ─────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parent.parent
RAW_DIR     = ROOT / "data" / "live_raw" / "dionaea"
OFFSETS_DIR = ROOT / "data" / "live_processed" / ".offsets"

sys.path.insert(0, str(ROOT / "scripts"))
from token_definitions import TOKEN_SHORTCUTS  # noqa: E402  # type: ignore[import]
# Import shared classification tables from the authoritative offline parser.
from parse_dionaea import (  # noqa: E402  # type: ignore[import]
    INCIDENT_EVENT_TYPES,
    PORT_EVENT_TYPES,
    classify_attack_type,
)

# Tier-3 keyword fallback — local alias to match scripts/ naming
_KEYWORD_FALLBACK = [
    ('malware',    'MALWARE'),
    ('exploit',    'EXPLOITATION'),
    ('shellcode',  'EXPLOITATION'),
    ('download',   'FILE_TRANSFER'),
    ('upload',     'FILE_TRANSFER'),
    ('tftp',       'FILE_TRANSFER'),
    ('http',       'RECONNAISSANCE'),
    ('smb',        'EXPLOITATION'),
    ('ftp',        'FILE_TRANSFER'),
    ('connection', 'SCAN'),
]


# ── 3-tier event type extractor ───────────────────────────────────────────

def _extract_event_type(ev: dict) -> str:
    """
    Classify a pre-parsed JSON event using the same 3-tier logic as
    scripts/parse_dionaea.py (adapted for JSON input instead of text logs):

      Tier 1 — named incident_type / event_type strings
      Tier 2 — dst_port number
      Tier 3 — keyword scan of any string fields
    """
    # Tier 1: check event_type / incident_type fields
    raw_type = (ev.get("event_type") or ev.get("incident_type") or "").lower()
    for pattern, etype in INCIDENT_EVENT_TYPES:
        if pattern in raw_type:  # type: ignore[operator]
            return etype
    # also check exact mapping by upper-cased event_type
    et_upper = raw_type.upper()  # type: ignore[attr-defined]
    if et_upper in ("MALWARE",):         return "MALWARE"
    if et_upper in ("EXPLOITATION", "SHELLCODE"): return "EXPLOITATION"
    if et_upper in ("FILE_TRANSFER",):   return "FILE_TRANSFER"
    if et_upper in ("RECONNAISSANCE",):  return "RECONNAISSANCE"
    if et_upper == "SCAN":               return "SCAN"

    # Tier 2: dst_port
    port = ev.get("dst_port")
    if port is not None:
        try:
            port_int = int(port)
            if port_int in PORT_EVENT_TYPES:
                return PORT_EVENT_TYPES[port_int]
        except (ValueError, TypeError):
            pass

    # Tier 3: keyword scan across all string values
    haystack = " ".join(str(v) for v in ev.values() if isinstance(v, str)).lower()
    for keyword, etype in _KEYWORD_FALLBACK:
        if keyword in haystack:
            return etype

    return "SCAN"


# classify_attack_type is imported from scripts/parse_dionaea.py (single source of truth)


# ── Offset helpers ────────────────────────────────────────────────────────

def _date_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _offset_file(date: str) -> Path:
    OFFSETS_DIR.mkdir(parents=True, exist_ok=True)
    return OFFSETS_DIR / f"dionaea_{date}.offset"


def _read_offset(date: str) -> int:
    f = _offset_file(date)
    return int(f.read_text()) if f.exists() else 0


def _write_offset(date: str, offset: int) -> None:
    _offset_file(date).write_text(str(offset))


# ── Main parse function ───────────────────────────────────────────────────

def parse_new_events(date: str | None = None) -> list[dict]:
    """
    Parse only new lines in today's Dionaea raw log (JSON-Lines format).
    Uses byte-offset tracking for incremental reads.

    Classification is 3-tier incident→port→keyword, matching scripts/parse_dionaea.py.
    Multiple events sharing a session_id are aggregated and classified as a session.
    """
    date     = date or _date_str()
    raw_file = RAW_DIR / f"{date}.json"

    if not raw_file.exists():
        return []

    start_offset = _read_offset(date)
    new_lines: list[str] = []
    with open(raw_file, "rb") as fh:
        fh.seek(start_offset)
        new_lines  = [line.decode("utf-8").strip() for line in fh if line.strip()]
        end_offset = fh.tell()

    if not new_lines:
        return []

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Group events by session_id (mirrors aggregate_events in scripts/) ─
    sessions: dict[str, dict] = {}

    for idx, line in enumerate(new_lines):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        session = ev.get("session_id", f"anon_{start_offset}_{idx}")
        etype   = _extract_event_type(ev)
        token   = TOKEN_SHORTCUTS.get(etype, etype)

        if session not in sessions:
            sessions[session] = {
                "tokens":      [],
                "event_types": set(),
                "src_ips":     set(),
                "start_time":  None,
                "end_time":    None,
                "protocol":    ev.get("protocol"),
                "dst_port":    ev.get("dst_port"),
                "exploit_url": ev.get("exploit_url"),
                "malware_sha256": ev.get("malware_sha256"),
                "raw_events":  [],
            }

        s = sessions[session]
        s["tokens"].append(token)
        s["event_types"].add(etype)
        src_ip = ev.get("src_ip")
        if src_ip:
            s["src_ips"].add(src_ip)
        ts = ev.get("timestamp")
        if ts:
            if s["start_time"] is None or ts < s["start_time"]:
                s["start_time"] = ts
            if s["end_time"]   is None or ts > s["end_time"]:
                s["end_time"]   = ts
        # Keep first non-null values for metadata fields
        for field in ("protocol", "dst_port", "exploit_url", "malware_sha256"):
            if s[field] is None:
                s[field] = ev.get(field)
        s["raw_events"].append(etype)

    # ── Build output records per session ──────────────────────────────────
    new_records: list[dict] = []

    for sid, s in sessions.items():
        src_ips   = list(s["src_ips"])
        token_set = set(s["tokens"])
        attack_type = classify_attack_type(s)  # expects a session dict with 'tokens' key

        unique_key = f"{start_offset}_{sid}"
        record = {
            "date":           date,
            "event_id":       f"dionaea_{sid}_{date}_{unique_key}",
            "session_id":     sid,
            "source":         "dionaea",
            "parsed_at":      now_iso,
            "src_ip":         src_ips[0] if src_ips else None,
            "start_time":     s["start_time"],
            "end_time":       s["end_time"],
            "protocol":       s["protocol"],
            "dst_port":       s["dst_port"],
            "event_tokens":   s["tokens"],
            "attack_type":    attack_type,
            "exploit_url":    s["exploit_url"],
            "malware_sha256": s["malware_sha256"],
            "num_events":     len(s["raw_events"]),
            "is_live":        True,
        }
        new_records.append(record)

    # ── Upsert into MongoDB ───────────────────────────────────────────────
    if new_records:
        events_col = get_collection("live_events")
        for rec in new_records:
            events_col.update_one(
                {"event_id": rec["event_id"]},
                {"$set": rec},
                upsert=True,
            )

    _write_offset(date, end_offset)
    return new_records


if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    _log = _logging.getLogger("parse_dionaea")
    records = parse_new_events()
    _log.info("Parsed %d new session(s) for %s", len(records), _date_str())
