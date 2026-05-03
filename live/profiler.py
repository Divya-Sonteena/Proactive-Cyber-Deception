"""
live/profiler.py — Attacker Behavioral Profiling

Builds and maintains a per-IP behavioral fingerprint stored in the
`attacker_profiles` MongoDB collection.

Profile structure
─────────────────
  src_ip              : str   — attacker IP address
  session_count       : int   — total sessions seen from this IP
  first_seen          : str   — ISO timestamp of first session
  last_seen           : str   — ISO timestamp of most recent session
  attack_type_counts  : dict  — {attack_type: count}
  risk_counts         : dict  — {LOW/MEDIUM/HIGH/CRITICAL: count}
  peak_risk           : str   — highest risk level ever observed
  token_signature     : list  — sorted unique tokens across all sessions
  sources             : list  — ["cowrie", "dionaea"] etc.
  repeat_attacker     : bool  — True if ≥3 sessions

Called from runner.py Step 8 after inference.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shared_db import get_collection  # type: ignore[import]

_RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _higher_risk(a: str, b: str) -> str:
    """Return whichever risk label is higher."""
    ia = _RISK_ORDER.index(a) if a in _RISK_ORDER else 0
    ib = _RISK_ORDER.index(b) if b in _RISK_ORDER else 0
    return _RISK_ORDER[max(ia, ib)]


# ── Main profile builder ───────────────────────────────────────────────────────

def build_profile(src_ip: str) -> dict | None:
    """
    Build (or refresh) the behavioral profile for a given src_ip.
    Reads all live_predictions for this IP and aggregates into a profile.
    Returns the upserted profile dict, or None if no predictions found.
    """
    if not src_ip:
        return None

    preds_col    = get_collection("live_predictions")
    profiles_col = get_collection("attacker_profiles")

    docs = list(preds_col.find(
        {"src_ip": src_ip},
        {"_id": 0, "attack_type": 1, "risk_level": 1, "tokens": 1,
         "source": 1, "inferred_at": 1, "start_time": 1}
    ).sort("inferred_at", 1))

    if not docs:
        return None

    # ── Aggregate ────────────────────────────────────────────────────────────
    attack_type_counts: dict[str, int] = {}
    risk_counts: dict[str, int]        = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    peak_risk   = "LOW"
    token_set:  set[str] = set()
    sources:    set[str] = set()
    timestamps: list[str] = []

    for doc in docs:
        # Attack type tally
        at = doc.get("attack_type", "UNKNOWN")
        attack_type_counts[at] = attack_type_counts.get(at, 0) + 1

        # Risk tally
        rl = doc.get("risk_level", "LOW")
        risk_counts[rl]  = risk_counts.get(rl, 0) + 1
        peak_risk        = _higher_risk(peak_risk, rl)

        # Token union
        for t in doc.get("tokens", []):
            if t not in ("SESS_END", "PAD", "UNK", "CLS", "SEP"):
                token_set.add(t)  # type: ignore[arg-type]

        # Sources
        src = doc.get("source")
        if src:
            sources.add(src)

        # Timestamps
        ts = doc.get("inferred_at") or doc.get("start_time")
        if ts:
            timestamps.append(ts)

    timestamps.sort()
    session_count = len(docs)

    # ── Risk progression (last 20 for chart display) ────────────────────────
    risk_progression = [
        {"inferred_at": d.get("inferred_at", ""), "risk_level": d.get("risk_level", "LOW")}
        for d in docs[-20:]  # type: ignore[index]
    ]

    # ── Build profile doc ────────────────────────────────────────────────────
    profile = {
        "src_ip":             src_ip,
        "session_count":      session_count,
        "first_seen":         timestamps[0]  if timestamps else None,
        "last_seen":          timestamps[-1] if timestamps else None,
        "attack_type_counts": attack_type_counts,
        "risk_counts":        risk_counts,
        "peak_risk":          peak_risk,
        "token_signature":    sorted(token_set),
        "sources":            sorted(sources),
        "repeat_attacker":    session_count >= 3,
        "risk_progression":   risk_progression,
        "updated_at":         datetime.now(timezone.utc).isoformat(),
    }

    profiles_col.update_one(
        {"src_ip": src_ip},
        {"$set": profile},
        upsert=True,
    )
    return profile


def update_profiles_for_new_predictions(predictions: list[dict]) -> int:
    """
    Build/refresh profiles for all unique src_ips in the given new prediction list.
    Returns the count of profiles updated.
    """
    ips = {p.get("src_ip") for p in predictions if p.get("src_ip")}
    count = 0
    for ip in ips:
        if ip and build_profile(ip):
            count += 1  # type: ignore[operator]
    return count


def get_profile(src_ip: str) -> dict | None:
    """Return the cached profile for a given IP (no live rebuild)."""
    if not src_ip:
        return None
    col = get_collection("attacker_profiles")
    doc = col.find_one({"src_ip": src_ip}, {"_id": 0})
    return doc


def get_top_attackers(limit: int = 10) -> list[dict]:
    """Return top attackers sorted by session count descending."""
    col = get_collection("attacker_profiles")
    return list(col.find({}, {"_id": 0})
                .sort("session_count", -1)
                .limit(limit))
