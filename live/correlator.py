"""
live/correlator.py — Cross-Session Attack Campaign Correlation Engine

Groups related sessions into attack campaigns using shared signals:
  - Same src_ip (weight 0.5)
  - Same HASSH SSH fingerprint (weight 0.3)
  - Same username attempted (weight 0.2)

Uses Union-Find (disjoint-set) for O(N α(N)) campaign clustering.
Writes campaign summaries to MongoDB collection `attack_campaigns`.
Called as Step 6 in live/runner.py after inference.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared_db import get_collection


# ── Weights for correlation signals ──────────────────────────────────────────
SIGNAL_WEIGHTS = {
    "src_ip":   0.5,
    "hassh":    0.3,
    "username": 0.2,
}
CORRELATION_THRESHOLD = 0.5   # minimum similarity to link two sessions


# ── Union-Find (disjoint-set) ─────────────────────────────────────────────────
class _UnionFind:
    def __init__(self):
        self._parent: dict[str, str] = {}
        self._rank:   dict[str, int] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        self._rank.setdefault(x, 0)
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def groups(self, items: list[str]) -> dict[str, list[str]]:
        """Return {root_id → [member_ids]} for given items."""
        groups: dict[str, list[str]] = defaultdict(list)
        for item in items:
            groups[self.find(item)].append(item)
        return dict(groups)


# ── Similarity helper ─────────────────────────────────────────────────────────
def _similarity(a: dict, b: dict) -> float:
    """Compute weighted similarity score between two prediction documents."""
    score = 0.0
    for field, weight in SIGNAL_WEIGHTS.items():
        val_a = (a.get(field) or "").strip()
        val_b = (b.get(field) or "").strip()
        if val_a and val_b and val_a == val_b:
            score += weight
    return score


# ── Redis-style campaign_id generator ─────────────────────────────────────────
def _campaign_id(root_seq_id: str) -> str:
    return "camp_" + root_seq_id.replace("live_", "").replace("-", "")[:20]


# ── Main correlation function ─────────────────────────────────────────────────
def correlate_sessions(date: str | None = None) -> list[dict]:
    """
    Load today's predictions, cluster them into campaigns, write to MongoDB.
    Returns list of campaign dicts written/updated.
    """
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    preds_col    = get_collection("live_predictions")
    camps_col    = get_collection("attack_campaigns")

    # Load predictions for today that are NOT benign
    docs = list(preds_col.find(
        {"date": date},
        {"sequence_id": 1, "session_id": 1, "src_ip": 1, "hassh": 1,
         "username": 1, "attack_type": 1, "risk_level": 1,
         "inferred_at": 1, "tokens": 1, "source": 1}
    ))

    if len(docs) < 2:
        return []

    # Build lookup by sequence_id
    by_id = {d["sequence_id"]: d for d in docs}
    ids   = list(by_id.keys())

    uf = _UnionFind()

    # O(N²) pairwise similarity — acceptable for N < 500 sessions/day
    for i in range(len(docs)):
        for j in range(i + 1, len(docs)):
            sim = _similarity(docs[i], docs[j])
            if sim >= CORRELATION_THRESHOLD:
                uf.union(ids[i], ids[j])

    # Build campaign groups
    groups = uf.groups(ids)
    written = []

    for root, members in groups.items():
        if len(members) < 2:
            # Single-session groups are not campaigns
            continue

        member_docs = [by_id[m] for m in members]

        src_ips     = list({d.get("src_ip") or "unknown" for d in member_docs})
        hasshs      = list({d.get("hassh")  or ""        for d in member_docs if d.get("hassh")})
        usernames   = list({d.get("username") or ""      for d in member_docs if d.get("username")})
        attack_types= list({d.get("attack_type", "SCAN") for d in member_docs})
        sources     = list({d.get("source", "cowrie")    for d in member_docs})

        risk_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        all_risks   = [d.get("risk_level", "LOW") for d in member_docs]
        top_risk    = min(all_risks, key=lambda r: risk_order.index(r) if r in risk_order else 99)

        timestamps  = [d.get("inferred_at", "") for d in member_docs if d.get("inferred_at")]
        first_seen  = min(timestamps) if timestamps else date
        last_seen   = max(timestamps) if timestamps else date

        camp_id = _campaign_id(root)

        campaign = {
            "campaign_id":         camp_id,
            "sequence_ids":        members,
            "session_count":       len(members),
            "src_ips":             src_ips,
            "hassh_fingerprints":  hasshs,
            "usernames_tried":     [u for u in usernames if u],
            "attack_types":        attack_types,
            "sources":             sources,
            "campaign_risk":       top_risk,
            "first_seen":          first_seen,
            "last_seen":           last_seen,
            "date":                date,
            "correlation_signals": [s for s, d in SIGNAL_WEIGHTS.items()
                                    if any((dd.get(s) or "") for dd in member_docs)],
        }

        camps_col.update_one(
            {"campaign_id": camp_id},
            {"$set": campaign},
            upsert=True,
        )

        # Back-annotate each prediction with its campaign_id
        preds_col.update_many(
            {"sequence_id": {"$in": members}},
            {"$set": {"campaign_id": camp_id, "campaign_risk": top_risk}},
        )

        written.append(campaign)

    return written


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    _log = _logging.getLogger("correlator")
    campaigns = correlate_sessions()
    _log.info("%d campaign(s) found:", len(campaigns))
    for c in campaigns:
        _log.info("  %s  sessions=%d  risk=%s  ips=%s",
                  c['campaign_id'], c['session_count'], c['campaign_risk'], c['src_ips'])
