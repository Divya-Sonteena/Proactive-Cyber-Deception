"""
flask_app/services/utils.py — Shared utility functions used across blueprints and WS handlers.

This module eliminates code duplication between api/routes.py and ws/events.py.
"""

from __future__ import annotations

# ── Prevention hints ─────────────────────────────────────────────────────────
# Single source of truth for the one-line prevention summary shown in the
# live monitoring table and pushed over WebSocket.

PREVENTION_HINTS: dict[str, str] = {
    "BRUTE_FORCE":    "Block IP after 5 failures; enable MFA",
    "EXPLOIT":        "Patch vulnerable services; WAF rules",
    "MALWARE":        "Isolate host; scan for persistence",
    "RECONNAISSANCE": "Rate-limit probes; reduce banner info",
    "SCAN":           "Firewall ICMP/SYN; port knocking",
    "TUNNEL":         "Block non-approved outbound ports",
    "MIXED":          "Apply layered defences",
}

_DEFAULT_HINT = "Monitor and log traffic"


def prevention_summary(attack_type: str, risk_level: str) -> str:
    """
    Return a short one-line prevention hint for a given attack type and risk level.

    Used in both the REST API live feed endpoint and the WebSocket background thread
    so the hint shown in the table is always consistent.

    Args:
        attack_type: e.g. "BRUTE_FORCE", "EXPLOIT", "SCAN"
        risk_level:  e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL"

    Returns:
        A short human-readable string. Prefixed with "⚠ URGENT — " for HIGH/CRITICAL.
    """
    base = PREVENTION_HINTS.get(attack_type, _DEFAULT_HINT)
    if risk_level in {"HIGH", "CRITICAL"}:
        base = "⚠ URGENT — " + base
    return base


def int_param(value, default: int, minimum: int = 1, maximum: int = 200) -> int:
    """Safely parse an integer query parameter with clamping.

    Prevents 500 errors when API endpoints receive non-numeric query params
    (e.g. GET /api/live/feed?page=abc).

    Args:
        value:   Raw value from request.args.get() — may be None or non-numeric.
        default: Fallback value if parsing fails.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.

    Returns:
        An integer clamped to [minimum, maximum].
    """
    try:
        return max(minimum, min(maximum, int(value)))
    except (ValueError, TypeError):
        return default
