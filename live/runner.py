#!/usr/bin/env python3
"""
live/runner.py — Main execution loop for the live inference pipeline.

Execution cycle (once per minute):
    1. replay_next_session()    ← feed next real Cowrie session from cowrie.json
    2. parse_cowrie()           ← parse new Cowrie lines → events file
    3. parse_dionaea()          ← parse new Dionaea lines → events file
    4. build_sequences()        ← emit complete session sequences
    5. run_inference()          ← score new sequences with both models
    6. correlate_sessions()     ← group related sessions into campaigns
    7. profiling                ← update attacker behavioral profiles
    8. sleep(interval)

Flags:
    --dry-run   Run exactly one full cycle then exit (no sleep). Use for testing.
    --cycles N  Run N cycles then exit (default: infinite).

The loop is restart-safe: every stage is idempotent.
Handles SIGINT / SIGTERM gracefully.
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
_log = logging.getLogger("runner")

# ── Package imports ────────────────────────────────────────────────────────
# Allow running as   python live/runner.py   from the project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from live.generator        import generate_one_attack, generate_one_dionaea_attack
from live.parse_cowrie     import parse_new_events as parse_cowrie
from live.parse_dionaea    import parse_new_events as parse_dionaea
from live.sequence_builder import build_sequences
from live.inference        import run_inference
from live.correlator       import correlate_sessions

try:
    from live.profiler import update_profiles_for_new_predictions as _update_profiles
    _PROFILER_OK = True
except Exception:
    _PROFILER_OK = False

# ── Graceful shutdown flag ────────────────────────────────────────────────
_STOP = False


def _signal_handler(sig, frame):
    global _STOP
    _log.warning("Shutdown signal received — finishing current cycle …")
    _STOP = True


signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ── Single pipeline cycle ─────────────────────────────────────────────────

def run_one_cycle(cycle_num: int = 1) -> dict:
    """Execute one full pipeline cycle and return a summary dict."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _log.info("=" * 58)
    _log.info("Cycle #%d  at %s", cycle_num, ts)
    _log.info("=" * 58)

    # Step 1 — Replay next real Cowrie & Dionaea sessions
    _log.info("[1/8] Replaying next real Honeypot sessions …")

    # Cowrie
    gen_c = generate_one_attack(source="cowrie")
    _log.info("      [Cowrie]  session=%s  src=%s  events=%d  login=%s  idx=%d/%d",
              gen_c['session_id'], gen_c['src_ip'], gen_c['num_events'],
              '✓' if gen_c.get('login_success') else '✗',
              gen_c['replay_index']+1, gen_c['total_sessions'])

    # Dionaea
    gen_d = generate_one_dionaea_attack()
    _log.info("      [Dionaea] session=%s  src=%s  events=%d  type=%s  idx=%d/%d",
              gen_d['session_id'], gen_d['src_ip'], gen_d['num_events'],
              gen_d['attack_type'], gen_d['replay_index']+1, gen_d['total_sessions'])

    # Step 2 — Parse Cowrie
    _log.info("[2/8] Parsing Cowrie logs …")
    cowrie_recs = parse_cowrie()
    _log.info("      %d new Cowrie session(s) parsed", len(cowrie_recs))

    # Step 3 — Parse Dionaea
    _log.info("[3/8] Parsing Dionaea logs …")
    dionaea_recs = parse_dionaea()
    _log.info("      %d new Dionaea event(s) parsed", len(dionaea_recs))

    # Step 4 — Build sequences
    _log.info("[4/8] Building sequences …")
    seqs = build_sequences()
    _log.info("      %d sequence(s) emitted", len(seqs))

    # Step 5 — Inference
    _log.info("[5/8] Running inference …")
    preds = run_inference()
    _log.info("      %d prediction(s) written", len(preds))

    for p in preds:
        _log.info("        → %-32s  risk=%-8s  prob=%.3f  next=%s",
                  p['sequence_id'], p['risk_level'], p['attack_prob'], p['predicted_next_token'])

    # Step 6 — Campaign Correlation
    _log.info("[6/8] Correlating sessions into campaigns …")
    try:
        campaigns = correlate_sessions()
        _log.info("      %d campaign(s) detected/updated", len(campaigns))
        for c in campaigns:
            _log.info("        ⌖ %s  sessions=%d  risk=%s  ips=%s",
                      c['campaign_id'], c['session_count'], c['campaign_risk'], c['src_ips'][:2])
    except Exception as exc:
        _log.warning("Campaign correlation failed: %s", exc)
        campaigns = []

    # Step 7 — Attacker Profiling
    profiles_updated = 0
    if _PROFILER_OK:
        _log.info("[7/8] Updating attacker profiles …")
        try:
            profiles_updated = _update_profiles(preds)
            _log.info("      %d attacker profile(s) updated", profiles_updated)
        except Exception as exc:
            _log.warning("Profiling failed: %s", exc)
    else:
        _log.info("[7/8] Profiler unavailable, skipping profile updates")

    summary = {
        "cycle":                cycle_num,
        "timestamp":            ts,
        "cowrie_attack":        gen_c["attack_type"],
        "dionaea_attack":       gen_d["attack_type"],
        "cowrie_sessions":      len(cowrie_recs),
        "dionaea_events":       len(dionaea_recs),
        "sequences_emitted":    len(seqs),
        "predictions":          len(preds),
        "campaigns":            len(campaigns)
    }
    _log.info("Cycle #%d complete ✓  predictions=%d  campaigns=%d",
              cycle_num, len(preds), len(campaigns))
    return summary


# ── Main loop ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Live honeypot inference runner"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run exactly one cycle then exit (skips sleep)"
    )
    parser.add_argument(
        "--cycles", type=int, default=0,
        help="Number of cycles to run (0 = infinite)"
    )
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between cycles (default: 60)"
    )
    args = parser.parse_args()

    if args.dry_run:
        _log.info("DRY-RUN mode: one cycle, no sleep")
        run_one_cycle(1)
        return

    max_cycles = args.cycles or float("inf")
    cycle_num  = 0

    _log.info("Starting live pipeline (interval=%ds)", args.interval)
    _log.info("Press Ctrl+C to stop gracefully")

    while not _STOP and cycle_num < max_cycles:
        cycle_num += 1
        run_one_cycle(cycle_num)

        if _STOP or cycle_num >= max_cycles:
            break

        _log.info("Sleeping %ds until next cycle …", args.interval)
        for _ in range(args.interval):
            if _STOP:
                break
            time.sleep(1)

    _log.info("Pipeline stopped cleanly.")


if __name__ == "__main__":
    main()
