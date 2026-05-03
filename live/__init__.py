"""
live/ — Live honeypot inference package.

This package contains the full live inference pipeline:
  generator.py       — synthetic Cowrie/Dionaea attack traffic
  parse_cowrie.py    — incremental Cowrie log parser
  parse_dionaea.py   — incremental Dionaea log parser
  sequence_builder.py — token-sequence builder (session-buffered)
  inference.py       — DistilBERT + XLNet scoring engine
  runner.py          — main execution loop (1 attack/min)

All offline functionality in scripts/ and flask_app/ remains unchanged.
"""
