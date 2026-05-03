"""
run_flask.py — Entry point for the Proactive Cyber Deception dashboard.

Usage:
    python run_flask.py              # development (debug=True)
    FLASK_ENV=production python run_flask.py  # production (debug=False)

Runs on http://0.0.0.0:5000 by default.
Set PORT environment variable to change.
"""

import logging
import os
from flask_app import create_app, socketio

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
_log = logging.getLogger("pcd")

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") != "production"

    _log.info("=" * 58)
    _log.info("  Proactive Cyber Deception Dashboard")
    _log.info("  http://localhost:%d", port)
    _log.info("  Mode: %s", 'DEVELOPMENT' if debug else 'PRODUCTION')
    _log.info("=" * 58)

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=debug,
        use_reloader=False,          # avoid double-loading background thread
        allow_unsafe_werkzeug=True,  # required for SocketIO + Werkzeug dev server
    )
