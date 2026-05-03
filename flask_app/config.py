"""flask_app/config.py — Application configuration."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Auto-load .env from project root if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except ImportError:
    pass   # python-dotenv not installed; use OS environment variables directly


class Config:
    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    if not SECRET_KEY:
        sys.exit(
            "[CONFIG] FATAL: SECRET_KEY is not set.\n"
            "         Add SECRET_KEY=<random-64-char-string> to your .env file.\n"
            "         Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # ── Database ──────────────────────────────────────────────────────────────
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
    DB_NAME   = "proactive_deception"

    REPORTS_DIR = ROOT / "reports"

    # ── Session ───────────────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY  = True
    SESSION_COOKIE_SAMESITE  = "Lax"
    # Send cookies over HTTPS only when running in production
    SESSION_COOKIE_SECURE    = os.environ.get("FLASK_ENV", "development") == "production"
    PERMANENT_SESSION_LIFETIME = 86400  # 1 day in seconds

    # ── Flask-SocketIO ────────────────────────────────────────────────────────
    SOCKETIO_PING_INTERVAL = 10
    SOCKETIO_PING_TIMEOUT  = 60

    # Live feed refresh interval (seconds)
    LIVE_POLL_INTERVAL = 12

    # ── AI Features ───────────────────────────────────────────────────────────
    # Groq API key for LLaMA-powered prevention advice
    # Get yours free at: https://console.groq.com/
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

