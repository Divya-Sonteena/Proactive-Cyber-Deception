"""
shared_db.py — Thread-safe MongoDB singleton client.

Loads .env automatically so any script importing this module gets
the correct MONGO_URI even before Flask config is initialised.

Auto-creates indexes on first database connection (no separate setup script needed).
"""

import os
import threading
from pathlib import Path
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import OperationFailure

# Auto-load .env from project root
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
except ImportError:
    pass  # python-dotenv not installed; rely on OS environment

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "proactive_deception"

_client: MongoClient | None = None
_lock = threading.Lock()
_indexes_initialized = False
_init_lock = threading.Lock()


def _safe_create_index(col: Collection, keys, **kwargs) -> None:
    """Safely create an index, ignoring IndexOptionsConflict if index already exists."""
    try:
        col.create_index(keys, **kwargs)
    except OperationFailure as e:
        # Code 85 = IndexOptionsConflict: index exists with different name/options
        # Safe to ignore — the index already exists and serves the same purpose
        if e.code != 85:
            raise


def _ensure_indexes(db: Database) -> None:
    """Create all necessary indexes for production (idempotent, thread-safe).
    
    Called automatically on first get_db() call.
    Safe to call multiple times — handles existing indexes gracefully.
    Uses double-checked locking to avoid repeated initialization.
    """
    global _indexes_initialized
    if _indexes_initialized:
        return
    
    with _init_lock:
        if _indexes_initialized:  # double-checked locking
            return
        
        # ── live_predictions ─────────────────────────────────────────────────
        col = db["live_predictions"]
        _safe_create_index(col, "sequence_id", unique=True, name="idx_sequence_id")
        _safe_create_index(col, "inferred_at", name="idx_inferred_at")
        _safe_create_index(col, "date", name="idx_date")
        _safe_create_index(col, "risk_level", name="idx_risk_level")
        _safe_create_index(col, "src_ip", name="idx_src_ip")
        _safe_create_index(col, "source", name="idx_source")
        _safe_create_index(col, [("date", 1), ("risk_level", 1)], name="idx_date_risk")
        _safe_create_index(col, [("source", 1), ("date", 1)], name="idx_source_date")
        _safe_create_index(col, [("date", 1), ("source", 1), ("inferred_at", -1)], name="idx_date_source_time")
        _safe_create_index(col, [("date", 1), ("risk_level", 1), ("inferred_at", -1)], name="idx_date_risk_time")
        
        # ── attack_campaigns ─────────────────────────────────────────────────
        col = db["attack_campaigns"]
        _safe_create_index(col, "campaign_id", unique=True, name="idx_campaign_id")
        _safe_create_index(col, "date", name="idx_date")
        _safe_create_index(col, "src_ips", name="idx_src_ips")
        _safe_create_index(col, "campaign_risk", name="idx_campaign_risk")
        
        # ── attacker_profiles ────────────────────────────────────────────────
        col = db["attacker_profiles"]
        _safe_create_index(col, "src_ip", unique=True, name="idx_src_ip")
        _safe_create_index(col, "session_count", name="idx_session_count")
        
        # ── ai_prevention_cache — TTL index (auto-expire after 24h) ──────────
        col = db["ai_prevention_cache"]
        _safe_create_index(col, "cache_key", unique=True, name="idx_cache_key")
        _safe_create_index(col, "cached_at", expireAfterSeconds=86400, name="ttl_cached_at")
        
        # ── sequence_notes ───────────────────────────────────────────────────
        col = db["sequence_notes"]
        _safe_create_index(col, "sequence_id", name="idx_sequence_id")
        _safe_create_index(col, "created_at", name="idx_created_at")
        
        # ── response_audit ───────────────────────────────────────────────────
        col = db["response_audit"]
        _safe_create_index(col, "performed_at", name="idx_performed_at")
        _safe_create_index(col, "sequence_id", name="idx_sequence_id")
        
        # ── users ────────────────────────────────────────────────────────────
        col = db["users"]
        _safe_create_index(col, "username", unique=True, name="idx_username")
        
        # ── live_events ──────────────────────────────────────────────────────
        col = db["live_events"]
        _safe_create_index(col, "date", name="idx_date")
        _safe_create_index(col, "session_id", name="idx_session_id")
        _safe_create_index(col, [("date", 1), ("source", 1)], name="idx_date_source")
        _safe_create_index(col, [("session_id", 1), ("timestamp", -1)], name="idx_session_time")
        
        # ── live_sequences ───────────────────────────────────────────────────
        col = db["live_sequences"]
        _safe_create_index(col, "sequence_id", name="idx_sequence_id")
        _safe_create_index(col, "date", name="idx_date")
        _safe_create_index(col, [("date", 1), ("source", 1)], name="idx_date_source")
        
        _indexes_initialized = True


def get_db() -> Database:
    """Return the PyMongo database instance (thread-safe lazy singleton).
    
    Automatically creates all necessary indexes on first call.
    Idempotent and thread-safe.
    """
    global _client
    if _client is None:
        with _lock:
            if _client is None:  # double-checked locking
                _client = MongoClient(
                    MONGO_URI,
                    # Production-ready connection pool:
                    # 50 max connections handles concurrent SocketIO threads + API requests
                    maxPoolSize=50,
                    minPoolSize=5,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=10000,
                )
    
    db = _client[DB_NAME]
    _ensure_indexes(db)  # Initialize indexes on first connection
    return db


def get_collection(collection_name: str) -> Collection:
    """Return a specific PyMongo collection."""
    return get_db()[collection_name]
