"""
flask_app/ws/events.py — Flask-SocketIO live feed WebSocket events.

Namespace: /ws/live
Background thread polls MongoDB live_predictions every 12 seconds and
emits new_predictions events to all connected clients.
"""

import logging
import threading
import time
from datetime import datetime, timezone

from flask_socketio import emit, join_room

from flask_app import socketio
from flask_app.services.utils import prevention_summary as _prevention_summary
from shared_db import get_collection

_log = logging.getLogger(__name__)
_POLL_INTERVAL = 12  # seconds
_last_seen: datetime | None = None   # datetime of last emitted prediction (was ISO string)
_thread = None
_thread_lock = threading.Lock()


def _parse_inferred_at(s: str) -> datetime | None:
    """Safely parse inferred_at ISO string to datetime. Returns None on failure."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _background_feed():
    """Continuously poll MongoDB and broadcast new predictions."""
    global _last_seen
    while True:
        time.sleep(_POLL_INTERVAL)
        try:
            preds_col = get_collection("live_predictions")
            query: dict = {}
            if _last_seen:
                # Use ISO string for MongoDB query (stored as string in collection)
                query["inferred_at"] = {"$gt": _last_seen.strftime("%Y-%m-%dT%H:%M:%SZ")}

            docs = list(
                preds_col.find(query, {
                    "_id": 0,
                    "sequence_id": 1,
                    "session_id": 1,
                    "source": 1,
                    "attack_type": 1,
                    "risk_level": 1,
                    "predicted_next_token": 1,
                    "xlnet_trajectory": 1,
                    "inferred_at": 1,
                    "status": 1,
                    "combined_severity": 1,
                    "distilbert_label": 1,
                })
                .sort("inferred_at", -1)
                .limit(50)
            )

            if docs:
                # Update cursor — use datetime objects for safe max() comparison
                datetimes = [dt for d in docs if (dt := _parse_inferred_at(d.get("inferred_at", "")))]
                if datetimes:
                    most_recent = max(datetimes)
                    if _last_seen is None or most_recent > _last_seen:
                        _last_seen = most_recent

                # Attach prevention summary
                for d in docs:
                    d["prevention_summary"] = _prevention_summary(
                        d.get("attack_type", "UNKNOWN"),
                        d.get("risk_level", "LOW")
                    )

                socketio.emit(
                    "new_predictions",
                    {"rows": docs, "timestamp": datetime.now(timezone.utc).isoformat()},
                    namespace="/ws/live",
                )
        except Exception as e:
            _log.warning("[WS] Background thread error: %s", e)


# _prevention_summary is imported from flask_app.services.utils (single source of truth)


@socketio.on("connect", namespace="/ws/live")
def on_connect():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = socketio.start_background_task(_background_feed)
    emit("connected", {"msg": "Live feed WebSocket connected."})


@socketio.on("disconnect", namespace="/ws/live")
def on_disconnect():
    pass  # handled automatically


@socketio.on("subscribe", namespace="/ws/live")
def on_subscribe(data):
    room = data.get("room", "all")
    join_room(room)
    emit("subscribed", {"room": room})
