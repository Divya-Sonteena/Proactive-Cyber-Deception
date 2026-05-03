"""
flask_app/services/decorators.py — Shared role-based access-control decorators.

Used by auth/, main/, admin/, api/ blueprints. Defined ONCE here to
eliminate the identical copies that previously existed in every blueprint.
"""

from functools import wraps
from flask import abort, jsonify
from flask_login import current_user


# ── Page-render decorators (abort 403) ───────────────────────────────────────

def analyst_required(f):
    """Require the user to be an analyst or admin (page routes)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_analyst():
            abort(403)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Require the user to be an admin (page routes)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── API decorators (return JSON 403) ─────────────────────────────────────────

def api_analyst_required(f):
    """Require analyst or admin — returns JSON error for API routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_analyst():
            return jsonify({"error": "Analyst or Admin required"}), 403
        return f(*args, **kwargs)
    return decorated


def api_admin_required(f):
    """Require admin — returns JSON error for API routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return jsonify({"error": "Admin required"}), 403
        return f(*args, **kwargs)
    return decorated
