"""
flask_app/auth/routes.py — Authentication routes: landing, login, signup, logout.
"""

from urllib.parse import urlparse, urljoin

from flask import (
    Blueprint, render_template, redirect, url_for,
    request, flash
)
from flask_login import login_user, logout_user, login_required, current_user
from flask_app.models import User
from shared_db import get_collection
from datetime import datetime, timezone, timedelta

auth_bp = Blueprint("auth", __name__)


def _is_safe_redirect(url: str) -> bool:
    """Return True only if the URL is host-relative (same origin)."""
    ref = urlparse(request.host_url)
    test = urlparse(urljoin(request.host_url, url))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


# ── Public landing page ───────────────────────────────────────────────────────
@auth_bp.route("/")
def landing():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("public/landing.html")


# ── Login ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        # Rate Limiting & Lockout Check
        lockout_col = get_collection("login_attempts")
        record = lockout_col.find_one({"username": username}) or {"count": 0, "locked_until": None}
        now = datetime.now(timezone.utc)
        
        if record.get("locked_until") and record["locked_until"].replace(tzinfo=timezone.utc) > now:
            error = f"Account locked. Try again after {record['locked_until'].strftime('%H:%M:%S')} UTC."
            return render_template("auth/login.html", error=error)

        user = User.get_by_username(username)

        if user and user.is_active and user.check_password(password):
            lockout_col.delete_one({"username": username}) # Reset counter
            login_user(user, remember=True)
            # Validate next-page redirect to prevent open redirect
            next_page = request.args.get("next")
            if next_page and not _is_safe_redirect(next_page):
                next_page = None
            return redirect(next_page or url_for("main.dashboard"))
        else:
            record["count"] = record.get("count", 0) + 1
            if record["count"] >= 5:
                lockout_end = now + timedelta(minutes=15)
                record["locked_until"] = lockout_end
                error = "Too many failed attempts. Account locked for 15 minutes."
            else:
                error = f"Invalid username or password. ({5 - record['count']} attempts remaining)"
            lockout_col.update_one({"username": username}, {"$set": record}, upsert=True)

    return render_template("auth/login.html", error=error)


# ── Signup ────────────────────────────────────────────────────────────────────
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "student")

        # Students and analysts only — admins must be promoted manually
        if role not in {"student", "analyst"}:
            role = "student"

        if not username or len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(username) > 64:
            error = "Username must be 64 characters or fewer."
        elif not password or len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            user = User.create(username, password, role)
            if user is None:
                error = "Username already taken."
            else:
                flash("Account created! Please log in.", "success")
                return redirect(url_for("auth.login"))

    return render_template("auth/signup.html", error=error)


# ── Logout ────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.landing"))
