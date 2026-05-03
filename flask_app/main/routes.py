"""
flask_app/main/routes.py — Main application routes (all protected).
"""

from flask import Blueprint, render_template, redirect, url_for, abort
from flask_login import login_required, current_user
from flask_app.services.decorators import analyst_required, admin_required  # shared — no duplicates

main_bp = Blueprint("main", __name__)


# ── Dashboard ─────────────────────────────────────────────────────────────────
@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard/index.html")


# ── Live Monitoring ───────────────────────────────────────────────────────────
@main_bp.route("/live")
@login_required
def live_monitor():
    return render_template("live/monitor.html")


@main_bp.route("/live/<sequence_id>")
@login_required
@analyst_required
def sequence_detail(sequence_id: str):
    return render_template("live/sequence_detail.html", sequence_id=sequence_id)


# ── Honeypots ─────────────────────────────────────────────────────────────────
@main_bp.route("/honeypots")
@login_required
def honeypots():
    return render_template("honeypots/index.html")


# ── Models (offline only) ─────────────────────────────────────────────────────
@main_bp.route("/models")
@login_required
def models_page():
    return render_template("models/index.html")


# ── Reports (offline only) ────────────────────────────────────────────────────
@main_bp.route("/reports")
@login_required
def reports():
    return render_template("reports/index.html")


# ── Explainability ────────────────────────────────────────────────────────────
@main_bp.route("/explainability")
@login_required
def explainability():
    return render_template("explainability/index.html")


# ── Campaigns (Feature 3) ─────────────────────────────────────────────────────
@main_bp.route("/live/campaigns")
@login_required
@analyst_required
def campaigns():
    return render_template("live/campaigns.html")


@main_bp.route("/live/campaigns/<campaign_id>")
@login_required
@analyst_required
def campaign_detail(campaign_id: str):
    return render_template("live/campaign_detail.html", campaign_id=campaign_id)


# ── Response Audit (Feature 5, admin only) ────────────────────────────────────
@main_bp.route("/admin/response-audit")
@login_required
@admin_required
def response_audit():
    return render_template("admin/response_audit.html")


# ── Error Handlers ────────────────────────────────────────────────────────────
@main_bp.app_errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@main_bp.app_errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404
