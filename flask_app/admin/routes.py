"""
flask_app/admin/routes.py — Admin-only page routes.
"""

from flask import Blueprint, render_template
from flask_login import login_required
from flask_app.services.decorators import admin_required  # shared — no duplicates

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/settings")
@login_required
@admin_required
def settings():
    return render_template("admin/settings.html")
