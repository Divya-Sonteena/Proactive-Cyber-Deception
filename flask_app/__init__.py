"""
flask_app/__init__.py — Application factory for Proactive Cyber Deception dashboard.
"""

import os
from flask import Flask, request
from flask_login import LoginManager, current_user
from flask_socketio import SocketIO

socketio = SocketIO()
login_manager = LoginManager()


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ── Config ───────────────────────────────────────────────────────────────
    from flask_app.config import Config
    app.config.from_object(Config)

    # ── Extensions ───────────────────────────────────────────────────────────
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"

    # ── No-Cache headers for analyst/student ──────────────────────────────────
    @app.after_request
    def set_cache_headers(response):
        """Prevent browser caching for analysts and students."""
        if current_user.is_authenticated:
            # Check if user is student or analyst (not admin)
            if current_user.role in {"student", "analyst"}:
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private, max-age=0"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
        return response

    socketio.init_app(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # ── User loader ───────────────────────────────────────────────────────────
    from flask_app.models import User

    @login_manager.user_loader
    def load_user(user_id: str):
        return User.get_by_id(user_id)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from flask_app.auth.routes import auth_bp
    from flask_app.main.routes import main_bp
    from flask_app.api.routes import api_bp
    from flask_app.admin.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    # ── WebSocket events ──────────────────────────────────────────────────────
    from flask_app.ws import events  # noqa: F401  (registers handlers as side effect)

    return app
