"""
flask_app/models.py — User model backed by MongoDB (no ORM).

Collection: proactive_deception.users
Schema:
  _id          : ObjectId
  username     : str (unique, indexed)
  password_hash: str (bcrypt)
  role         : str  ("student" | "analyst" | "admin")
  is_active    : bool
  created_at   : str  (ISO 8601)
"""

from __future__ import annotations

import bcrypt
from bson import ObjectId
from datetime import datetime, timezone
from flask_login import UserMixin
from shared_db import get_collection


VALID_ROLES = {"student", "analyst", "admin"}


class User(UserMixin):
    """Flask-Login compatible user wrapping a MongoDB document."""

    def __init__(self, doc: dict):
        self._id = str(doc["_id"])
        self.username = doc["username"]
        self.password_hash = doc.get("password_hash", "")
        self.role = doc.get("role", "student")
        self.is_active_flag = doc.get("is_active", True)

    # ── Flask-Login interface ─────────────────────────────────────────────────
    def get_id(self) -> str:
        return self._id

    @property
    def is_active(self) -> bool:
        return self.is_active_flag

    # ── Role helpers ──────────────────────────────────────────────────────────
    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_analyst(self) -> bool:
        return self.role in {"analyst", "admin"}

    def is_student(self) -> bool:
        return self.role == "student"

    # ── DB helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _col():
        return get_collection("users")

    @classmethod
    def get_by_id(cls, user_id: str) -> "User | None":
        try:
            doc = cls._col().find_one({"_id": ObjectId(user_id)})
        except Exception:
            return None
        return cls(doc) if doc else None

    @classmethod
    def get_by_username(cls, username: str) -> "User | None":
        doc = cls._col().find_one({"username": username})
        return cls(doc) if doc else None

    @classmethod
    def create(cls, username: str, password: str, role: str = "student") -> "User | None":
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        if cls.get_by_username(username):
            return None  # duplicate

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        doc = {
            "username": username,
            "password_hash": pw_hash,
            "role": role,
            "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        result = cls._col().insert_one(doc)
        doc["_id"] = result.inserted_id
        return cls(doc)

    def check_password(self, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode(), self.password_hash.encode())
        except Exception:
            return False

    # ── Admin operations ──────────────────────────────────────────────────────
    @classmethod
    def all_users(cls) -> list[dict]:
        docs = cls._col().find({}, {"password_hash": 0})
        return [
            {
                "id": str(d["_id"]),
                "username": d["username"],
                "role": d.get("role", "student"),
                "is_active": d.get("is_active", True),
                "created_at": d.get("created_at", ""),
            }
            for d in docs
        ]

    @classmethod
    def update_user(cls, user_id: str, role: str | None = None, is_active: bool | None = None) -> bool:
        update: dict = {}
        if role is not None and role in VALID_ROLES:
            update["role"] = role
        if is_active is not None:
            update["is_active"] = is_active
        if not update:
            return False
        result = cls._col().update_one({"_id": ObjectId(user_id)}, {"$set": update})
        return result.matched_count > 0
