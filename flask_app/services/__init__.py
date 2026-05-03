"""
flask_app/services/__init__.py — Shared services package.

Contains cross-cutting concerns used across all blueprints:
  - decorators.py   : RBAC access-control decorators
  - utils.py        : prevention_summary, int_param helpers
  - ai_prevention.py: Groq LLaMA AI prevention advice engine
"""
