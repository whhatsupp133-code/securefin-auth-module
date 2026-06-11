"""
SecureFin RBAC Decorators & Session Helpers
Enforces Role-Based Access Control on protected routes.

ASVS V4.1.1 – Access control enforced server-side on every request
ASVS V4.1.3 – Deny by default
ASVS V3.2.1 – Session validated on every protected request
"""

import logging
from functools import wraps
from flask import session, redirect, url_for, flash, request
from models import User
from security_utils import log_event

logger = logging.getLogger(__name__)


def get_current_user() -> User | None:
    """Retrieve the currently authenticated user from the session."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)


def login_required(f):
    """
    Decorator: Require valid session before allowing access.
    Redirects unauthenticated users to login (ASVS V3.2.1).
    Complete mediation — checks session on every request.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or not user.is_active:
            log_event(
                "ACCESS_DENIED",
                f"Unauthenticated access attempt to {request.path}",
                success=False
            )
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
# RBAC enforcement:
# Access is denied by default unless the current user has the required role.
# This mitigates privilege escalation and unauthorized admin access.
    """
    Decorator: Restrict route to users with specific roles.
    Implements RBAC deny-by-default (ASVS V4.1.3).
    Logs unauthorized access attempts (T9, T10 mitigation).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()

            # Must be logged in first
            if not user or not user.is_active:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("auth.login"))

            # Role check — deny by default if role not in allowed list
            if user.role.name not in roles:
                log_event(
                    "PRIVILEGE_ESCALATION_ATTEMPT",
                    f"User '{user.username}' (role={user.role.name}) attempted to access "
                    f"{request.path} — required roles: {roles}",
                    user=user,
                    success=False
                )
                flash("Access denied. You do not have permission to view this page.", "danger")
                # Redirect back to their own dashboard, not a generic 403
                if user.role.name == "admin":
                    return redirect(url_for("admin.dashboard"))
                return redirect(url_for("customer.dashboard"))

            return f(*args, **kwargs)
        return decorated
    return decorator
