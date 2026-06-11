"""
SecureFin Customer Blueprint
Protected routes accessible only to authenticated customers.
RBAC enforced via decorators — customers cannot access admin routes.
"""

from flask import Blueprint, render_template, session
from rbac import login_required, role_required, get_current_user
from models import AuditLog

customer_bp = Blueprint("customer", __name__, url_prefix="/customer")


@customer_bp.route("/dashboard")
@login_required
@role_required("customer", "staff", "admin")  # All authenticated users
def dashboard():
    user = get_current_user()
    # Customers only see their own audit logs (Least Privilege)
    recent_logs = (AuditLog.query
                   .filter_by(user_id=user.id)
                   .order_by(AuditLog.timestamp.desc())
                   .limit(10)
                   .all())
    return render_template("customer_dashboard.html", user=user, logs=recent_logs)


@customer_bp.route("/profile")
@login_required
@role_required("customer", "staff", "admin")
def profile():
    user = get_current_user()
    return render_template("profile.html", user=user)
