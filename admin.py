"""
SecureFin Admin Blueprint
Protected routes restricted to admin role only.
Separation of Duties: admin actions are distinct from customer actions.
ASVS V4.1.1, V4.1.3
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from database import db
from models import User, Role, AuditLog
from rbac import login_required, role_required, get_current_user
from security_utils import log_event, sanitize_input

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/dashboard")
@login_required
@role_required("admin")          # Only admins — deny by default
def dashboard():
    users     = User.query.all()
    log_count = AuditLog.query.count()
    recent_logs = (AuditLog.query
                   .order_by(AuditLog.timestamp.desc())
                   .limit(20)
                   .all())
    return render_template("admin_dashboard.html",
                           users=users,
                           log_count=log_count,
                           recent_logs=recent_logs)


@admin_bp.route("/users")
@login_required
@role_required("admin")
def user_list():
    users = User.query.all()
    return render_template("admin_users.html", users=users)


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def toggle_user(user_id):
    """Enable or disable a user account."""
    admin = get_current_user()
    user  = User.query.get_or_404(user_id)

    # Prevent admin from disabling their own account
    if user.id == admin.id:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("admin.user_list"))

    user.is_active = not user.is_active
    db.session.commit()

    action = "enabled" if user.is_active else "disabled"
    log_event(
        "ADMIN_USER_TOGGLE",
        f"Admin '{admin.username}' {action} account for user '{user.username}'.",
        user=admin
    )
    flash(f"Account for '{user.username}' has been {action}.", "success")
    return redirect(url_for("admin.user_list"))


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def change_role(user_id):
    """
    Change a user's role.
    Requires admin approval — separation of duties (T4, T10 mitigation).
    All role changes are audit logged.
    """
    admin    = get_current_user()
    user     = User.query.get_or_404(user_id)
    new_role_name = sanitize_input(request.form.get("role", ""))

    # Validate role exists
    new_role = Role.query.filter_by(name=new_role_name).first()
    if not new_role:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("admin.user_list"))

    old_role = user.role.name
    user.role_id = new_role.id
    db.session.commit()

    log_event(
        "ROLE_CHANGED",
        f"Admin '{admin.username}' changed role of '{user.username}' "
        f"from '{old_role}' to '{new_role_name}'.",
        user=admin
    )
    flash(f"Role updated for '{user.username}'.", "success")
    return redirect(url_for("admin.user_list"))


@admin_bp.route("/audit-logs")
@login_required
@role_required("admin")
def audit_logs():
    """View all system audit logs — admin only."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template("audit_logs.html", logs=logs)
