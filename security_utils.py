"""
SecureFin Security Utilities
Centralised helpers for input validation, audit logging, and account lockout.
ASVS V5.1 (Input Validation), V7.2 (Audit Logging), V2.2 (Account Lockout)
"""

import re
import logging
from datetime import datetime, timedelta
from flask import request
from database import db
from models import AuditLog

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION_MINUTES = 15


# ── Input Validation (ASVS V5.1.1, V5.1.3) ───────────────────────────────────

def validate_username(username: str) -> tuple[bool, str]:
    """
    Validate username: 3–30 alphanumeric characters and underscores only.
    Rejects special characters to prevent injection attacks.
    """
    if not username or not isinstance(username, str):
        return False, "Username is required."
    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username may only contain letters, numbers, and underscores."
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate email format using a strict regex pattern.
    ASVS V5.1.3 – validates format, not just presence.
    """
    if not email or not isinstance(email, str):
        return False, "Email is required."
    email = email.strip().lower()
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return False, "Invalid email address format."
    if len(email) > 120:
        return False, "Email address is too long."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """
    Enforce strong password policy (ASVS V2.1.1):
    - Minimum 12 characters
    - At least one uppercase, one lowercase, one digit, one special character
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_totp_code(code: str) -> tuple[bool, str]:
    """Validate that TOTP code is exactly 6 digits."""
    if not code or not isinstance(code, str):
        return False, "MFA code is required."
    code = code.strip()
    if not re.match(r"^\d{6}$", code):
        return False, "MFA code must be exactly 6 digits."
    return True, ""


def sanitize_input(value: str, max_length: int = 255) -> str:
    """
    Strip leading/trailing whitespace and truncate to max_length.
    Output encoding — never trust raw user input.
    """
    if not value:
        return ""
    return str(value).strip()[:max_length]


# ── Audit Logging (ASVS V7.2.1) ──────────────────────────────────────────────
# Audit logging records security-relevant events without storing passwords,
# OTP codes, MFA secrets, or session tokens.
def log_event(event_type: str, description: str, user=None, success: bool = True):
    """
    Write a security event to the audit log table and application log file.
    Records: event type, description, IP address, timestamp, user ID.
    """
    ip = request.remote_addr if request else "N/A"
    username = user.username if user else "anonymous"
    user_id  = user.id if user else None

    entry = AuditLog(
        user_id     = user_id,
        username    = username,
        event_type  = event_type,
        description = description,
        ip_address  = ip,
        success     = success
    )
    db.session.add(entry)
    db.session.commit()

    # Also write to file-based audit log
    level = logging.INFO if success else logging.WARNING
    logger.log(level, "[AUDIT] %s | user=%s | ip=%s | %s", event_type, username, ip, description)


# ── Account Lockout (ASVS V2.2.4) ────────────────────────────────────────────

def is_account_locked(user) -> bool:
    """Return True if account is currently locked out."""
    if user.locked_until and datetime.utcnow() < user.locked_until:
        return True
    return False


def record_failed_login(user):
    """Increment failed login counter and lock account if threshold exceeded."""
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED_LOGINS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        db.session.commit()
        log_event(
            "ACCOUNT_LOCKED",
            f"Account locked after {MAX_FAILED_LOGINS} failed attempts.",
            user=user,
            success=False
        )
    else:
        db.session.commit()


def reset_failed_logins(user):
    """Reset failed login counter after successful login."""
    user.failed_logins = 0
    user.locked_until  = None
    user.last_login    = datetime.utcnow()
    db.session.commit()


# ── Secure Error Messages ─────────────────────────────────────────────────────

GENERIC_AUTH_ERROR = "Invalid username or password."  # Never reveal which field is wrong (ASVS V2.1)
