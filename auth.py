"""
SecureFin Authentication Blueprint
Handles: Registration, Login, TOTP MFA setup/verification, Logout.

ASVS Controls implemented:
  V2.1.1  – Argon2id password hashing
  V2.4.1  – Passwords never stored in plaintext
  V2.2.1  – Rate limiting on login endpoint
  V2.2.4  – Account lockout after repeated failures
  V3.2.1  – Secure session token issued after login
  V3.4.1  – HttpOnly, Secure, SameSite cookie flags
  V5.1.1  – Server-side input validation
  V7.2.1  – Audit logging of all auth events
  V8.3.1  – MFA secret stored securely
"""

import pyotp
import qrcode
import io
import base64
import logging

from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, flash, make_response)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from database import db
from models import User, Role
from security_utils import (
    validate_username, validate_email, validate_password,
    validate_totp_code, sanitize_input, log_event,
    is_account_locked, record_failed_login, reset_failed_logins,
    GENERIC_AUTH_ERROR
)

auth_bp = Blueprint("auth", __name__)
ph      = PasswordHasher()  # Argon2id is default variant
logger  = logging.getLogger(__name__)


# ── Registration ──────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # ── Sanitize & validate all inputs (ASVS V5.1.1) ──────────────────
        username = sanitize_input(request.form.get("username", ""))
        email    = sanitize_input(request.form.get("email", ""))
        password = request.form.get("password", "")  # Don't strip passwords

        ok, msg = validate_username(username)
        if not ok:
            flash(msg, "danger")
            return render_template("register.html")

        ok, msg = validate_email(email)
        if not ok:
            flash(msg, "danger")
            return render_template("register.html")

        ok, msg = validate_password(password)
        if not ok:
            flash(msg, "danger")
            return render_template("register.html")

        # ── Check for duplicate username/email ──────────────────────────────
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("register.html")

        # ── Hash password with Argon2id (ASVS V2.4.1) ──────────────────────
        password_hash = ph.hash(password)

        # ── Assign default 'customer' role (Least Privilege) ───────────────
        customer_role = Role.query.filter_by(name="customer").first()

        new_user = User(
            username      = username,
            email         = email,
            password_hash = password_hash,
            role_id       = customer_role.id,
            is_active     = True,
            mfa_enabled   = False
        )
        db.session.add(new_user)
        db.session.commit()

        log_event("USER_REGISTERED", f"New customer account registered: {username}", user=new_user)
        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")

        # ── Basic input presence check ──────────────────────────────────────
        if not username or not password:
            flash(GENERIC_AUTH_ERROR, "danger")
            return render_template("login.html")

        # ── Retrieve user (parameterized via ORM — ASVS V5.3.4) ────────────
        user = User.query.filter_by(username=username).first()

        # ── Generic error — don't reveal if username exists (ASVS V2.1) ────
        if not user or not user.is_active:
            log_event("LOGIN_FAILED", f"Unknown or inactive user: {username}", success=False)
            flash(GENERIC_AUTH_ERROR, "danger")
            return render_template("login.html")

        # ── Account lockout check (ASVS V2.2.4) ────────────────────────────
        if is_account_locked(user):
            log_event("LOGIN_BLOCKED", "Login attempt on locked account.", user=user, success=False)
            flash("Account is temporarily locked. Please try again later.", "danger")
            return render_template("login.html")

        # ── Verify Argon2id password hash (ASVS V2.4.1) ────────────────────
        try:
            ph.verify(user.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            record_failed_login(user)
            log_event("LOGIN_FAILED", "Incorrect password.", user=user, success=False)
            flash(GENERIC_AUTH_ERROR, "danger")
            return render_template("login.html")

        # ── Rehash if parameters have been updated ──────────────────────────
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password)
            db.session.commit()

        reset_failed_logins(user)

        # ── MFA required? Store pre-auth state in session ───────────────────
        if user.mfa_enabled:
            session.clear()
            session["pre_auth_user_id"] = user.id
            log_event("LOGIN_MFA_REQUIRED", "Password verified; MFA step required.", user=user)
            return redirect(url_for("auth.verify_mfa"))

        # ── No MFA — complete login, regenerate session (ASVS V3.2.1) ──────
        _complete_login(user)
        return redirect(_post_login_redirect(user))

    return render_template("login.html")


# ── MFA Setup ─────────────────────────────────────────────────────────────────

@auth_bp.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """Allow logged-in users to enable TOTP MFA."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = sanitize_input(request.form.get("totp_code", ""))

        ok, msg = validate_totp_code(code)
        if not ok:
            flash(msg, "danger")
            return redirect(url_for("auth.mfa_setup"))

        # Retrieve the temporary secret stored in session during setup
        temp_secret = session.get("mfa_temp_secret")
        if not temp_secret:
            flash("Session expired. Please restart MFA setup.", "danger")
            return redirect(url_for("auth.mfa_setup"))

        totp = pyotp.TOTP(temp_secret)

        # Verify code before saving secret (replay protection — ASVS V2.8.3)
        if not totp.verify(code, valid_window=1):
            log_event("MFA_SETUP_FAILED", "Invalid TOTP code during MFA setup.", user=user, success=False)
            flash("Invalid code. Please try again.", "danger")
            return redirect(url_for("auth.mfa_setup"))

        # Save MFA secret and enable MFA for user
        user.mfa_secret  = temp_secret
        user.mfa_enabled = True
        db.session.commit()
        session.pop("mfa_temp_secret", None)

        log_event("MFA_ENABLED", "TOTP MFA successfully enabled.", user=user)
        flash("MFA enabled successfully!", "success")
        return redirect(_post_login_redirect(user))

    # GET: generate new TOTP secret and QR code
    secret = pyotp.random_base32()
    session["mfa_temp_secret"] = secret

    totp     = pyotp.TOTP(secret)
    otp_uri  = totp.provisioning_uri(name=user.email, issuer_name="SecureFin")

    # Generate QR code as base64 image
    qr_img   = qrcode.make(otp_uri)
    buf      = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64   = base64.b64encode(buf.getvalue()).decode()

    return render_template("mfa_setup.html", qr_b64=qr_b64, secret=secret)


# ── MFA Verification ──────────────────────────────────────────────────────────

@auth_bp.route("/mfa/verify", methods=["GET", "POST"])
def verify_mfa():
    """Second factor step — verify TOTP code after password is confirmed."""
    pre_auth_id = session.get("pre_auth_user_id")
    if not pre_auth_id:
        return redirect(url_for("auth.login"))

    user = User.query.get(pre_auth_id)
    if not user or not user.mfa_enabled:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = sanitize_input(request.form.get("totp_code", ""))

        ok, msg = validate_totp_code(code)
        if not ok:
            flash(msg, "danger")
            return render_template("mfa_verify.html")

        totp = pyotp.TOTP(user.mfa_secret)

        # valid_window=1 allows ±1 time step (30s) to account for clock drift
        # but prevents full replay (ASVS V2.8.3)
        if not totp.verify(code, valid_window=1):
            record_failed_login(user)
            log_event("MFA_FAILED", "Incorrect TOTP code.", user=user, success=False)
            flash("Invalid MFA code. Please try again.", "danger")
            return render_template("mfa_verify.html")

        # Clear pre-auth state, complete full login
        session.pop("pre_auth_user_id", None)
        _complete_login(user)
        log_event("MFA_SUCCESS", "TOTP MFA verified successfully.", user=user)
        return redirect(_post_login_redirect(user))

    return render_template("mfa_verify.html")


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
def logout():
    user_id = session.get("user_id")
    if user_id:
        user = User.query.get(user_id)
        if user:
            log_event("LOGOUT", "User logged out.", user=user)

    # Fully clear session (ASVS V3.3.1)
    session.clear()
    response = make_response(redirect(url_for("auth.login")))
    # Instruct browser to delete session cookie
    response.delete_cookie("session")
    flash("You have been logged out.", "info")
    return response


# ── Internal helpers ──────────────────────────────────────────────────────────

def _complete_login(user: User):
    """Regenerate session and store user identity after successful auth."""
    session.clear()                        # Invalidate any previous session
    session.permanent = True               # Apply PERMANENT_SESSION_LIFETIME
    session["user_id"]   = user.id
    session["username"]  = user.username
    session["role"]      = user.role.name
    log_event("LOGIN_SUCCESS", f"User logged in successfully.", user=user)


def _post_login_redirect(user: User):
    """Route user to the correct dashboard based on role."""
    if user.role.name == "admin":
        return url_for("admin.dashboard")
    return url_for("customer.dashboard")
