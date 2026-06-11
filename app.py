"""
SecureFin - User Authentication & Authorization Module
ITS69405 Software Secure Systems - Group Assignment 2
"""

import os
import logging
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database import db
from auth import auth_bp
from admin import admin_bp
from customer import customer_bp

# ── Secure logging setup (ASVS V7.1.1) ───────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("securefin_audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)

    # ── Secure configuration (ASVS V2.1, V3.4) ───────────────────────────────
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securefin.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Secure session cookie settings (ASVS V3.4)
    app.config["SESSION_COOKIE_HTTPONLY"] = True   # Prevent JS access
    app.config["SESSION_COOKIE_SECURE"] = False    # Set True in production (requires HTTPS)
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
    app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30-minute session timeout

    # ── Rate limiter (ASVS V2.2.1 / mitigates T8 DoS, T1 brute-force) ────────
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # ── Database init ─────────────────────────────────────────────────────────
    db.init_app(app)

    # ── Register blueprints ───────────────────────────────────────────────────
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(customer_bp)

    with app.app_context():
        db.create_all()
        seed_roles()

    return app, limiter


def seed_roles():
    """Create default roles if they don't exist."""
    from models import Role, User
    from argon2 import PasswordHasher

    ph = PasswordHasher()

    roles_data = [
        {"name": "customer",  "description": "Standard customer account"},
        {"name": "staff",     "description": "Support staff account"},
        {"name": "admin",     "description": "System administrator"},
    ]
    for r in roles_data:
        if not Role.query.filter_by(name=r["name"]).first():
            db.session.add(Role(**r))
    db.session.commit()

    # Create a default admin account for testing
    if not User.query.filter_by(username="admin").first():
        admin_role = Role.query.filter_by(name="admin").first()
        admin_user = User(
            username="admin",
            email="admin@securefin.com",
            password_hash=ph.hash("Admin@12345!"),
            role_id=admin_role.id,
            is_active=True,
            mfa_enabled=False
        )
        db.session.add(admin_user)
        db.session.commit()
        logger.info("Default admin account created.")


if __name__ == "__main__":
    app, _ = create_app()
    # Debug=False in production; use a proper WSGI server
    app.run(debug=True, host="127.0.0.1", port=5000)
