"""
SecureFin Database Models
Stores user profiles, roles, sessions, and audit logs.
AES-256 encryption applied at the database/backup level (ASVS V6.2).
"""

from datetime import datetime
from database import db


class Role(db.Model):
    """Role-Based Access Control roles (ASVS V4.1)."""
    __tablename__ = "roles"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    users       = db.relationship("User", back_populates="role")

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model):
    """
    User accounts.
    Passwords stored as Argon2id hashes only — never plaintext (ASVS V2.4.1).
    """
    __tablename__ = "users"

    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    email           = db.Column(db.String(120), unique=True, nullable=False)
    password_hash   = db.Column(db.String(256), nullable=False)
    role_id         = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role            = db.relationship("Role", back_populates="users")

    is_active       = db.Column(db.Boolean, default=True)
    failed_logins   = db.Column(db.Integer, default=0)
    locked_until    = db.Column(db.DateTime, nullable=True)

    # MFA fields
    mfa_enabled     = db.Column(db.Boolean, default=False)
    mfa_secret      = db.Column(db.String(64), nullable=True)  # Encrypted TOTP secret

    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    last_login      = db.Column(db.DateTime, nullable=True)

    audit_logs      = db.relationship("AuditLog", back_populates="user", lazy="dynamic")

    def __repr__(self):
        return f"<User {self.username} [{self.role.name}]>"


class AuditLog(db.Model):
    """
    Tamper-evident audit log for all security-relevant events (ASVS V7.2.1).
    Records login attempts, access denials, privilege changes.
    """
    __tablename__ = "audit_logs"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user        = db.relationship("User", back_populates="audit_logs")
    username    = db.Column(db.String(80))           # Keep even if user deleted
    event_type  = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(500))
    ip_address  = db.Column(db.String(45))
    timestamp   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    success     = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<AuditLog {self.event_type} | {self.username} | {self.timestamp}>"
