# SecureFin – User Authentication & Authorization Module

**ITS69405 Software Secure Systems | Group Assignment 2**  
Taylor's University – School of Computer Science

---

## Overview

This is a functional prototype of the **User Authentication and Authorization Module** for SecureFin Sdn. Bhd.'s online customer portal. The prototype demonstrates secure software development practices aligned with OWASP ASVS Level 2 and the STRIDE threat model identified in the assignment.

### Features Implemented

| Feature | Description |
|---|---|
| User Registration | Input-validated account creation with Argon2id password hashing |
| Secure Login | Generic error messages, account lockout after 5 failed attempts |
| TOTP MFA | QR code setup + 6-digit TOTP verification (Google Authenticator compatible) |
| Session Management | HttpOnly, Secure, SameSite cookies; 30-minute timeout; session rotation |
| RBAC | Three roles: `customer`, `staff`, `admin` with enforced access control |
| Audit Logging | All auth events logged to database and file with timestamp + IP |
| Rate Limiting | 50 requests/hour per IP to mitigate DoS and brute-force |
| Admin Panel | User management, role assignment, audit log viewer |

---

## Prerequisites

- Python 3.11 or higher
- pip

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/your-group/securefin-auth.git
cd securefin-auth
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root (or set variables in your shell):

```bash
# Required in production — use a strong random value
SECRET_KEY=your-very-long-random-secret-key-here

# Set to True only when running behind HTTPS (production)
# SECURE_COOKIES=True
```

> **Security note:** Never commit the `.env` file. It is listed in `.gitignore`.

### 5. Run the prototype

```bash
python app.py
```

The application starts at: `http://127.0.0.1:5000`

---

## Default Credentials (for testing only)

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@12345!` |

> **Important:** Change the default admin password immediately in any non-testing environment.

---

## Security-Relevant Configuration

### SECRET_KEY
The Flask `SECRET_KEY` is used to sign session cookies. It must be:
- At least 32 random bytes
- Stored as an environment variable, **never hardcoded**
- Rotated if compromised

In `app.py`:
```python
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
```

### Session Cookie Flags
Configured in `app.py`:
```python
app.config["SESSION_COOKIE_HTTPONLY"] = True   # Prevents JavaScript access
app.config["SESSION_COOKIE_SECURE"]   = False  # Set True in production (HTTPS required)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
app.config["PERMANENT_SESSION_LIFETIME"] = 1800 # 30-minute timeout
```

### TLS / HTTPS
In production, this application must be deployed behind a reverse proxy (e.g., Nginx) with TLS 1.3. Set `SESSION_COOKIE_SECURE = True` when HTTPS is enabled.

Example Nginx configuration snippet:
```nginx
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers off;
```

### Database
SQLite is used for the prototype. For production, replace with PostgreSQL:
```python
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:pass@host/securefin"
```

### MFA Secrets
TOTP secrets are stored in the `users` table. In production, encrypt this column using a dedicated key management service (e.g., AWS KMS, Azure Key Vault).

### Audit Logs
- **Database:** `AuditLog` table in `securefin.db`
- **File:** `securefin_audit.log` in the project root

---

## Project Structure

```
securefin/
├── app.py              # Application factory, configuration, seeding
├── database.py         # SQLAlchemy instance
├── models.py           # Database models (User, Role, AuditLog)
├── auth.py             # Authentication blueprint (register, login, MFA, logout)
├── admin.py            # Admin blueprint (user management, audit logs)
├── customer.py         # Customer blueprint (dashboard, profile)
├── rbac.py             # RBAC decorators (login_required, role_required)
├── security_utils.py   # Input validation, audit logging, account lockout
├── requirements.txt    # Python dependencies
├── templates/          # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── mfa_setup.html
│   ├── mfa_verify.html
│   ├── customer_dashboard.html
│   ├── profile.html
│   ├── admin_dashboard.html
│   ├── admin_users.html
│   └── audit_logs.html
└── instance/
    └── securefin.db    # SQLite database (auto-created)
```

---

## OWASP ASVS Compliance Summary

| ASVS Ref | Requirement | Implementation | File |
|---|---|---|---|
| V2.1.1 | Passwords min 12 chars, complexity enforced | `validate_password()` | `security_utils.py` |
| V2.4.1 | Passwords hashed with Argon2id | `ph.hash(password)` | `auth.py` |
| V2.2.1 | Rate limiting on login | `Flask-Limiter` | `app.py` |
| V2.2.4 | Account lockout after 5 failures | `record_failed_login()` | `security_utils.py` |
| V2.8.3 | TOTP replay protection | `valid_window=1` | `auth.py` |
| V3.2.1 | New session on login | `session.clear()` + regeneration | `auth.py` |
| V3.4.1 | HttpOnly, Secure, SameSite cookies | Cookie config | `app.py` |
| V3.3.1 | Session invalidated on logout | `session.clear()` | `auth.py` |
| V4.1.1 | Server-side access control on every request | `@login_required`, `@role_required` | `rbac.py` |
| V4.1.3 | Deny by default | Default deny in role decorator | `rbac.py` |
| V5.1.1 | Server-side input validation | `validate_*()` functions | `security_utils.py` |
| V5.3.4 | Parameterised queries (ORM) | SQLAlchemy ORM | All route files |
| V7.2.1 | Audit logging of security events | `log_event()` | `security_utils.py` |
| V14.4.3 | Content-Security-Policy header | Meta CSP tag | `base.html` |

---

## Threat Mitigations Demonstrated

| Threat (from Q1) | Mitigation in Code |
|---|---|
| T1 – Credential theft | Argon2id hashing, rate limiting, account lockout |
| T2 – Session hijacking | HttpOnly/Secure/SameSite cookies, session timeout, rotation |
| T3 – MFA request tampering | Server-side TOTP validation, replay protection |
| T4 – Role modification | RBAC, admin-only route, audit logged |
| T5 – Repudiation | Full audit log with user ID, IP, timestamp |
| T6 – Database disclosure | ORM parameterized queries, Argon2id hashes |
| T7 – Token/MFA leakage | Secure cookies, short TOTP window |
| T8 – DoS on auth service | Flask-Limiter rate limiting, account lockout |
| T9 – Privilege escalation | `@role_required` deny-by-default decorator |
| T10 – Insider misuse | Separation of duties, audit logging of admin actions |

---

## Academic Integrity

This prototype was developed as original group work for ITS69405. All external libraries used are open-source and listed in `requirements.txt`. No AI-generated code was submitted without declaration per Taylor's University AI-use policy.
