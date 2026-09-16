"""Admin credentials, login lockout and TOTP helpers for the /admin login.

Admin accounts live in the database (table admin_users: PBKDF2 hash, role
admin/readonly, TOTP secret; passkeys in admin_passkeys) and are managed on
/admin/users or with scripts/manage_users.py. Two-factor authentication is
mandatory. The YAML file (OSC_ADMIN_USERS_PATH, bind-mounted) is read only for
usernames that are not in the database: it seeds the first start and serves
as a rescue entrance (such a user is a full admin and must set up MFA):

    users:
      terje: pbkdf2_sha256$600000$<salt_hex>$<hash_hex>

Hashes are created with scripts/hash_password.py. Only hashes are stored,
never plaintext. Failed attempts are rate limited per IP AND per username
(10 per 15 min each). Sessions themselves live in SQLite (see db.py) and are
managed by the login routes in main.py.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from pathlib import Path

import yaml
from fastapi import Request

from .config import env

USERS_PATH = Path(env("ADMIN_USERS_PATH", "/config/admin_users.yaml"))

# The ONE request header trusted to carry the real client IP (used for rate
# limits, login lockout, the audit log and the daily usage hash). Behind
# Cloudflare this is CF-Connecting-IP, which Cloudflare always overwrites.
# X-Forwarded-For is deliberately NOT consulted: Cloudflare appends the visitor
# to a client-supplied X-Forwarded-For, so its first element is attacker
# controlled. Set the variable to an empty string to use the socket address
# (no proxy in front).
CLIENT_IP_HEADER = env("CLIENT_IP_HEADER", "cf-connecting-ip").strip().lower()

PBKDF2_ITERATIONS = 600_000
MAX_FAILED = 10
FAILED_WINDOW = 15 * 60

SESSION_COOKIE = "osc_admin"
SESSION_IDLE_SECONDS = 8 * 3600       # logged out after 8 h without activity
SESSION_MAX_SECONDS = 24 * 3600       # ...and after 24 h regardless

# Failed-login timestamps keyed by "ip:<addr>" and "user:<name>"
_failed_attempts: dict[str, list[float]] = {}


class LoginRequired(Exception):
    """Raised by the admin dependency when no valid session cookie is present."""


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.strip().split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# Verified against when the username does not exist, so a login attempt costs
# one PBKDF2 run whether or not the user exists (no user-enumeration timing).
_DUMMY_HASH = hash_password("dummy")


def load_users() -> dict[str, str]:
    if not USERS_PATH.exists():
        return {}
    raw = yaml.safe_load(USERS_PATH.read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in (raw.get("users") or {}).items()}


def client_ip(request: Request) -> str:
    """Client IP from the single trusted proxy header, else the socket address."""
    if CLIENT_IP_HEADER:
        value = request.headers.get(CLIENT_IP_HEADER, "")
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _recent_failures(key: str) -> list[float]:
    now = time.time()
    attempts = [t for t in _failed_attempts.get(key, []) if t > now - FAILED_WINDOW]
    if attempts:
        _failed_attempts[key] = attempts
    else:
        _failed_attempts.pop(key, None)  # do not keep a key per IP/user forever
    return attempts


def is_locked_out(ip: str, username: str) -> bool:
    return (
        len(_recent_failures(f"ip:{ip}")) >= MAX_FAILED
        or len(_recent_failures(f"user:{username}")) >= MAX_FAILED
    )


def _register_failure(ip: str, username: str) -> None:
    now = time.time()
    _failed_attempts.setdefault(f"ip:{ip}", []).append(now)
    if username:
        _failed_attempts.setdefault(f"user:{username}", []).append(now)


def find_user(database, username: str) -> dict | None:
    """The user record from the database, else from the YAML file (rescue
    entrance: such a user is a full admin without MFA). None if unknown."""
    user = database.get_user(username)
    if user is not None:
        return user
    stored = load_users().get(username)
    if stored is None:
        return None
    return {"username": username, "password_hash": stored, "role": "admin", "disabled": 0,
            "totp_secret": None, "totp_confirmed_at": None, "from_yaml": True}


def authenticate(username: str, password: str, ip: str, user: dict | None) -> bool:
    """True if the password matches the user record. Records a failure
    otherwise. Callers must check `is_locked_out` first. A missing user still
    costs one PBKDF2 run (no user-enumeration timing)."""
    stored = user["password_hash"] if user else None
    ok = verify_password(password, stored if stored is not None else _DUMMY_HASH)
    if stored is None or not ok or user.get("disabled"):
        _register_failure(ip, username)
        return False
    return True


def register_failure(ip: str, username: str) -> None:
    """A failed TOTP code counts like a failed password."""
    _register_failure(ip, username)


# --- TOTP (RFC 6238) -----------------------------------------------------

TOTP_ISSUER = "Ocean Software Check"
TOTP_STEP = 30


def new_totp_secret() -> str:
    import pyotp

    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def totp_qr_svg(uri: str) -> str:
    """The provisioning URI as an inline SVG (no raster libraries needed)."""
    import qrcode
    import qrcode.image.svg

    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=6, border=2)
    return image.to_string(encoding="unicode")


def verify_totp(secret: str, code: str, *, now: float | None = None) -> int | None:
    """The time step the code belongs to if it is valid in the current step
    or one step either side (clock drift), else None."""
    import pyotp

    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    base = int((now if now is not None else time.time()) // TOTP_STEP)
    for step in (base, base - 1, base + 1):
        if hmac.compare_digest(totp.at(step * TOTP_STEP), code):
            return step
    return None
