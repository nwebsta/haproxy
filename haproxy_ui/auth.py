"""Anmeldung: ein Admin-Konto, Argon2, serverseitige Sitzungen, Sperre nach Fehlversuchen."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import AppConfig
from .models import Admin, AuthSession, LoginAttempt, utcnow

SESSION_COOKIE = "haproxy_ui_session"
LOGIN_CSRF_COOKIE = "haproxy_ui_login_csrf"
MIN_PASSWORD_LENGTH = 12

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("timing-ausgleich")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def set_admin(db: Session, username: str, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen haben")
    if not username or len(username) > 64 or any(c.isspace() for c in username):
        raise ValueError("Benutzername ungültig")
    admin = db.scalars(select(Admin)).first()
    if admin is None:
        db.add(Admin(username=username, password_hash=_ph.hash(password)))
    else:
        admin.username = username
        admin.password_hash = _ph.hash(password)
    # Alle bestehenden Sitzungen beenden
    db.execute(delete(AuthSession))
    db.commit()


def admin_exists(db: Session) -> bool:
    return db.scalars(select(Admin)).first() is not None


def verify_login(db: Session, username: str, password: str) -> bool:
    admin = db.scalars(select(Admin)).first()
    if admin is None:
        try:
            _ph.verify(_DUMMY_HASH, password + "x")
        except VerificationError:
            pass
        return False
    try:
        _ph.verify(admin.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    if not hmac.compare_digest(admin.username.encode(), username.encode()):
        return False
    if _ph.check_needs_rehash(admin.password_hash):
        admin.password_hash = _ph.hash(password)
        db.commit()
    return True


# -- Sperre nach Fehlversuchen -------------------------------------------------


def locked_until(db: Session, ip: str) -> datetime | None:
    row = db.get(LoginAttempt, ip)
    if row and row.locked_until and row.locked_until > utcnow():
        return row.locked_until
    return None


def register_failure(db: Session, ip: str, config: AppConfig) -> None:
    now = utcnow()
    window = timedelta(minutes=config.lockout_minutes)
    row = db.get(LoginAttempt, ip)
    if row is None:
        row = LoginAttempt(ip=ip, failures=0)
        db.add(row)
    if row.last_failure is None or now - row.last_failure > window:
        row.failures = 0
    row.failures += 1
    row.last_failure = now
    if row.failures >= config.max_failed_logins:
        row.locked_until = now + window
        row.failures = 0
    db.commit()


def reset_failures(db: Session, ip: str) -> None:
    row = db.get(LoginAttempt, ip)
    if row is not None:
        db.delete(row)
        db.commit()


# -- Sitzungen -------------------------------------------------------------------


def create_session(db: Session, config: AppConfig) -> str:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(AuthSession).where(AuthSession.expires_at < now))
    db.add(
        AuthSession(
            token_hash=_hash_token(token),
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + timedelta(hours=config.session_hours),
        )
    )
    db.commit()
    return token


def get_session(db: Session, token: str | None) -> AuthSession | None:
    if not token or len(token) > 200:
        return None
    sess = db.get(AuthSession, _hash_token(token))
    if sess is None:
        return None
    if sess.expires_at < utcnow():
        db.delete(sess)
        db.commit()
        return None
    return sess


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(AuthSession).where(AuthSession.token_hash == _hash_token(token)))
        db.commit()


def tokens_equal(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())
