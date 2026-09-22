import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import PasswordResetToken, User


PASSWORD_RESET_TTL_MINUTES = 60


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_password_reset_token(
    db: Session,
    user: User,
) -> str:
    now = _utc_now()

    existing_tokens = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .all()
    )

    for existing_token in existing_tokens:
        existing_token.used_at = now

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    reset_token = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=(
            now
            + timedelta(
                minutes=PASSWORD_RESET_TTL_MINUTES
            )
        ),
    )

    db.add(reset_token)
    db.commit()

    return raw_token


def get_valid_password_reset_token(
    db: Session,
    raw_token: str,
) -> PasswordResetToken | None:
    if not raw_token:
        return None

    token_hash = _hash_token(raw_token)

    reset_token = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.token_hash
            == token_hash
        )
        .first()
    )

    if reset_token is None:
        return None

    if reset_token.used_at is not None:
        return None

    expires_at = reset_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    if expires_at <= _utc_now():
        return None

    return reset_token


def mark_password_reset_token_used(
    db: Session,
    reset_token: PasswordResetToken,
) -> None:
    now = _utc_now()

    outstanding_tokens = (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id
            == reset_token.user_id,
            PasswordResetToken.used_at.is_(None),
        )
        .all()
    )

    for token in outstanding_tokens:
        token.used_at = now

    db.commit()