"""Tokens de un solo uso: verificación de correo y restablecimiento de contraseña.

RN-AUTH-04/05 y RNF-AUTH-05: se generan con un generador criptográfico, en la BD solo se
guarda su hash SHA-256, emitir uno nuevo invalida los anteriores sin usar y el consumo es
atómico (dos usos simultáneos: solo uno tiene éxito).
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from finora.auth.models import AuthToken


class TokenPurpose(StrEnum):
    VERIFY_EMAIL = "verify_email"
    RESET_PASSWORD = "reset_password"  # noqa: S105 - nombre del propósito, no una clave


TOKEN_TTL: dict[TokenPurpose, timedelta] = {
    TokenPurpose.VERIFY_EMAIL: timedelta(hours=24),  # RN-AUTH-04
    TokenPurpose.RESET_PASSWORD: timedelta(hours=1),  # RN-AUTH-05
}

# 32 bytes aleatorios (256 bits): no hace falta un hash lento para guardarlos.
_TOKEN_BYTES = 32


def hash_token(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("utf-8")).digest()


def issue_token(db: Session, user_id: uuid.UUID, purpose: TokenPurpose, now: datetime) -> str:
    """Crea un token nuevo y devuelve su valor en claro (solo para el enlace del correo)."""
    db.execute(
        delete(AuthToken).where(
            AuthToken.user_id == user_id,
            AuthToken.purpose == purpose,
            AuthToken.used_at.is_(None),
        )
    )
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    db.add(
        AuthToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(raw),
            created_at=now,
            expires_at=now + TOKEN_TTL[purpose],
        )
    )
    db.flush()
    return raw


def peek_token(db: Session, raw: str, purpose: TokenPurpose, now: datetime) -> uuid.UUID | None:
    """Usuario de un token vigente, sin consumirlo (p. ej. para validar antes de usarlo)."""
    return db.scalar(
        select(AuthToken.user_id).where(
            AuthToken.token_hash == hash_token(raw),
            AuthToken.purpose == purpose,
            AuthToken.used_at.is_(None),
            AuthToken.expires_at > now,
        )
    )


def consume_token(db: Session, raw: str, purpose: TokenPurpose, now: datetime) -> uuid.UUID | None:
    """Marca el token como usado y devuelve su usuario; None si es inválido, vencido o usado.

    Un único UPDATE con la condición `used_at IS NULL`: si dos peticiones llegan a la vez,
    PostgreSQL bloquea la fila y la segunda ya no la encuentra sin usar.
    """
    statement = (
        update(AuthToken)
        .where(
            AuthToken.token_hash == hash_token(raw),
            AuthToken.purpose == purpose,
            AuthToken.used_at.is_(None),
            AuthToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(AuthToken.user_id)
    )
    return db.execute(statement).scalar_one_or_none()
