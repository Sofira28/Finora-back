"""Sesiones de servidor con etapas (plan.md §2, RF-AUTH-07, RNF-AUTH-02).

La cookie solo lleva un identificador aleatorio; en la BD se guarda su hash. Una sesión
`active` expira tras 30 minutos sin actividad o 7 días después de creada; las parciales
(`mfa_pending`, `link_pending`) duran 5 minutos y no se renuevan.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from enum import StrEnum

from fastapi import Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession

COOKIE_NAME = "finora_session"

IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(days=7)
PARTIAL_TIMEOUT = timedelta(minutes=5)
REAUTH_WINDOW = timedelta(minutes=5)  # RF-AUTH-21
# last_activity_at se escribe como máximo una vez por minuto.
TOUCH_INTERVAL = timedelta(minutes=1)

_TOKEN_BYTES = 32


class SessionStage(StrEnum):
    ACTIVE = "active"
    MFA_PENDING = "mfa_pending"
    LINK_PENDING = "link_pending"


def hash_session_token(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("utf-8")).digest()


def is_expired(session: AuthSession, now: datetime) -> bool:
    if now >= session.expires_at:
        return True
    return session.stage == SessionStage.ACTIVE and now - session.last_activity_at >= IDLE_TIMEOUT


def is_recently_reauthenticated(session: AuthSession, now: datetime) -> bool:
    return (
        session.reauthenticated_at is not None and now - session.reauthenticated_at < REAUTH_WINDOW
    )


def create_session(
    db: Session,
    user_id: uuid.UUID,
    stage: SessionStage,
    now: datetime,
    *,
    pending_google_subject: str | None = None,
) -> tuple[str, AuthSession]:
    """Crea una sesión y devuelve (valor en claro para la cookie, sesión)."""
    raw = secrets.token_urlsafe(_TOKEN_BYTES)
    lifetime = ABSOLUTE_TIMEOUT if stage == SessionStage.ACTIVE else PARTIAL_TIMEOUT
    session = AuthSession(
        token_hash=hash_session_token(raw),
        user_id=user_id,
        stage=stage,
        csrf_token=secrets.token_urlsafe(_TOKEN_BYTES),
        created_at=now,
        last_activity_at=now,
        expires_at=now + lifetime,
        pending_google_subject=pending_google_subject,
    )
    db.add(session)
    db.flush()
    return raw, session


def load_session(db: Session, raw: str, now: datetime) -> AuthSession | None:
    """Sesión vigente para el valor de la cookie; borra la sesión si ya expiró."""
    session = db.scalar(
        select(AuthSession).where(AuthSession.token_hash == hash_session_token(raw))
    )
    if session is None:
        return None
    if is_expired(session, now):
        db.delete(session)
        db.flush()
        return None
    if session.stage == SessionStage.ACTIVE and now - session.last_activity_at >= TOUCH_INTERVAL:
        session.last_activity_at = now
        db.flush()
    return session


def rotate_session(
    db: Session,
    old: AuthSession,
    stage: SessionStage,
    now: datetime,
    *,
    pending_google_subject: str | None = None,
) -> tuple[str, AuthSession]:
    """Reemplaza la sesión al cambiar de etapa: identificador nuevo (fijación de sesión)."""
    user_id = old.user_id
    db.delete(old)
    db.flush()
    return create_session(db, user_id, stage, now, pending_google_subject=pending_google_subject)


def revoke_session(db: Session, session: AuthSession) -> None:
    db.delete(session)
    db.flush()


def revoke_all_sessions(
    db: Session, user_id: uuid.UUID, *, except_id: uuid.UUID | None = None
) -> None:
    statement = delete(AuthSession).where(AuthSession.user_id == user_id)
    if except_id is not None:
        statement = statement.where(AuthSession.id != except_id)
    db.execute(statement)


def set_session_cookie(response: Response, raw: str) -> None:
    # Sin Max-Age: cookie de sesión del navegador; la expiración real la controla el servidor.
    response.set_cookie(COOKIE_NAME, raw, httponly=True, secure=True, samesite="lax", path="/")


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="lax", path="/")
