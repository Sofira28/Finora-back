"""Registro de eventos de seguridad (RNF-AUTH-06).

Solo se guardan el tipo, el usuario (si se conoce), la IP y el instante: nunca
contraseñas, tokens, códigos ni el correo.
"""

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from finora.auth.models import SecurityEvent


class SecurityEventType(StrEnum):
    REGISTERED = "registered"
    EMAIL_VERIFIED = "email_verified"
    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    MFA_FAILED = "mfa_failed"
    LOGOUT = "logout"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105 - nombre del evento
    PASSWORD_RESET = "password_reset"  # noqa: S105 - nombre del evento
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
    GOOGLE_LINKED = "google_linked"
    REAUTHENTICATED = "reauthenticated"
    ACCOUNT_DELETED = "account_deleted"


def record_event(
    db: Session,
    event_type: SecurityEventType,
    now: datetime,
    *,
    user_id: uuid.UUID | None = None,
    ip: str | None = None,
) -> None:
    db.add(SecurityEvent(user_id=user_id, type=event_type, ip=ip, created_at=now))
    db.flush()
