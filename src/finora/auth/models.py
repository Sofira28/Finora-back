"""Tablas de autenticación (FEAT-AUTH, plan.md §5; specs/database.md §5.1).

Los tokens, códigos e identificadores de sesión se guardan solo como hash. Todas las
claves foráneas a users borran en cascada, salvo security_events (RN-AUTH-07).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    LargeBinary,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, MappedColumn, mapped_column

from finora.db import Base


def _uuid_pk() -> MappedColumn[Any]:
    # UUIDv7: ordenado por tiempo, mejor localidad en índices que UUIDv4.
    return mapped_column(primary_key=True, default=uuid.uuid7)


def _instant(*, nullable: bool = False, index: bool = False) -> MappedColumn[Any]:
    # timestamptz (UTC, DP-DB-07). Los valores los pone la aplicación con su Clock,
    # para que las expiraciones se puedan probar.
    return mapped_column(DateTime(timezone=True), nullable=nullable, index=index)


def _user_fk(*, ondelete: str = "CASCADE", nullable: bool = False) -> MappedColumn[Any]:
    return mapped_column(ForeignKey("users.id", ondelete=ondelete), nullable=nullable, index=True)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        # El correo se guarda normalizado (RN-AUTH-01); el índice único va tras la clase.
        CheckConstraint("email = lower(btrim(email))", name="email_normalized"),
        CheckConstraint(
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 100", name="name_length"
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(Text)
    email_verified_at: Mapped[datetime | None] = _instant(nullable=True)
    name: Mapped[str] = mapped_column(Text)
    # Nulo en cuentas que solo usan Google.
    password_hash: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _instant()


# Unicidad sin distinguir mayúsculas (plan.md §5).
Index("uq_users_email_lower", func.lower(User.email), unique=True)


class ExternalIdentity(Base):
    __tablename__ = "external_identities"
    __table_args__ = (
        UniqueConstraint("provider", "subject", name="uq_external_identities_provider_subject"),
        CheckConstraint("provider IN ('google')", name="provider"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk()
    provider: Mapped[str] = mapped_column(Text)
    # `sub` de OpenID Connect: identificador estable, a diferencia del correo.
    subject: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _instant()


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint("stage IN ('active', 'mfa_pending', 'link_pending')", name="stage"),
        # Solo la etapa de vinculación guarda la identidad de Google pendiente.
        CheckConstraint(
            "(stage = 'link_pending') = (pending_google_subject IS NOT NULL)",
            name="pending_google_subject",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    user_id: Mapped[uuid.UUID] = _user_fk()
    stage: Mapped[str] = mapped_column(Text)
    csrf_token: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _instant()
    last_activity_at: Mapped[datetime] = _instant()
    expires_at: Mapped[datetime] = _instant()
    reauthenticated_at: Mapped[datetime | None] = _instant(nullable=True)
    # Reautenticación con Google superada, pendiente del código MFA (RF-AUTH-21).
    google_reauth_at: Mapped[datetime | None] = _instant(nullable=True)
    pending_google_subject: Mapped[str | None] = mapped_column(Text)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    __table_args__ = (
        CheckConstraint("purpose IN ('verify_email', 'reset_password')", name="purpose"),
        Index("ix_auth_tokens_user_id_purpose", "user_id", "purpose"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    purpose: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_at: Mapped[datetime] = _instant()
    expires_at: Mapped[datetime] = _instant()
    used_at: Mapped[datetime | None] = _instant(nullable=True)


class MfaCredential(Base):
    __tablename__ = "mfa_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    # Cifrado con AES-GCM (FINORA_MFA_ENCRYPTION_KEY).
    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary)
    # Nulo mientras la configuración no se confirma con un código (RF-AUTH-10).
    confirmed_at: Mapped[datetime | None] = _instant(nullable=True)
    # Último intervalo TOTP aceptado: impide reutilizar el mismo código.
    last_used_step: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = _instant()


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk()
    code_hash: Mapped[str] = mapped_column(Text)
    used_at: Mapped[datetime | None] = _instant(nullable=True)


class OAuthFlow(Base):
    __tablename__ = "oauth_flows"
    __table_args__ = (CheckConstraint("intent IN ('login', 'reauth')", name="intent"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    state_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    nonce: Mapped[str] = mapped_column(Text)
    code_verifier: Mapped[str] = mapped_column(Text)
    intent: Mapped[str] = mapped_column(Text)
    # Sesión que pidió la reautenticación; nulo en el inicio de sesión.
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="CASCADE"), index=True
    )
    # Versión de la política aceptada con el aviso junto al botón; solo se usa si se crea
    # una cuenta nueva (RF-AUTH-05).
    privacy_policy_version: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _instant()
    expires_at: Mapped[datetime] = _instant()


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempts_key_kind_created_at", "key", "kind", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # account:<hash del correo> o ip:<IP>; nunca el correo en claro.
    key: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _instant()


class DataConsent(Base):
    __tablename__ = "data_consents"

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = _user_fk()
    policy_version: Mapped[str] = mapped_column(Text)
    accepted_at: Mapped[datetime] = _instant()


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Se conserva el evento al eliminar la cuenta, sin vínculo con el usuario (SUP-AUTH-04).
    user_id: Mapped[uuid.UUID | None] = _user_fk(ondelete="SET NULL", nullable=True)
    type: Mapped[str] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(INET)
    created_at: Mapped[datetime] = _instant(index=True)
