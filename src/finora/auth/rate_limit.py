"""Limitación de intentos con ventanas de tiempo en PostgreSQL (RNF-AUTH-04, ADR-0002).

- Por cuenta: 5 fallos (contraseña o código MFA) en 15 minutos bloquean esa cuenta hasta
  que el fallo más antiguo salga de la ventana. La clave es el hash del correo normalizado,
  así que también cuenta para correos sin cuenta (sin enumeración).
- Por IP: todos los intentos, con límites configurables.

El conteo previo y el registro no son atómicos: con peticiones simultáneas se pueden colar
unos pocos intentos de más, aceptable para este propósito.
"""

import hashlib
import ipaddress
import math
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from finora.auth.models import LoginAttempt
from finora.auth.passwords import normalize_email
from finora.config import Settings
from finora.errors import ApiProblemError


@dataclass(frozen=True)
class Limit:
    kind: str
    max_attempts: int
    window: timedelta


ACCOUNT_FAILURES = Limit("account_failure", 5, timedelta(minutes=15))


def login_ip_limit(settings: Settings) -> Limit:
    return Limit("ip_login", settings.rate_limit_login_per_ip, timedelta(minutes=15))


def email_ip_limit(settings: Settings) -> Limit:
    # Registro, recuperación y reenvío de verificación comparten el límite.
    return Limit("ip_email", settings.rate_limit_email_per_ip, timedelta(hours=1))


# Ventana más larga: los intentos más viejos ya no influyen en ningún límite.
LONGEST_WINDOW = timedelta(hours=1)


def account_key(email: str) -> str:
    digest = hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()
    return f"account:{digest}"


def client_ip(request: Request, settings: Settings) -> str | None:
    """IP del cliente; None si no es una IP válida (p. ej. el cliente de pruebas)."""
    candidate = request.client.host if request.client else None
    if settings.trusted_proxy:
        # El proxy de confianza agrega la IP real al final de X-Forwarded-For.
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            candidate = forwarded.split(",")[-1].strip()
    if candidate is None:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def ip_key(ip: str | None) -> str:
    return f"ip:{ip or 'unknown'}"


def too_many_attempts(retry_after: int) -> ApiProblemError:
    return ApiProblemError(
        429,
        "too_many_attempts",
        "Demasiados intentos. Intenta de nuevo en unos minutos.",
        headers={"Retry-After": str(retry_after)},
    )


def check(db: Session, key: str, limit: Limit, now: datetime) -> None:
    """Lanza 429 con Retry-After si `key` ya alcanzó el límite dentro de la ventana."""
    since = now - limit.window
    count, oldest = db.execute(
        select(func.count(), func.min(LoginAttempt.created_at)).where(
            LoginAttempt.key == key,
            LoginAttempt.kind == limit.kind,
            LoginAttempt.created_at > since,
        )
    ).one()
    if count >= limit.max_attempts:
        wait = (oldest + limit.window - now).total_seconds()
        raise too_many_attempts(max(1, math.ceil(wait)))


def record(db: Session, key: str, limit: Limit, now: datetime) -> None:
    db.add(LoginAttempt(key=key, kind=limit.kind, created_at=now))
    db.flush()


def purge_attempts(db: Session, now: datetime) -> int:
    result = db.execute(delete(LoginAttempt).where(LoginAttempt.created_at <= now - LONGEST_WINDOW))
    return result.rowcount  # type: ignore[attr-defined, no-any-return]
