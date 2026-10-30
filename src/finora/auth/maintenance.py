"""Limpieza de datos de autenticación vencidos (plan.md §5).

Mientras no haya hosting definido no existe un programador de tareas: la limpieza corre en la
primera petición de autenticación tras arrancar y luego como máximo una vez por hora.
"""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Delete, delete, or_
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession, AuthToken, OAuthFlow
from finora.auth.rate_limit import purge_attempts
from finora.auth.sessions import IDLE_TIMEOUT

logger = logging.getLogger(__name__)

PURGE_INTERVAL = timedelta(hours=1)


@dataclass(frozen=True)
class PurgeResult:
    sessions: int
    tokens: int
    oauth_flows: int
    login_attempts: int


def _count(db: Session, statement: Delete) -> int:
    return db.execute(statement).rowcount  # type: ignore[attr-defined, no-any-return]


def purge_expired(db: Session, now: datetime) -> PurgeResult:
    """Borra sesiones, tokens, flujos OAuth e intentos que ya no sirven. No hace commit."""
    result = PurgeResult(
        sessions=_count(
            db,
            delete(AuthSession).where(
                or_(
                    AuthSession.expires_at <= now,
                    AuthSession.last_activity_at <= now - IDLE_TIMEOUT,
                )
            ),
        ),
        tokens=_count(db, delete(AuthToken).where(AuthToken.expires_at <= now)),
        oauth_flows=_count(db, delete(OAuthFlow).where(OAuthFlow.expires_at <= now)),
        login_attempts=purge_attempts(db, now),
    )
    return result


class PeriodicPurge:
    """Ejecuta `purge_expired` como máximo una vez por intervalo (una instancia por app)."""

    def __init__(self, interval: timedelta = PURGE_INTERVAL) -> None:
        self._interval = interval
        self._last_run: datetime | None = None
        self._lock = threading.Lock()

    def _due(self, now: datetime) -> bool:
        with self._lock:
            if self._last_run is not None and now - self._last_run < self._interval:
                return False
            self._last_run = now  # otra petición concurrente ya no la repite
            return True

    def maybe_run(self, db: Session, now: datetime) -> PurgeResult | None:
        if not self._due(now):
            return None
        try:
            result = purge_expired(db, now)
            db.commit()
        except Exception:
            # La limpieza nunca debe tumbar la petición del usuario.
            db.rollback()
            logger.exception("Falló la limpieza de datos de autenticación vencidos")
            return None
        logger.info("Limpieza de autenticación: %s", result)
        return result
