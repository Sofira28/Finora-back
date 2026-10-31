"""Dependencias de FastAPI para sesión, usuario y reautenticación (RN-AUTH-08).

El usuario sale siempre de la sesión: ningún endpoint recibe un identificador de usuario.
"""

from collections.abc import Callable, Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from finora.auth.csrf import check_csrf_token, check_origin_and_content_type
from finora.auth.maintenance import PeriodicPurge
from finora.auth.models import AuthSession, User
from finora.auth.sessions import (
    COOKIE_NAME,
    SessionStage,
    is_recently_reauthenticated,
    load_session,
)
from finora.clock import Clock, get_clock
from finora.config import Settings, get_settings
from finora.db import get_db_session
from finora.db.rls import bind_user, unbind_user
from finora.errors import ApiProblemError

DbSession = Annotated[Session, Depends(get_db_session)]
ClockDep = Annotated[Clock, Depends(get_clock)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def session_expired() -> ApiProblemError:
    return ApiProblemError(401, "session_expired", "Tu sesión terminó. Inicia sesión de nuevo.")


def verify_request_origin(request: Request, settings: SettingsDep) -> None:
    """Dependencia de router para /auth y /me: Content-Type y Origin en métodos que modifican."""
    check_origin_and_content_type(request, settings.web_url)


def _cookie_session(request: Request, db: Session, clock: Clock) -> AuthSession | None:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return None
    session = load_session(db, raw, clock.now())
    # Guarda la renovación de actividad o el borrado de la sesión vencida.
    db.commit()
    return session


def optional_session(request: Request, db: DbSession, clock: ClockDep) -> AuthSession | None:
    session = _cookie_session(request, db, clock)
    if session is not None:
        check_csrf_token(request, session)
    return session


def previous_session(request: Request, db: DbSession, clock: ClockDep) -> AuthSession | None:
    """Sesión anterior al iniciar sesión, solo para revocarla: no exige CSRF.

    El inicio de sesión ya está protegido por Origin y Content-Type; exigir el token de
    una sesión vieja (p. ej. un paso MFA abandonado) impediría volver a entrar.
    """
    return _cookie_session(request, db, clock)


PreviousSession = Annotated[AuthSession | None, Depends(previous_session)]
OptionalSession = Annotated[AuthSession | None, Depends(optional_session)]


def require_session(*stages: SessionStage) -> Callable[[AuthSession | None], AuthSession]:
    """Exige una sesión en alguna de las etapas indicadas; si no, 401 session_expired."""

    def dependency(session: OptionalSession) -> AuthSession:
        if session is None or session.stage not in stages:
            raise session_expired()
        return session

    return dependency


current_session = require_session(SessionStage.ACTIVE)
CurrentSession = Annotated[AuthSession, Depends(current_session)]
PendingMfaSession = Annotated[AuthSession, Depends(require_session(SessionStage.MFA_PENDING))]
LinkPendingSession = Annotated[AuthSession, Depends(require_session(SessionStage.LINK_PENDING))]


def current_user(session: CurrentSession, db: DbSession) -> User:
    user = db.get(User, session.user_id)
    if user is None:  # no ocurre: la sesión se borra en cascada con el usuario
        raise session_expired()
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def user_db(user: CurrentUser, db: DbSession) -> Iterator[Session]:
    """Sesión de BD con el usuario fijado para RLS (ADR-0004): para datos financieros."""
    bind_user(db, user.id)
    try:
        yield db
    finally:
        unbind_user(db)


UserDb = Annotated[Session, Depends(user_db)]


def require_recent_reauth(session: CurrentSession, clock: ClockDep) -> AuthSession:
    """RF-AUTH-21: acciones sensibles exigen reautenticación en los últimos 5 minutos."""
    if not is_recently_reauthenticated(session, clock.now()):
        raise ApiProblemError(
            403, "reauthentication_required", "Confirma tu identidad para continuar."
        )
    return session


RecentlyReauthenticated = Annotated[AuthSession, Depends(require_recent_reauth)]


def purge_periodically(request: Request, db: DbSession, clock: ClockDep) -> None:
    """Limpieza oportunista de datos vencidos, como máximo una vez por hora (plan.md §5)."""
    purge: PeriodicPurge = request.app.state.auth_purge
    purge.maybe_run(db, clock.now())
