"""Limpieza de datos de autenticación vencidos (T-AUTH-BE-11, plan.md §5)."""

from datetime import timedelta
from unittest.mock import MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.maintenance import PeriodicPurge, PurgeResult, purge_expired
from finora.auth.models import AuthSession, AuthToken, LoginAttempt, OAuthFlow, User
from finora.auth.sessions import SessionStage, create_session
from finora.auth.tokens import TokenPurpose, hash_token, issue_token
from finora.clock import FrozenClock


def _usuario(db: Session, clock: FrozenClock) -> User:
    user = User(
        email="ana@correo.com",
        name="Ana",
        email_verified_at=clock.now(),
        created_at=clock.now(),
    )
    db.add(user)
    db.flush()
    return user


def _flujo(db: Session, clock: FrozenClock, state: str) -> None:
    db.add(
        OAuthFlow(
            state_hash=hash_token(state),
            nonce="n",
            code_verifier="v" * 43,
            intent="login",
            created_at=clock.now(),
            expires_at=clock.now() + timedelta(minutes=10),
        )
    )
    db.flush()


def _cuenta(db: Session, model: type) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


def test_borra_solo_lo_vencido(db_session: Session, clock: FrozenClock) -> None:
    user = _usuario(db_session, clock)
    inicio = clock.now()
    # Creados al inicio.
    create_session(db_session, user.id, SessionStage.ACTIVE, inicio)  # vencerá por inactividad
    create_session(db_session, user.id, SessionStage.MFA_PENDING, inicio)  # vence a los 5 min
    issue_token(db_session, user.id, TokenPurpose.RESET_PASSWORD, inicio)  # vence a la hora
    issue_token(db_session, user.id, TokenPurpose.VERIFY_EMAIL, inicio)  # vence a las 24 h
    _flujo(db_session, clock, "viejo")  # vence a los 10 min
    db_session.add(LoginAttempt(key="ip:1.2.3.4", kind="ip", created_at=inicio))

    clock.advance(timedelta(minutes=55))
    # Creados 55 minutos después: aún vigentes.
    _, activa = create_session(db_session, user.id, SessionStage.ACTIVE, clock.now())
    _flujo(db_session, clock, "nuevo")
    db_session.add(LoginAttempt(key="ip:1.2.3.4", kind="ip", created_at=clock.now()))
    db_session.flush()

    clock.advance(timedelta(minutes=5))  # 1 h desde el inicio
    result = purge_expired(db_session, clock.now())
    assert result == PurgeResult(sessions=2, tokens=1, oauth_flows=1, login_attempts=1)
    assert db_session.scalars(select(AuthSession.id)).all() == [activa.id]
    assert db_session.scalars(select(AuthToken.purpose)).all() == ["verify_email"]
    assert _cuenta(db_session, OAuthFlow) == 1
    assert _cuenta(db_session, LoginAttempt) == 1


def test_sesion_activa_al_limite_de_7_dias(db_session: Session, clock: FrozenClock) -> None:
    user = _usuario(db_session, clock)
    _, sesion = create_session(db_session, user.id, SessionStage.ACTIVE, clock.now())
    clock.advance(timedelta(days=7))
    sesion.last_activity_at = clock.now()  # activa hasta el final
    db_session.flush()
    assert purge_expired(db_session, clock.now()).sessions == 1


def test_como_maximo_una_vez_por_hora(db_session: Session, clock: FrozenClock) -> None:
    purge = PeriodicPurge()
    assert purge.maybe_run(db_session, clock.now()) is not None
    clock.advance(timedelta(minutes=59))
    assert purge.maybe_run(db_session, clock.now()) is None
    clock.advance(timedelta(minutes=1))
    assert purge.maybe_run(db_session, clock.now()) is not None


def test_un_fallo_no_rompe_la_peticion(clock: FrozenClock) -> None:
    db = MagicMock()
    db.execute.side_effect = RuntimeError("BD caída")
    assert PeriodicPurge().maybe_run(db, clock.now()) is None
    db.rollback.assert_called_once()


def test_corre_en_la_primera_peticion_de_autenticacion(
    client: TestClient, db_session: Session, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock)
    issue_token(db_session, user.id, TokenPurpose.RESET_PASSWORD, clock.now() - timedelta(hours=2))
    assert _cuenta(db_session, AuthToken) == 1
    assert client.get("/api/v1/auth/session").status_code == 200
    assert _cuenta(db_session, AuthToken) == 0
    # Dentro de la hora siguiente ya no vuelve a correr.
    issue_token(db_session, user.id, TokenPurpose.VERIFY_EMAIL, clock.now() - timedelta(days=2))
    client.get("/api/v1/auth/session")
    assert _cuenta(db_session, AuthToken) == 1
