"""Eliminación de la cuenta (T-AUTH-BE-11).

CA-AUTH-10, RF-AUTH-16, RN-AUTH-07, SUP-AUTH-04.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Table, func, select
from sqlalchemy.orm import Session

from finora.auth import rate_limit
from finora.auth.models import (
    AuthSession,
    DataConsent,
    ExternalIdentity,
    LoginAttempt,
    MfaCredential,
    MfaRecoveryCode,
    OAuthFlow,
    SecurityEvent,
    User,
)
from finora.auth.passwords import hash_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.auth.tokens import TokenPurpose, hash_token, issue_token
from finora.clock import FrozenClock
from finora.db.base import Base
from finora.email import InMemoryEmailSender

CLAVE = "caballo correcto batería grapa"


def _usuario(db: Session, clock: FrozenClock, email: str) -> User:
    user = User(
        email=email,
        name=email.split("@")[0],
        password_hash=hash_password(CLAVE),
        email_verified_at=clock.now(),
        created_at=clock.now(),
    )
    db.add(user)
    db.flush()
    return user


def _poblar(db: Session, user: User, clock: FrozenClock) -> None:
    """Un registro en cada tabla que depende del usuario."""
    now = clock.now()
    _, sesion = create_session(db, user.id, SessionStage.ACTIVE, now)
    issue_token(db, user.id, TokenPurpose.RESET_PASSWORD, now)
    db.add_all(
        [
            MfaCredential(user_id=user.id, secret_encrypted=b"x", confirmed_at=now, created_at=now),
            MfaRecoveryCode(user_id=user.id, code_hash=f"h-{user.id}"),
            ExternalIdentity(
                user_id=user.id, provider="google", subject=f"g-{user.id}", created_at=now
            ),
            DataConsent(user_id=user.id, policy_version="0", accepted_at=now),
            OAuthFlow(
                state_hash=hash_token(f"s-{user.id}"),
                nonce="n",
                code_verifier="v" * 43,
                intent="reauth",
                session_id=sesion.id,
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            ),
            LoginAttempt(key=rate_limit.account_key(user.email), kind="account", created_at=now),
            SecurityEvent(
                user_id=user.id, type="login_succeeded", ip="203.0.113.7", created_at=now
            ),
        ]
    )
    db.flush()


def _tablas_del_usuario() -> list[Table]:
    """Toda tabla con clave foránea a users.id (incluidas las de features futuras)."""
    return [
        table
        for table in Base.metadata.sorted_tables
        if any(fk.column.table.name == "users" for fk in table.foreign_keys)
    ]


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    return _usuario(db_session, clock, "ana@correo.com")


@pytest.fixture
def csrf(client: TestClient, db_session: Session, ana: User, clock: FrozenClock) -> dict[str, str]:
    """Sesión activa de Ana, recién reautenticada."""
    raw, sesion = create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    sesion.reauthenticated_at = clock.now()
    db_session.flush()
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


def _eliminar(client: TestClient, csrf: dict[str, str], confirmation: str = "ELIMINAR") -> int:
    response = client.request(
        "DELETE", "/api/v1/me", json={"confirmation": confirmation}, headers=csrf
    )
    return response.status_code


def test_ca_auth_10_eliminacion_inmediata(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    csrf: dict[str, str],
    email_outbox: InMemoryEmailSender,
) -> None:
    luis = _usuario(db_session, clock, "luis@correo.com")
    _poblar(db_session, ana, clock)  # incluye otra sesión de Ana (segundo dispositivo)
    _poblar(db_session, luis, clock)
    ana_id = ana.id

    response = client.request(
        "DELETE", "/api/v1/me", json={"confirmation": "ELIMINAR"}, headers=csrf
    )
    assert response.status_code == 204
    assert 'finora_session="";' in response.headers["set-cookie"]
    db_session.expire_all()

    # Sus datos dejan de existir en todas las tablas que dependen del usuario.
    assert db_session.get(User, ana_id) is None
    for table in _tablas_del_usuario():
        if table.name == "security_events":
            continue
        for fk in table.foreign_keys:
            if fk.column.table.name == "users":
                restantes = db_session.scalar(
                    select(func.count()).select_from(table).where(fk.parent == ana_id)
                )
                assert restantes == 0, table.name
    assert db_session.scalar(select(func.count()).select_from(OAuthFlow)) == 1  # el de Luis
    cuenta = rate_limit.account_key("ana@correo.com")
    assert db_session.scalar(select(func.count()).where(LoginAttempt.key == cuenta)) == 0

    # Los eventos se conservan sin datos que la identifiquen (SUP-AUTH-04).
    eventos = db_session.scalars(select(SecurityEvent).where(SecurityEvent.user_id.is_(None))).all()
    assert {e.type for e in eventos} == {"login_succeeded", "account_deleted"}
    assert all(e.ip is None for e in eventos)

    # Luis no se ve afectado.
    assert db_session.get(User, luis.id) is not None
    assert db_session.scalar(select(func.count()).where(AuthSession.user_id == luis.id)) == 1
    assert db_session.scalar(select(SecurityEvent.ip).where(SecurityEvent.user_id == luis.id))

    # Todas sus sesiones quedan inválidas, y el correo puede registrarse de nuevo, vacío.
    assert client.get("/api/v1/me").status_code == 401
    registro = {
        "email": "ana@correo.com",
        "name": "Ana Nueva",
        "password": CLAVE,
        "privacy_policy_version": "0",
    }
    assert client.post("/api/v1/auth/register", json=registro).status_code == 202
    assert email_outbox.outbox[-1].subject == "Confirma tu correo en FINORA"
    nueva = db_session.scalars(select(User).where(User.email == "ana@correo.com")).one()
    assert nueva.id != ana_id
    assert nueva.email_verified_at is None


def test_exige_reautenticacion_reciente(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    clock.advance(timedelta(minutes=5))
    response = client.request(
        "DELETE", "/api/v1/me", json={"confirmation": "ELIMINAR"}, headers=csrf
    )
    assert response.status_code == 403
    assert response.json()["code"] == "reauthentication_required"
    assert db_session.get(User, ana.id) is not None


@pytest.mark.parametrize("confirmation", ["", "eliminar", "ELIMINAR ", "BORRAR"])
def test_confirmacion_incorrecta(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str], confirmation: str
) -> None:
    response = client.request(
        "DELETE", "/api/v1/me", json={"confirmation": confirmation}, headers=csrf
    )
    assert response.status_code == 422
    assert response.json()["errors"] == [
        {
            "loc": ["body", "confirmation"],
            "type": "confirmation_mismatch",
            "message": "Escribe ELIMINAR para confirmar.",
        }
    ]
    assert db_session.get(User, ana.id) is not None


def test_exige_csrf(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str]
) -> None:
    assert _eliminar(client, {}) == 403
    assert db_session.get(User, ana.id) is not None


def test_sin_sesion(client: TestClient) -> None:
    assert _eliminar(client, {}) == 401


def test_cuenta_solo_con_google(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str]
) -> None:
    ana.password_hash = None
    db_session.flush()
    assert _eliminar(client, csrf) == 204
    assert db_session.get(User, ana.id) is None
