"""Reautenticación reciente (T-AUTH-BE-09). RF-AUTH-21."""

from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from finora.auth import mfa
from finora.auth.models import AuthSession, MfaCredential, SecurityEvent, User
from finora.auth.passwords import hash_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock
from finora.config import Settings

CLAVE = "caballo correcto batería grapa"
SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - secreto TOTP de prueba
REAUTH = "/api/v1/auth/reauthenticate"


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    user = User(
        email="ana@correo.com",
        name="Ana",
        password_hash=hash_password(CLAVE),
        email_verified_at=clock.now(),
        created_at=clock.now(),
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture
def csrf(client: TestClient, db_session: Session, ana: User, clock: FrozenClock) -> dict[str, str]:
    raw, sesion = create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


@pytest.fixture
def con_mfa(
    db_session: Session, ana: User, clock: FrozenClock, settings: Settings
) -> MfaCredential:
    credential = MfaCredential(
        user_id=ana.id,
        secret_encrypted=mfa.encrypt_secret(settings.mfa_key, ana.id, SECRET),
        confirmed_at=clock.now(),
        created_at=clock.now(),
    )
    db_session.add(credential)
    db_session.flush()
    return credential


def _setup(client: TestClient, csrf: dict[str, str]) -> int:
    """Una acción que exige reautenticación reciente."""
    return client.post("/api/v1/me/mfa/setup", json={}, headers=csrf).status_code


def test_reautenticacion_vale_cinco_minutos(
    client: TestClient, db_session: Session, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    assert _setup(client, csrf) == 403
    assert client.post(REAUTH, json={"password": CLAVE}, headers=csrf).status_code == 204
    sesion = db_session.scalars(select(AuthSession)).one()
    assert sesion.reauthenticated_at == clock.now()
    assert "reauthenticated" in db_session.scalars(select(SecurityEvent.type)).all()
    clock.advance(timedelta(minutes=4, seconds=59))
    assert _setup(client, csrf) == 200
    clock.advance(timedelta(seconds=1))
    assert _setup(client, csrf) == 403


def test_contrasena_incorrecta(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post(REAUTH, json={"password": "no es la clave"}, headers=csrf)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"
    assert _setup(client, csrf) == 403


def test_cinco_fallos_bloquean(client: TestClient, csrf: dict[str, str]) -> None:
    for _ in range(5):
        client.post(REAUTH, json={"password": "no es la clave"}, headers=csrf)
    response = client.post(REAUTH, json={"password": CLAVE}, headers=csrf)
    assert response.status_code == 429


def test_con_mfa_exige_el_codigo(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str], con_mfa: MfaCredential
) -> None:
    assert client.post(REAUTH, json={"password": CLAVE}, headers=csrf).status_code == 401
    malo = {"password": CLAVE, "code": "000000"}
    assert client.post(REAUTH, json=malo, headers=csrf).status_code == 401
    bueno = {"password": CLAVE, "code": pyotp.TOTP(SECRET).at(clock.now())}
    assert client.post(REAUTH, json=bueno, headers=csrf).status_code == 204
    # El mismo código no se acepta otra vez.
    assert client.post(REAUTH, json=bueno, headers=csrf).status_code == 401


def test_codigo_correcto_con_contrasena_incorrecta_no_gasta_el_codigo(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str], con_mfa: MfaCredential
) -> None:
    code = pyotp.TOTP(SECRET).at(clock.now())
    malo = {"password": "no es la clave", "code": code}
    assert client.post(REAUTH, json=malo, headers=csrf).status_code == 401
    bueno = {"password": CLAVE, "code": code}
    assert client.post(REAUTH, json=bueno, headers=csrf).status_code == 204


def test_cuenta_solo_con_google(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str]
) -> None:
    ana.password_hash = None
    db_session.flush()
    assert client.post(REAUTH, json={"password": CLAVE}, headers=csrf).status_code == 401


def test_exige_sesion_y_csrf(client: TestClient, csrf: dict[str, str]) -> None:
    assert client.post(REAUTH, json={"password": CLAVE}).status_code == 403
    client.cookies.clear()
    assert client.post(REAUTH, json={"password": CLAVE}, headers=csrf).status_code == 401
