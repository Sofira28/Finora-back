"""Recuperación de contraseña y primera contraseña (T-AUTH-BE-08).

CA-AUTH-07, CA-AUTH-03 (recuperación), RF-AUTH-08, RF-AUTH-09, RF-AUTH-18, VAL-AUTH-09.
"""

import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession, SecurityEvent, User
from finora.auth.passwords import hash_password, verify_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.auth.tokens import TokenPurpose, issue_token
from finora.clock import FrozenClock
from finora.config import Settings
from finora.email import InMemoryEmailSender, OutgoingEmail

CLAVE = "caballo correcto batería grapa"
NUEVA = "elefante azul cuaderno lámpara"
FORGOT = "/api/v1/auth/password/forgot"
RESET = "/api/v1/auth/password/reset"


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


def _token(correo: OutgoingEmail) -> str:
    encontrado = re.search(r"/restablecer-contrasena\?token=([\w-]+)", correo.text)
    assert encontrado, correo.text
    return encontrado.group(1)


def _sesiones(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(AuthSession)) or 0


def _login(client: TestClient, password: str) -> int:
    response = client.post(
        "/api/v1/auth/login", json={"email": "ana@correo.com", "password": password}
    )
    return response.status_code


def test_ca_auth_07_recuperacion_completa(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    email_outbox: InMemoryEmailSender,
) -> None:
    # Dos dispositivos con sesión abierta.
    create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())

    assert client.post(FORGOT, json={"email": "ana@correo.com"}).status_code == 202
    [correo] = email_outbox.outbox
    assert correo.subject == "Restablece tu contraseña de FINORA"
    token = _token(correo)

    assert client.post(RESET, json={"token": token, "new_password": NUEVA}).status_code == 204
    assert _sesiones(db_session) == 0  # RF-AUTH-09: se cerraron las dos sesiones
    aviso = email_outbox.outbox[-1]
    assert aviso.subject == "Tu contraseña de FINORA cambió"

    reuso = client.post(RESET, json={"token": token, "new_password": "otra clave distinta 9"})
    assert reuso.status_code == 400
    assert reuso.json()["code"] == "invalid_token"
    assert _login(client, CLAVE) == 401
    assert _login(client, NUEVA) == 200
    assert "password_reset" in db_session.scalars(select(SecurityEvent.type)).all()


def test_ca_auth_03_misma_respuesta_exista_o_no_la_cuenta(
    client: TestClient, ana: User, email_outbox: InMemoryEmailSender
) -> None:
    existe = client.post(FORGOT, json={"email": "ana@correo.com"})
    no_existe = client.post(FORGOT, json={"email": "nadie@correo.com"})
    assert (existe.status_code, existe.json()) == (no_existe.status_code, no_existe.json())
    assert existe.json()["message"] == (
        "Si existe una cuenta con ese correo, te enviamos un enlace para restablecer la contraseña."
    )
    assert [c.to for c in email_outbox.outbox] == ["ana@correo.com"]


def test_contrasena_invalida_no_gasta_el_enlace(
    client: TestClient, ana: User, email_outbox: InMemoryEmailSender
) -> None:
    client.post(FORGOT, json={"email": "ana@correo.com"})
    token = _token(email_outbox.outbox[0])
    response = client.post(RESET, json={"token": token, "new_password": "corta"})
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "new_password"]
    assert response.json()["errors"][0]["type"] == "too_short"
    assert client.post(RESET, json={"token": token, "new_password": NUEVA}).status_code == 204


def test_nueva_contrasena_no_puede_ser_el_correo(
    client: TestClient, ana: User, email_outbox: InMemoryEmailSender
) -> None:
    client.post(FORGOT, json={"email": "ana@correo.com"})
    token = _token(email_outbox.outbox[0])
    response = client.post(RESET, json={"token": token, "new_password": "ana@correo.com"})
    assert response.json()["errors"][0]["type"] == "matches_email"


def test_enlace_vence_a_la_hora(
    client: TestClient, ana: User, clock: FrozenClock, email_outbox: InMemoryEmailSender
) -> None:
    client.post(FORGOT, json={"email": "ana@correo.com"})
    clock.advance(timedelta(hours=1))
    token = _token(email_outbox.outbox[0])
    assert client.post(RESET, json={"token": token, "new_password": NUEVA}).status_code == 400


def test_nueva_solicitud_invalida_la_anterior(
    client: TestClient, ana: User, email_outbox: InMemoryEmailSender
) -> None:
    client.post(FORGOT, json={"email": "ana@correo.com"})
    client.post(FORGOT, json={"email": "ana@correo.com"})
    viejo, nuevo = (_token(c) for c in email_outbox.outbox)
    assert client.post(RESET, json={"token": viejo, "new_password": NUEVA}).status_code == 400
    assert client.post(RESET, json={"token": nuevo, "new_password": NUEVA}).status_code == 204


def test_enlace_de_verificacion_no_sirve_para_restablecer(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    token = issue_token(db_session, ana.id, TokenPurpose.VERIFY_EMAIL, clock.now())
    assert client.post(RESET, json={"token": token, "new_password": NUEVA}).status_code == 400


def test_limite_por_ip(client: TestClient, settings: Settings) -> None:
    settings.rate_limit_email_per_ip = 1
    assert client.post(FORGOT, json={"email": "ana@correo.com"}).status_code == 202
    assert client.post(FORGOT, json={"email": "ana@correo.com"}).status_code == 429


# --- Cuentas solo con Google (RF-AUTH-18) -------------------------------------------------


@pytest.fixture
def solo_google(db_session: Session, ana: User) -> User:
    ana.password_hash = None
    db_session.flush()
    return ana


def test_olvide_mi_contrasena_crea_la_primera(
    client: TestClient, db_session: Session, solo_google: User, email_outbox: InMemoryEmailSender
) -> None:
    client.post(FORGOT, json={"email": "ana@correo.com"})
    [correo] = email_outbox.outbox
    assert correo.subject == "Crea tu contraseña de FINORA"
    assert (
        client.post(RESET, json={"token": _token(correo), "new_password": NUEVA}).status_code == 204
    )
    db_session.refresh(solo_google)
    assert verify_password(solo_google.password_hash, NUEVA)


def test_crear_contrasena_desde_el_perfil(
    client: TestClient,
    db_session: Session,
    solo_google: User,
    clock: FrozenClock,
    email_outbox: InMemoryEmailSender,
) -> None:
    raw, sesion = create_session(db_session, solo_google.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    csrf = {"X-CSRF-Token": sesion.csrf_token}
    response = client.post("/api/v1/me/password/setup", json={}, headers=csrf)
    assert response.status_code == 202
    assert response.json() == {
        "message": "Te enviamos un enlace a tu correo para crear tu contraseña."
    }
    [correo] = email_outbox.outbox
    assert correo.subject == "Crea tu contraseña de FINORA"


def test_crear_contrasena_si_ya_tiene_una(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    raw, sesion = create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    response = client.post(
        "/api/v1/me/password/setup", json={}, headers={"X-CSRF-Token": sesion.csrf_token}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "password_already_set"
