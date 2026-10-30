"""Perfil y cambio de contraseña (T-AUTH-BE-08).

CA-AUTH-11, RF-AUTH-09, RF-AUTH-14, RF-AUTH-15, RN-AUTH-03, RN-AUTH-08.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession, ExternalIdentity, MfaCredential, SecurityEvent, User
from finora.auth.passwords import hash_password, verify_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock
from finora.email import InMemoryEmailSender

CLAVE = "caballo correcto batería grapa"
NUEVA = "elefante azul cuaderno lámpara"


def _usuario(db: Session, clock: FrozenClock, email: str, name: str) -> User:
    user = User(
        email=email,
        name=name,
        password_hash=hash_password(CLAVE),
        email_verified_at=clock.now(),
        created_at=clock.now(),
    )
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    return _usuario(db_session, clock, "ana@correo.com", "Ana")


@pytest.fixture
def csrf(client: TestClient, db_session: Session, ana: User, clock: FrozenClock) -> dict[str, str]:
    """Inicia sesión como Ana y devuelve la cabecera CSRF."""
    raw, sesion = create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


def test_perfil(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.get("/api/v1/me")
    assert response.status_code == 200
    assert response.json() == {
        "name": "Ana",
        "email": "ana@correo.com",
        "has_password": True,
        "google_linked": False,
        "mfa_enabled": False,
    }


def test_perfil_refleja_google_y_mfa(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    db_session.add_all(
        [
            ExternalIdentity(
                user_id=ana.id, provider="google", subject="g1", created_at=clock.now()
            ),
            MfaCredential(
                user_id=ana.id,
                secret_encrypted=b"x",
                confirmed_at=clock.now(),
                created_at=clock.now(),
            ),
        ]
    )
    db_session.flush()
    body = client.get("/api/v1/me").json()
    assert (body["google_linked"], body["mfa_enabled"]) == (True, True)


def test_perfil_sin_sesion(client: TestClient) -> None:
    response = client.get("/api/v1/me")
    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"
    assert response.headers["cache-control"] == "no-store"


# --- Nombre (RN-AUTH-03) ------------------------------------------------------------------


def test_cambiar_nombre(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str]
) -> None:
    response = client.patch("/api/v1/me", json={"name": "  Ana María  "}, headers=csrf)
    assert response.status_code == 200
    assert response.json()["name"] == "Ana María"
    db_session.refresh(ana)
    assert ana.name == "Ana María"


@pytest.mark.parametrize("name", ["", "   ", "a" * 101])
def test_nombre_invalido(client: TestClient, csrf: dict[str, str], name: str) -> None:
    assert client.patch("/api/v1/me", json={"name": name}, headers=csrf).status_code == 422


def test_cambiar_nombre_exige_csrf(client: TestClient, csrf: dict[str, str]) -> None:
    assert client.patch("/api/v1/me", json={"name": "Otra"}).status_code == 403


# --- CA-AUTH-11: aislamiento --------------------------------------------------------------


def test_ca_auth_11_solo_ve_y_modifica_lo_propio(
    client: TestClient, db_session: Session, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    luis = _usuario(db_session, clock, "luis@correo.com", "Luis")
    assert client.get("/api/v1/me").json()["email"] == "ana@correo.com"
    assert client.get(f"/api/v1/me?user_id={luis.id}").json()["email"] == "ana@correo.com"
    # No existe forma de indicar otro usuario: el campo se rechaza.
    response = client.patch(
        "/api/v1/me", json={"name": "Hackeado", "id": str(luis.id)}, headers=csrf
    )
    assert response.status_code == 422
    client.patch("/api/v1/me", json={"name": "Ana Nueva"}, headers=csrf)
    db_session.refresh(luis)
    assert luis.name == "Luis"


# --- Cambio de contraseña (RF-AUTH-15, RF-AUTH-09) ----------------------------------------


def test_cambiar_contrasena_cierra_las_demas_sesiones(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    email_outbox: InMemoryEmailSender,
    csrf: dict[str, str],
) -> None:
    create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())  # otro dispositivo
    response = client.post(
        "/api/v1/me/password",
        json={"current_password": CLAVE, "new_password": NUEVA},
        headers=csrf,
    )
    assert response.status_code == 204
    db_session.refresh(ana)
    assert verify_password(ana.password_hash, NUEVA)
    # Solo queda la sesión actual, que sigue funcionando.
    assert len(db_session.scalars(select(AuthSession)).all()) == 1
    assert client.get("/api/v1/me").status_code == 200
    assert [c.subject for c in email_outbox.outbox] == ["Tu contraseña de FINORA cambió"]
    assert "password_changed" in db_session.scalars(select(SecurityEvent.type)).all()


def test_contrasena_actual_incorrecta(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post(
        "/api/v1/me/password",
        json={"current_password": "no es la clave", "new_password": NUEVA},
        headers=csrf,
    )
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"
    assert response.json()["title"] == "La contraseña actual no es correcta."


def test_cinco_intentos_fallidos_bloquean_el_cambio(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    mala = {"current_password": "no es la clave", "new_password": NUEVA}
    for _ in range(5):
        assert client.post("/api/v1/me/password", json=mala, headers=csrf).status_code == 401
    buena = {"current_password": CLAVE, "new_password": NUEVA}
    assert client.post("/api/v1/me/password", json=buena, headers=csrf).status_code == 429
    clock.advance(timedelta(minutes=15))
    assert client.post("/api/v1/me/password", json=buena, headers=csrf).status_code == 204


def test_nueva_contrasena_debe_cumplir_la_politica(
    client: TestClient, db_session: Session, ana: User, csrf: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/me/password",
        json={"current_password": CLAVE, "new_password": "q1w2e3r4t5y6"},
        headers=csrf,
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == "too_common"
    db_session.refresh(ana)
    assert verify_password(ana.password_hash, CLAVE)
