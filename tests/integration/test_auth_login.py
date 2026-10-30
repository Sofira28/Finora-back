"""Inicio y cierre de sesión y consulta de sesión (T-AUTH-BE-07).

CA-AUTH-02, CA-AUTH-03 (inicio de sesión), CA-AUTH-09, RF-AUTH-04/06, VAL-AUTH-05 a 07.
"""

from datetime import timedelta

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession, MfaCredential, SecurityEvent, User
from finora.auth.passwords import hash_password, needs_rehash
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock
from finora.config import Settings

CLAVE = "caballo correcto batería grapa"
LOGIN = {"email": "ana@correo.com", "password": CLAVE}
INCORRECTAS = {
    "code": "invalid_credentials",
    "title": "El correo o la contraseña no son correctos.",
}


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


def _sesiones(db: Session) -> list[AuthSession]:
    return list(db.scalars(select(AuthSession)))


def _csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/api/v1/auth/session").json()["csrf_token"]}


# --- Inicio de sesión ---------------------------------------------------------------------


def test_inicio_de_sesion_crea_sesion_y_cookie(
    client: TestClient, db_session: Session, ana: User
) -> None:
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.status_code == 200
    assert response.json() == {"next": "app"}
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert all(a in cookie for a in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"))
    [sesion] = _sesiones(db_session)
    assert (sesion.user_id, sesion.stage) == (ana.id, "active")
    tipos = db_session.scalars(select(SecurityEvent.type)).all()
    assert tipos == ["login_succeeded"]


def test_correo_sin_distinguir_mayusculas(client: TestClient, ana: User) -> None:
    login = {"email": " ANA@Correo.com ", "password": CLAVE}
    assert client.post("/api/v1/auth/login", json=login).status_code == 200


def test_ca_auth_03_mismo_error_exista_o_no_la_cuenta(client: TestClient, ana: User) -> None:
    mala_clave = client.post("/api/v1/auth/login", json={**LOGIN, "password": CLAVE + "x"})
    sin_cuenta = client.post(
        "/api/v1/auth/login", json={"email": "nadie@correo.com", "password": CLAVE}
    )
    mal_formado = client.post("/api/v1/auth/login", json={"email": "no-es-correo", "password": "x"})
    for response in (mala_clave, sin_cuenta, mal_formado):
        assert response.status_code == 401
        assert {k: response.json()[k] for k in INCORRECTAS} == INCORRECTAS
        assert "set-cookie" not in response.headers


def test_ca_auth_02_correo_sin_verificar(
    client: TestClient, db_session: Session, ana: User
) -> None:
    ana.email_verified_at = None
    db_session.flush()
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.status_code == 403
    assert response.json()["code"] == "email_not_verified"
    assert response.json()["title"] == (
        "Confirma tu correo para continuar. ¿Te enviamos el enlace de nuevo?"
    )
    assert "set-cookie" not in response.headers
    assert _sesiones(db_session) == []


def test_cuenta_solo_con_google_no_entra_con_contrasena(
    client: TestClient, db_session: Session, ana: User
) -> None:
    ana.password_hash = None
    db_session.flush()
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_con_mfa_queda_pendiente_del_codigo(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    db_session.add(
        MfaCredential(
            user_id=ana.id, secret_encrypted=b"x", confirmed_at=clock.now(), created_at=clock.now()
        )
    )
    db_session.flush()
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.json() == {"next": "mfa"}
    [sesion] = _sesiones(db_session)
    assert sesion.stage == "mfa_pending"
    assert sesion.expires_at == clock.now() + timedelta(minutes=5)
    # El inicio de sesión aún no está completo: no hay evento de éxito.
    assert db_session.scalars(select(SecurityEvent.type)).all() == []


def test_mfa_sin_confirmar_no_cuenta(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    db_session.add(MfaCredential(user_id=ana.id, secret_encrypted=b"x", created_at=clock.now()))
    db_session.flush()
    assert client.post("/api/v1/auth/login", json=LOGIN).json() == {"next": "app"}


def test_nuevo_inicio_de_sesion_reemplaza_la_sesion_anterior(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    # Una sesión MFA abandonada en el navegador no impide volver a entrar (sin CSRF).
    raw, vieja = create_session(db_session, ana.id, SessionStage.MFA_PENDING, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.status_code == 200
    [nueva] = _sesiones(db_session)
    assert nueva.id != vieja.id
    assert response.cookies[COOKIE_NAME] != raw


def test_rehash_de_parametros_viejos(client: TestClient, db_session: Session, ana: User) -> None:
    ana.password_hash = PasswordHasher(time_cost=1, memory_cost=8192).hash(CLAVE)
    db_session.flush()
    assert client.post("/api/v1/auth/login", json=LOGIN).status_code == 200
    db_session.refresh(ana)
    assert ana.password_hash is not None and not needs_rehash(ana.password_hash)


# --- Limitación de intentos (CA-AUTH-09) --------------------------------------------------


def test_ca_auth_09_sexto_intento_bloqueado_aun_con_la_clave_correcta(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    for _ in range(5):
        response = client.post("/api/v1/auth/login", json={**LOGIN, "password": "mala clave larga"})
        assert response.status_code == 401
    response = client.post("/api/v1/auth/login", json=LOGIN)
    assert response.status_code == 429
    assert response.json()["code"] == "too_many_attempts"
    assert response.headers["retry-after"] == "900"
    assert _sesiones(db_session) == []

    clock.advance(timedelta(minutes=15))
    assert client.post("/api/v1/auth/login", json=LOGIN).status_code == 200


def test_bloqueo_identico_para_correos_sin_cuenta(client: TestClient) -> None:
    datos = {"email": "nadie@correo.com", "password": "mala clave larga"}
    codigos = [client.post("/api/v1/auth/login", json=datos).status_code for _ in range(6)]
    assert codigos == [401] * 5 + [429]


def test_limite_por_ip(client: TestClient, settings: Settings, ana: User) -> None:
    settings.rate_limit_login_per_ip = 3
    for _ in range(3):
        assert client.post("/api/v1/auth/login", json=LOGIN).status_code == 200
    assert client.post("/api/v1/auth/login", json=LOGIN).status_code == 429


def test_fallos_quedan_registrados_sin_datos_sensibles(
    client: TestClient, db_session: Session, ana: User
) -> None:
    client.post("/api/v1/auth/login", json={**LOGIN, "password": "mala clave larga"})
    client.post("/api/v1/auth/login", json={"email": "nadie@correo.com", "password": "x"})
    eventos = db_session.scalars(select(SecurityEvent).order_by(SecurityEvent.id)).all()
    assert [(e.type, e.user_id) for e in eventos] == [
        ("login_failed", ana.id),
        ("login_failed", None),
    ]


# --- Sesión y cierre de sesión ------------------------------------------------------------


def test_consulta_de_sesion_activa(client: TestClient, ana: User) -> None:
    client.post("/api/v1/auth/login", json=LOGIN)
    body = client.get("/api/v1/auth/session").json()
    assert body["stage"] == "active"
    assert body["csrf_token"]
    assert body["google_enabled"] is False
    assert body["user"] == {"name": "Ana", "email": "ana@correo.com"}


def test_consulta_de_sesion_parcial_sin_datos_del_usuario(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    raw, _ = create_session(db_session, ana.id, SessionStage.MFA_PENDING, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    body = client.get("/api/v1/auth/session").json()
    assert (body["stage"], body["user"]) == ("mfa_pending", None)


def test_consulta_sin_sesion(client: TestClient, settings: Settings) -> None:
    response = client.get("/api/v1/auth/session")
    assert response.status_code == 200
    assert response.json() == {
        "stage": None,
        "csrf_token": None,
        "google_enabled": False,
        "user": None,
    }
    settings.google_client_id = "id.apps.googleusercontent.com"
    assert client.get("/api/v1/auth/session").json()["google_enabled"] is True


def test_cierre_de_sesion(client: TestClient, db_session: Session, ana: User) -> None:
    client.post("/api/v1/auth/login", json=LOGIN)
    response = client.post("/api/v1/auth/logout", json={}, headers=_csrf(client))
    assert response.status_code == 204
    assert 'finora_session="";' in response.headers["set-cookie"]
    assert _sesiones(db_session) == []
    assert client.get("/api/v1/auth/session").json()["stage"] is None
    assert "logout" in db_session.scalars(select(SecurityEvent.type)).all()


def test_cierre_de_sesion_exige_csrf(client: TestClient, db_session: Session, ana: User) -> None:
    client.post("/api/v1/auth/login", json=LOGIN)
    assert client.post("/api/v1/auth/logout", json={}).status_code == 403
    assert len(_sesiones(db_session)) == 1


def test_cierre_de_sesion_sin_sesion_es_idempotente(client: TestClient) -> None:
    assert client.post("/api/v1/auth/logout", json={}).status_code == 204


def test_cierre_de_sesion_solo_afecta_la_sesion_actual(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock
) -> None:
    create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())  # otro dispositivo
    client.post("/api/v1/auth/login", json=LOGIN)
    client.post("/api/v1/auth/logout", json={}, headers=_csrf(client))
    assert db_session.scalar(select(func.count()).select_from(AuthSession)) == 1
