"""Activación, uso y desactivación de la MFA (T-AUTH-BE-09).

CA-AUTH-08, RF-AUTH-10 a 13, RN-AUTH-06, VAL-AUTH-08.
"""

from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.models import AuthSession, MfaCredential, MfaRecoveryCode, SecurityEvent, User
from finora.auth.passwords import hash_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock

CLAVE = "caballo correcto batería grapa"
LOGIN = {"email": "ana@correo.com", "password": CLAVE}


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
    """Sesión activa de Ana, recién reautenticada."""
    raw, sesion = create_session(db_session, ana.id, SessionStage.ACTIVE, clock.now())
    sesion.reauthenticated_at = clock.now()
    db_session.flush()
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


def _activar(client: TestClient, csrf: dict[str, str], clock: FrozenClock) -> tuple[str, list[str]]:
    """Activa la MFA y devuelve el secreto y los códigos de recuperación."""
    secret = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf).json()["secret"]
    code = pyotp.TOTP(secret).at(clock.now())
    response = client.post("/api/v1/me/mfa/confirm", json={"code": code}, headers=csrf)
    assert response.status_code == 200
    return secret, response.json()["recovery_codes"]


def _pendiente(client: TestClient) -> dict[str, str]:
    """CSRF de la sesión actual (también las parciales lo exigen)."""
    return {"X-CSRF-Token": client.get("/api/v1/auth/session").json()["csrf_token"]}


def _codigo(client: TestClient, code: str) -> int:
    response = client.post(
        "/api/v1/auth/login/mfa", json={"code": code}, headers=_pendiente(client)
    )
    return response.status_code


def _login_mfa(client: TestClient, code: str) -> int:
    assert client.post("/api/v1/auth/login", json=LOGIN).json() == {"next": "mfa"}
    return _codigo(client, code)


# --- CA-AUTH-08 ---------------------------------------------------------------------------


def test_ca_auth_08_activacion_y_uso(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    csrf: dict[str, str],
) -> None:
    setup = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    assert setup.json()["otpauth_uri"].startswith("otpauth://totp/FINORA:ana%40correo.com?")
    assert client.get("/api/v1/me").json()["mfa_enabled"] is False  # aún pendiente

    code = pyotp.TOTP(secret).at(clock.now())
    confirm = client.post("/api/v1/me/mfa/confirm", json={"code": code}, headers=csrf)
    assert confirm.status_code == 200
    codes = confirm.json()["recovery_codes"]
    assert len(codes) == len(set(codes)) == 10
    assert client.get("/api/v1/me").json()["mfa_enabled"] is True

    # En la BD no queda nada en claro.
    credential = db_session.get_one(MfaCredential, ana.id)
    assert secret.encode() not in credential.secret_encrypted
    hashes = db_session.scalars(select(MfaRecoveryCode.code_hash)).all()
    assert not set(codes) & set(hashes)

    # El inicio de sesión ahora pide el código.
    client.cookies.clear()
    clock.advance(timedelta(seconds=30))
    assert _login_mfa(client, pyotp.TOTP(secret).at(clock.now())) == 200
    sesion = client.get("/api/v1/auth/session").json()
    assert sesion["stage"] == "active"
    tipos = db_session.scalars(select(SecurityEvent.type)).all()
    assert {"mfa_enabled", "login_succeeded"} <= set(tipos)


def test_el_mismo_codigo_no_sirve_dos_veces(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    secret, _ = _activar(client, csrf, clock)
    client.cookies.clear()
    # El código de la confirmación ya se usó en este intervalo.
    assert _login_mfa(client, pyotp.TOTP(secret).at(clock.now())) == 401
    clock.advance(timedelta(seconds=30))
    code = pyotp.TOTP(secret).at(clock.now())
    assert (
        client.post(
            "/api/v1/auth/login/mfa", json={"code": code}, headers=_pendiente(client)
        ).status_code
        == 200
    )
    client.cookies.clear()
    assert _login_mfa(client, code) == 401


def test_codigo_de_recuperacion_un_solo_uso(
    client: TestClient, db_session: Session, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    _, codes = _activar(client, csrf, clock)
    client.cookies.clear()
    assert _login_mfa(client, codes[0].lower()) == 200
    assert "mfa_recovery_code_used" in db_session.scalars(select(SecurityEvent.type)).all()
    client.cookies.clear()
    assert _login_mfa(client, codes[0]) == 401
    assert _login_mfa(client, codes[1]) == 200


def test_codigo_incorrecto_mantiene_la_sesion_pendiente(
    client: TestClient, db_session: Session, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    _activar(client, csrf, clock)
    client.cookies.clear()
    assert client.post("/api/v1/auth/login", json=LOGIN).json() == {"next": "mfa"}
    response = client.post(
        "/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_pendiente(client)
    )
    assert response.status_code == 401
    assert response.json() == {
        **response.json(),
        "code": "invalid_credentials",
        "title": "El código no es correcto.",
    }
    assert client.get("/api/v1/auth/session").json()["stage"] == "mfa_pending"
    assert "mfa_failed" in db_session.scalars(select(SecurityEvent.type)).all()


def test_cinco_codigos_fallidos_bloquean(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    secret, _ = _activar(client, csrf, clock)
    client.cookies.clear()
    clock.advance(timedelta(seconds=30))
    client.post("/api/v1/auth/login", json=LOGIN)
    for _ in range(5):
        client.post("/api/v1/auth/login/mfa", json={"code": "000000"}, headers=_pendiente(client))
    code = pyotp.TOTP(secret).at(clock.now())
    response = client.post(
        "/api/v1/auth/login/mfa", json={"code": code}, headers=_pendiente(client)
    )
    assert response.status_code == 429


def test_sesion_pendiente_no_da_acceso(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    _activar(client, csrf, clock)
    client.cookies.clear()
    client.post("/api/v1/auth/login", json=LOGIN)
    assert client.get("/api/v1/me").status_code == 401
    clock.advance(timedelta(minutes=5))  # RN: las etapas parciales duran 5 minutos
    assert client.post("/api/v1/auth/login/mfa", json={"code": "000000"}).status_code == 401
    assert client.get("/api/v1/auth/session").json()["stage"] is None


def test_login_mfa_sin_sesion_pendiente(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post("/api/v1/auth/login/mfa", json={"code": "123456"}, headers=csrf)
    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"


def test_login_mfa_rota_la_sesion(
    client: TestClient, db_session: Session, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    _, codes = _activar(client, csrf, clock)
    client.cookies.clear()
    client.post("/api/v1/auth/login", json=LOGIN)
    pendiente = client.cookies[COOKIE_NAME]
    response = client.post(
        "/api/v1/auth/login/mfa", json={"code": codes[0]}, headers=_pendiente(client)
    )
    assert response.cookies[COOKIE_NAME] != pendiente
    etapas = db_session.scalars(select(AuthSession.stage)).all()
    assert "mfa_pending" not in etapas


# --- Activación (RF-AUTH-10) --------------------------------------------------------------


def test_activar_exige_reautenticacion_reciente(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    clock.advance(timedelta(minutes=5))
    response = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf)
    assert response.status_code == 403
    assert response.json()["code"] == "reauthentication_required"


def test_repetir_la_configuracion_reemplaza_el_secreto(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    viejo = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf).json()["secret"]
    nuevo = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf).json()["secret"]
    assert viejo != nuevo
    code = pyotp.TOTP(viejo).at(clock.now())
    assert (
        client.post("/api/v1/me/mfa/confirm", json={"code": code}, headers=csrf).status_code == 422
    )
    code = pyotp.TOTP(nuevo).at(clock.now())
    assert (
        client.post("/api/v1/me/mfa/confirm", json={"code": code}, headers=csrf).status_code == 200
    )


def test_activar_si_ya_esta_activa(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    _activar(client, csrf, clock)
    response = client.post("/api/v1/me/mfa/setup", json={}, headers=csrf)
    assert response.status_code == 409
    assert response.json()["code"] == "mfa_already_enabled"


def test_confirmar_sin_configuracion_pendiente(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post("/api/v1/me/mfa/confirm", json={"code": "123456"}, headers=csrf)
    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == "mfa_not_pending"


def test_confirmar_con_codigo_incorrecto(client: TestClient, csrf: dict[str, str]) -> None:
    client.post("/api/v1/me/mfa/setup", json={}, headers=csrf)
    response = client.post("/api/v1/me/mfa/confirm", json={"code": "000000"}, headers=csrf)
    assert response.status_code == 422
    assert response.json()["errors"] == [
        {"loc": ["body", "code"], "type": "invalid_code", "message": "El código no es correcto."}
    ]


# --- Desactivación (RF-AUTH-13) -----------------------------------------------------------


def test_desactivar(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    secret, _ = _activar(client, csrf, clock)
    clock.advance(timedelta(seconds=30))
    code = pyotp.TOTP(secret).at(clock.now())
    response = client.post("/api/v1/me/mfa/disable", json={"code": code}, headers=csrf)
    assert response.status_code == 204
    assert db_session.get(MfaCredential, ana.id) is None
    assert db_session.scalar(select(func.count()).select_from(MfaRecoveryCode)) == 0
    assert "mfa_disabled" in db_session.scalars(select(SecurityEvent.type)).all()
    client.cookies.clear()
    assert client.post("/api/v1/auth/login", json=LOGIN).json() == {"next": "app"}


def test_desactivar_exige_reautenticacion_y_codigo_totp(
    client: TestClient, clock: FrozenClock, csrf: dict[str, str]
) -> None:
    secret, codes = _activar(client, csrf, clock)
    # Un código de recuperación no sirve para desactivar.
    response = client.post("/api/v1/me/mfa/disable", json={"code": codes[0]}, headers=csrf)
    assert response.status_code == 422
    clock.advance(timedelta(minutes=5))
    code = pyotp.TOTP(secret).at(clock.now())
    response = client.post("/api/v1/me/mfa/disable", json={"code": code}, headers=csrf)
    assert response.status_code == 403


def test_desactivar_sin_mfa(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post("/api/v1/me/mfa/disable", json={"code": "123456"}, headers=csrf)
    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == "mfa_not_enabled"
