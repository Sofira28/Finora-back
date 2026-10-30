"""Sesiones, CSRF y dependencias contra PostgreSQL (T-AUTH-BE-05).

CA-AUTH-05, CA-AUTH-06, RNF-AUTH-02, VAL-AUTH-10, VAL-AUTH-11, RN-AUTH-08.
"""

from datetime import timedelta

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.dependencies import (
    CurrentUser,
    require_recent_reauth,
    require_session,
    verify_request_origin,
)
from finora.auth.models import AuthSession, User
from finora.auth.sessions import (
    COOKIE_NAME,
    SessionStage,
    create_session,
    hash_session_token,
    load_session,
    revoke_all_sessions,
    rotate_session,
)
from finora.clock import FrozenClock

ACTIVA = SessionStage.ACTIVE
MFA = SessionStage.MFA_PENDING


@pytest.fixture
def usuario(db_session: Session, clock: FrozenClock) -> User:
    user = User(email="ana@correo.com", name="Ana", created_at=clock.now())
    db_session.add(user)
    db_session.flush()
    return user


def _cuantas(db_session: Session) -> int:
    return db_session.scalar(select(func.count()).select_from(AuthSession)) or 0


# --- Ciclo de vida -------------------------------------------------------------------------


def test_crear_guarda_solo_el_hash(db_session: Session, usuario: User, clock: FrozenClock) -> None:
    raw, sesion = create_session(db_session, usuario.id, ACTIVA, clock.now())
    assert sesion.token_hash == hash_session_token(raw)
    assert raw.encode() not in sesion.token_hash
    assert sesion.csrf_token and sesion.csrf_token != raw
    assert sesion.expires_at == clock.now() + timedelta(days=7)


def test_sesion_parcial_dura_5_minutos(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    _, sesion = create_session(db_session, usuario.id, MFA, clock.now())
    assert sesion.expires_at == clock.now() + timedelta(minutes=5)


def test_cargar_sesion_inexistente(db_session: Session, usuario: User, clock: FrozenClock) -> None:
    create_session(db_session, usuario.id, ACTIVA, clock.now())
    assert load_session(db_session, "inventado", clock.now()) is None


def test_inactividad_borra_la_sesion(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    raw, _ = create_session(db_session, usuario.id, ACTIVA, clock.now())
    clock.advance(timedelta(minutes=30))
    assert load_session(db_session, raw, clock.now()) is None
    assert _cuantas(db_session) == 0


def test_actividad_renueva_como_maximo_cada_minuto(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    inicio = clock.now()
    raw, sesion = create_session(db_session, usuario.id, ACTIVA, inicio)
    clock.advance(timedelta(seconds=59))
    load_session(db_session, raw, clock.now())
    assert sesion.last_activity_at == inicio
    clock.advance(timedelta(seconds=1))
    load_session(db_session, raw, clock.now())
    assert sesion.last_activity_at == inicio + timedelta(minutes=1)


def test_uso_continuo_vence_a_los_7_dias(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    raw, _ = create_session(db_session, usuario.id, ACTIVA, clock.now())
    for _ in range(7 * 24 * 6 - 1):  # una petición cada 10 minutos durante casi 7 días
        clock.advance(timedelta(minutes=10))
        assert load_session(db_session, raw, clock.now()) is not None
    clock.advance(timedelta(minutes=10))
    assert load_session(db_session, raw, clock.now()) is None


def test_sesion_parcial_no_se_renueva(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    raw, _ = create_session(db_session, usuario.id, MFA, clock.now())
    clock.advance(timedelta(minutes=4))
    assert load_session(db_session, raw, clock.now()) is not None
    clock.advance(timedelta(minutes=1))
    assert load_session(db_session, raw, clock.now()) is None


def test_rotar_cambia_el_identificador(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    raw_viejo, vieja = create_session(db_session, usuario.id, MFA, clock.now())
    raw_nuevo, nueva = rotate_session(db_session, vieja, ACTIVA, clock.now())
    assert raw_nuevo != raw_viejo
    assert nueva.stage == ACTIVA
    assert load_session(db_session, raw_viejo, clock.now()) is None
    assert load_session(db_session, raw_nuevo, clock.now()) is not None


def test_revocar_todas_salvo_la_actual(
    db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    luis = User(email="luis@correo.com", name="Luis", created_at=clock.now())
    db_session.add(luis)
    db_session.flush()
    _, actual = create_session(db_session, usuario.id, ACTIVA, clock.now())
    create_session(db_session, usuario.id, ACTIVA, clock.now())
    create_session(db_session, luis.id, ACTIVA, clock.now())
    revoke_all_sessions(db_session, usuario.id, except_id=actual.id)
    restantes = db_session.scalars(select(AuthSession)).all()
    assert {(s.user_id, s.id == actual.id) for s in restantes} == {
        (usuario.id, True),
        (luis.id, False),
    }


# --- Dependencias por HTTP ---------------------------------------------------------------


@pytest.fixture
def app(app: FastAPI) -> FastAPI:
    # Rutas de prueba bajo /api/v1/auth con las mismas dependencias que usarán los endpoints.
    router = APIRouter(prefix="/api/v1/auth/_prueba", dependencies=[Depends(verify_request_origin)])

    @router.get("/yo")
    def yo(user: CurrentUser) -> dict[str, str]:
        return {"email": user.email}

    @router.post("/yo")
    def cambiar(user: CurrentUser) -> dict[str, str]:
        return {"email": user.email}

    @router.post("/codigo", dependencies=[Depends(require_session(MFA))])
    def codigo() -> dict[str, str]:
        return {"ok": "mfa"}

    @router.post("/sensible", dependencies=[Depends(require_recent_reauth)])
    def sensible() -> dict[str, str]:
        return {"ok": "sensible"}

    app.include_router(router)
    return app


def _iniciar(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock, etapa: SessionStage
) -> AuthSession:
    raw, sesion = create_session(db_session, usuario.id, etapa, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return sesion


def test_sin_cookie_responde_401_session_expired(client: TestClient) -> None:
    response = client.get("/api/v1/auth/_prueba/yo")
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "session_expired"
    assert response.json()["title"] == "Tu sesión terminó. Inicia sesión de nuevo."


def test_usuario_sale_de_la_sesion(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    _iniciar(client, db_session, usuario, clock, ACTIVA)
    response = client.get("/api/v1/auth/_prueba/yo")
    assert response.status_code == 200
    assert response.json() == {"email": "ana@correo.com"}


def test_ca_auth_05_inactividad_por_http(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    _iniciar(client, db_session, usuario, clock, ACTIVA)
    clock.advance(timedelta(minutes=29))
    assert client.get("/api/v1/auth/_prueba/yo").status_code == 200
    clock.advance(timedelta(minutes=30))
    assert client.get("/api/v1/auth/_prueba/yo").status_code == 401


def test_sesion_parcial_no_da_acceso_a_la_aplicacion(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    sesion = _iniciar(client, db_session, usuario, clock, MFA)
    assert client.get("/api/v1/auth/_prueba/yo").status_code == 401
    response = client.post(
        "/api/v1/auth/_prueba/codigo", json={}, headers={"X-CSRF-Token": sesion.csrf_token}
    )
    assert response.status_code == 200


def test_sesion_activa_no_sirve_para_el_paso_mfa(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    sesion = _iniciar(client, db_session, usuario, clock, ACTIVA)
    response = client.post(
        "/api/v1/auth/_prueba/codigo", json={}, headers={"X-CSRF-Token": sesion.csrf_token}
    )
    assert response.status_code == 401


def test_csrf_correcto(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    sesion = _iniciar(client, db_session, usuario, clock, ACTIVA)
    response = client.post(
        "/api/v1/auth/_prueba/yo", json={}, headers={"X-CSRF-Token": sesion.csrf_token}
    )
    assert response.status_code == 200


@pytest.mark.parametrize("csrf", [None, "", "otro-token"])
def test_csrf_ausente_o_incorrecto(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock, csrf: str | None
) -> None:
    _iniciar(client, db_session, usuario, clock, ACTIVA)
    headers = {} if csrf is None else {"X-CSRF-Token": csrf}
    response = client.post("/api/v1/auth/_prueba/yo", json={}, headers=headers)
    assert response.status_code == 403
    assert response.json()["code"] == "csrf_failed"


@pytest.mark.parametrize("origin", ["https://atacante.example", "http://localhost:5174", None])
def test_origin_no_permitido(
    client: TestClient,
    db_session: Session,
    usuario: User,
    clock: FrozenClock,
    origin: str | None,
) -> None:
    sesion = _iniciar(client, db_session, usuario, clock, ACTIVA)
    headers = {"X-CSRF-Token": sesion.csrf_token}
    if origin is None:
        del client.headers["Origin"]
    else:
        headers["Origin"] = origin
    response = client.post("/api/v1/auth/_prueba/yo", json={}, headers=headers)
    assert response.status_code == 403
    assert response.json()["code"] == "csrf_failed"


@pytest.mark.parametrize(
    "content_type", ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"]
)
def test_content_type_distinto_de_json(
    client: TestClient,
    db_session: Session,
    usuario: User,
    clock: FrozenClock,
    content_type: str,
) -> None:
    # Los formularios HTML de otro sitio solo pueden enviar estos tipos sin preflight.
    sesion = _iniciar(client, db_session, usuario, clock, ACTIVA)
    response = client.post(
        "/api/v1/auth/_prueba/yo",
        content=b"{}",
        headers={"X-CSRF-Token": sesion.csrf_token, "Content-Type": content_type},
    )
    assert response.status_code == 403


def test_reautenticacion_reciente(
    client: TestClient, db_session: Session, usuario: User, clock: FrozenClock
) -> None:
    sesion = _iniciar(client, db_session, usuario, clock, ACTIVA)
    headers = {"X-CSRF-Token": sesion.csrf_token}
    response = client.post("/api/v1/auth/_prueba/sensible", json={}, headers=headers)
    assert response.status_code == 403
    assert response.json()["code"] == "reauthentication_required"

    sesion.reauthenticated_at = clock.now()
    db_session.flush()
    clock.advance(timedelta(minutes=4))
    assert client.post("/api/v1/auth/_prueba/sensible", json={}, headers=headers).status_code == 200
    clock.advance(timedelta(minutes=1))
    assert client.post("/api/v1/auth/_prueba/sensible", json={}, headers=headers).status_code == 403


def test_no_store_en_auth_tambien_en_errores(client: TestClient) -> None:
    assert client.get("/api/v1/auth/_prueba/yo").headers["cache-control"] == "no-store"
    assert "cache-control" not in client.get("/api/v1/health").headers
