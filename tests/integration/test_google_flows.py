"""Flujos de Google de punta a punta con un cliente falso (T-AUTH-BE-10).

CA-AUTH-04, CA-AUTH-13, CA-AUTH-14, RF-AUTH-05, RF-AUTH-17, RF-AUTH-19, RF-AUTH-21,
VAL-AUTH-12, VAL-AUTH-13.
"""

from dataclasses import dataclass, field, replace
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth import mfa
from finora.auth.google import GoogleAuthError, GoogleIdentity, get_google_client
from finora.auth.models import (
    AuthSession,
    DataConsent,
    ExternalIdentity,
    MfaCredential,
    OAuthFlow,
    SecurityEvent,
    User,
)
from finora.auth.passwords import hash_password
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.auth.tokens import TokenPurpose, hash_token, issue_token
from finora.clock import FrozenClock
from finora.config import Settings

WEB = "http://localhost:5173"
CLAVE = "caballo correcto batería grapa"
SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - secreto TOTP de prueba
START = "/api/v1/auth/google/start"
CALLBACK = "/api/v1/auth/google/callback"
ANA_GOOGLE = GoogleIdentity(
    subject="google-ana", email="ana@correo.com", email_verified=True, name="Ana Gómez"
)


@dataclass
class FakeGoogle:
    """Simula a Google: el código válido es `codigo-bueno` y el nonce debe ser el del flujo."""

    identity: GoogleIdentity = ANA_GOOGLE
    fail: bool = False
    nonces: dict[str, str] = field(default_factory=dict)  # state -> nonce
    reauth_requests: list[bool] = field(default_factory=list)

    def authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, code_verifier: str, reauth: bool
    ) -> str:
        assert redirect_uri == f"{WEB}/api/v1/auth/google/callback"
        assert len(code_verifier) >= 43
        self.nonces[state] = nonce
        self.reauth_requests.append(reauth)
        return f"https://accounts.google.test/auth?state={state}"

    def exchange_code(
        self, *, redirect_uri: str, code: str, code_verifier: str, nonce: str
    ) -> GoogleIdentity:
        if self.fail or code != "codigo-bueno" or nonce not in self.nonces.values():
            raise GoogleAuthError("rechazado")
        return self.identity


@pytest.fixture
def google(app: FastAPI) -> FakeGoogle:
    fake = FakeGoogle()
    app.dependency_overrides[get_google_client] = lambda: fake
    return fake


def _start(client: TestClient, **params: str) -> str:
    response = client.get(
        START, follow_redirects=False, params={"privacy_policy_version": "0", **params}
    )
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


def _callback(client: TestClient, state: str, **params: str) -> str:
    response = client.get(
        CALLBACK, follow_redirects=False, params={"state": state, "code": "codigo-bueno", **params}
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(WEB)
    return location.removeprefix(WEB)


def _google(client: TestClient, **params: str) -> str:
    return _callback(client, _start(client, **params))


def _sesion(client: TestClient) -> dict[str, object]:
    body: dict[str, object] = client.get("/api/v1/auth/session").json()
    return body


def _csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(_sesion(client)["csrf_token"])}


def _usuario(
    db: Session, clock: FrozenClock, *, password: bool = True, verified: bool = True
) -> User:
    user = User(
        email="ana@correo.com",
        name="Ana",
        password_hash=hash_password(CLAVE) if password else None,
        email_verified_at=clock.now() if verified else None,
        created_at=clock.now(),
    )
    db.add(user)
    db.flush()
    return user


def _vincular(db: Session, user: User, clock: FrozenClock, subject: str = "google-ana") -> None:
    db.add(
        ExternalIdentity(
            user_id=user.id, provider="google", subject=subject, created_at=clock.now()
        )
    )
    db.flush()


def _con_mfa(db: Session, user: User, clock: FrozenClock, settings: Settings) -> None:
    db.add(
        MfaCredential(
            user_id=user.id,
            secret_encrypted=mfa.encrypt_secret(settings.mfa_key, user.id, SECRET),
            confirmed_at=clock.now(),
            created_at=clock.now(),
        )
    )
    db.flush()


def _eventos(db: Session) -> list[str]:
    return list(db.scalars(select(SecurityEvent.type).order_by(SecurityEvent.id)))


# --- Inicio del flujo ---------------------------------------------------------------------


def test_sin_credenciales_404(client: TestClient) -> None:
    assert client.get(START, follow_redirects=False).status_code == 404
    assert _callback(client, "x") == "/iniciar-sesion?error=google"


def test_inicio_guarda_el_flujo_y_ata_el_navegador(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    response = client.get(START, follow_redirects=False, params={"privacy_policy_version": "0"})
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"finora_oauth_state={state};")
    assert all(
        a in cookie for a in ("HttpOnly", "Secure", "SameSite=lax", "Path=/api/v1/auth/google")
    )
    assert response.headers["cache-control"] == "no-store"
    flow = db_session.scalars(select(OAuthFlow)).one()
    assert flow.state_hash == hash_token(state)  # el state no se guarda en claro
    assert (flow.intent, flow.session_id, flow.privacy_policy_version) == ("login", None, "0")
    assert flow.expires_at == clock.now() + timedelta(minutes=10)
    assert google.reauth_requests == [False]


def test_version_de_politica_no_vigente_no_se_guarda(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    _start(client, privacy_policy_version="9")
    assert db_session.scalars(select(OAuthFlow.privacy_policy_version)).one() is None


# --- CA-AUTH-04: cuenta nueva -------------------------------------------------------------


def test_ca_auth_04_primera_vez_con_google(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    assert _google(client) == "/"
    user = db_session.scalars(select(User)).one()
    assert (user.email, user.name, user.password_hash) == ("ana@correo.com", "Ana Gómez", None)
    assert user.email_verified_at == clock.now()
    identidad = db_session.scalars(select(ExternalIdentity)).one()
    assert (identidad.user_id, identidad.subject) == (user.id, "google-ana")
    consentimiento = db_session.scalars(select(DataConsent)).one()
    assert (consentimiento.user_id, consentimiento.policy_version) == (user.id, "0")
    sesion = _sesion(client)
    assert sesion["stage"] == "active"
    assert sesion["user"] == {"name": "Ana Gómez", "email": "ana@correo.com"}
    assert _eventos(db_session) == ["registered", "google_linked", "login_succeeded"]
    assert db_session.scalar(select(func.count()).select_from(OAuthFlow)) == 0


def test_sin_aceptar_la_politica_no_se_crea_la_cuenta(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    state = _start(client, privacy_policy_version="")
    assert _callback(client, state) == "/iniciar-sesion?error=google"
    assert db_session.scalar(select(func.count()).select_from(User)) == 0


def test_nombre_de_google_ajustado(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    google.identity = replace(ANA_GOOGLE, name="   ")
    _google(client)
    assert db_session.scalars(select(User.name)).one() == "ana"


def test_nombre_de_google_sin_caracteres_de_control(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    google.identity = replace(ANA_GOOGLE, name="Ana\nGómez\x00")
    _google(client)
    assert db_session.scalars(select(User.name)).one() == "AnaGómez"


def test_correo_en_mayusculas_se_normaliza(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    google.identity = replace(ANA_GOOGLE, email="Ana@Correo.com")
    _google(client)
    assert db_session.scalars(select(User.email)).one() == "ana@correo.com"


# --- Errores (VAL-AUTH-12 y 13) -----------------------------------------------------------


def test_val_auth_12_correo_no_verificado_en_google(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    google.identity = replace(ANA_GOOGLE, email_verified=False)
    assert _google(client) == "/iniciar-sesion?error=google_unverified"
    assert db_session.scalar(select(func.count()).select_from(User)) == 0


def test_val_auth_13_cancelacion(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    state = _start(client)
    assert _callback(client, state, error="access_denied") == "/iniciar-sesion?error=google"
    # El flujo ya se gastó: repetir el callback no sirve.
    assert _callback(client, state) == "/iniciar-sesion?error=google"
    assert db_session.scalar(select(func.count()).select_from(User)) == 0


def test_google_rechaza_el_codigo(client: TestClient, google: FakeGoogle) -> None:
    google.fail = True
    assert _google(client) == "/iniciar-sesion?error=google"
    assert _sesion(client)["stage"] is None


def test_flujo_vencido(client: TestClient, google: FakeGoogle, clock: FrozenClock) -> None:
    state = _start(client)
    clock.advance(timedelta(minutes=10))
    assert _callback(client, state) == "/iniciar-sesion?error=google"


def test_callback_desde_otro_navegador(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    # Un atacante empieza el flujo y envía el enlace del callback a otra persona.
    state = _start(client)
    client.cookies.clear()
    assert _callback(client, state) == "/iniciar-sesion?error=google"
    assert db_session.scalar(select(func.count()).select_from(AuthSession)) == 0


def test_state_inventado(client: TestClient, google: FakeGoogle) -> None:
    _start(client)
    client.cookies.set("finora_oauth_state", "inventado", path="/api/v1/auth/google")
    assert _callback(client, "inventado") == "/iniciar-sesion?error=google"


def test_callback_borra_la_cookie_del_flujo(client: TestClient, google: FakeGoogle) -> None:
    state = _start(client)
    response = client.get(
        CALLBACK, follow_redirects=False, params={"state": state, "code": "codigo-bueno"}
    )
    assert 'finora_oauth_state="";' in response.headers["set-cookie"]


# --- Cuenta existente ---------------------------------------------------------------------


def test_identidad_conocida_entra_directo(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock, password=False)
    _vincular(db_session, user, clock)
    google.identity = replace(ANA_GOOGLE, email="otro@gmail.com", name="Otro nombre")
    assert _google(client) == "/"
    db_session.refresh(user)
    assert (user.email, user.name) == ("ana@correo.com", "Ana")  # no se tocan los datos
    assert db_session.scalar(select(func.count()).select_from(User)) == 1


def test_ca_auth_14_mfa_tambien_con_google(
    client: TestClient,
    db_session: Session,
    google: FakeGoogle,
    clock: FrozenClock,
    settings: Settings,
) -> None:
    user = _usuario(db_session, clock, password=False)
    _vincular(db_session, user, clock)
    _con_mfa(db_session, user, clock, settings)
    assert _google(client) == "/iniciar-sesion/codigo"
    assert _sesion(client)["stage"] == "mfa_pending"
    assert client.get("/api/v1/me").status_code == 401
    code = pyotp.TOTP(SECRET).at(clock.now())
    response = client.post("/api/v1/auth/login/mfa", json={"code": code}, headers=_csrf(client))
    assert response.json() == {"next": "app"}


def test_nuevo_inicio_reemplaza_la_sesion_anterior(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock, password=False)
    _vincular(db_session, user, clock)
    raw, vieja = create_session(db_session, user.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    _google(client)
    assert db_session.get(AuthSession, vieja.id) is None
    assert db_session.scalar(select(func.count()).select_from(AuthSession)) == 1


# --- CA-AUTH-13: vinculación con contraseña ----------------------------------------------


def test_ca_auth_13_vinculacion_segura(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock)
    assert _google(client) == "/iniciar-sesion/vincular-google"
    assert _sesion(client)["stage"] == "link_pending"
    assert client.get("/api/v1/me").status_code == 401  # aún no hay sesión
    assert db_session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0

    mala = client.post(
        "/api/v1/auth/google/link", json={"password": "no es la clave"}, headers=_csrf(client)
    )
    assert mala.status_code == 401
    assert mala.json()["code"] == "invalid_credentials"
    buena = client.post("/api/v1/auth/google/link", json={"password": CLAVE}, headers=_csrf(client))
    assert buena.json() == {"next": "app"}
    assert COOKIE_NAME in buena.cookies

    identidad = db_session.scalars(select(ExternalIdentity)).one()
    assert identidad.user_id == user.id
    assert db_session.scalar(select(func.count()).select_from(User)) == 1  # sin duplicados
    assert "google_linked" in _eventos(db_session)

    client.cookies.clear()
    assert _google(client) == "/"  # la próxima vez entra directo


def test_vinculacion_con_mfa_pide_el_codigo(
    client: TestClient,
    db_session: Session,
    google: FakeGoogle,
    clock: FrozenClock,
    settings: Settings,
) -> None:
    user = _usuario(db_session, clock)
    _con_mfa(db_session, user, clock, settings)
    _google(client)
    response = client.post(
        "/api/v1/auth/google/link", json={"password": CLAVE}, headers=_csrf(client)
    )
    assert response.json() == {"next": "mfa"}
    assert _sesion(client)["stage"] == "mfa_pending"


def test_vinculacion_limita_los_intentos(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    _usuario(db_session, clock)
    _google(client)
    for _ in range(5):
        client.post(
            "/api/v1/auth/google/link", json={"password": "no es la clave"}, headers=_csrf(client)
        )
    response = client.post(
        "/api/v1/auth/google/link", json={"password": CLAVE}, headers=_csrf(client)
    )
    assert response.status_code == 429


def test_vinculacion_vence_a_los_5_minutos(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    _usuario(db_session, clock)
    _google(client)
    csrf = _csrf(client)
    clock.advance(timedelta(minutes=5))
    response = client.post("/api/v1/auth/google/link", json={"password": CLAVE}, headers=csrf)
    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"


def test_vincular_sin_sesion_pendiente(
    client: TestClient, db_session: Session, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock)
    raw, sesion = create_session(db_session, user.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    response = client.post(
        "/api/v1/auth/google/link",
        json={"password": CLAVE},
        headers={"X-CSRF-Token": sesion.csrf_token},
    )
    assert response.status_code == 401


def test_cuenta_sin_verificar_queda_para_quien_entra_con_google(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    # Alguien registró el correo de Ana con su propia contraseña y nunca lo verificó.
    user = _usuario(db_session, clock, verified=False)
    token = issue_token(db_session, user.id, TokenPurpose.VERIFY_EMAIL, clock.now())
    assert _google(client) == "/"
    db_session.refresh(user)
    assert user.password_hash is None  # la contraseña del tercero ya no sirve
    assert user.email_verified_at == clock.now()
    assert user.name == "Ana Gómez"
    assert db_session.scalars(select(ExternalIdentity.user_id)).one() == user.id
    assert db_session.scalar(select(func.count()).select_from(User)) == 1
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 400
    client.cookies.clear()
    login = {"email": "ana@correo.com", "password": CLAVE}
    assert client.post("/api/v1/auth/login", json=login).status_code == 401


def test_cuenta_solo_google_con_otra_identidad(
    client: TestClient, db_session: Session, google: FakeGoogle, clock: FrozenClock
) -> None:
    user = _usuario(db_session, clock, password=False)
    _vincular(db_session, user, clock, subject="otra-identidad")
    assert _google(client) == "/iniciar-sesion?error=google"
    assert _sesion(client)["stage"] is None


# --- Reautenticación con Google (RF-AUTH-21) ----------------------------------------------


@pytest.fixture
def ana_google(
    client: TestClient, db_session: Session, clock: FrozenClock, google: FakeGoogle
) -> User:
    """Ana, solo con Google, con la sesión activa."""
    user = _usuario(db_session, clock, password=False)
    _vincular(db_session, user, clock)
    raw, _ = create_session(db_session, user.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return user


def _setup(client: TestClient) -> int:
    return client.post("/api/v1/me/mfa/setup", json={}, headers=_csrf(client)).status_code


def test_reautenticacion_con_google(
    client: TestClient, db_session: Session, ana_google: User, google: FakeGoogle
) -> None:
    assert _setup(client) == 403
    assert _google(client, intent="reauth") == "/perfil?reauth=ok"
    assert google.reauth_requests == [True]
    flow_count = db_session.scalar(select(func.count()).select_from(OAuthFlow))
    assert flow_count == 0
    assert "reauthenticated" in _eventos(db_session)
    assert _setup(client) == 200


def test_reautenticacion_con_google_y_mfa(
    client: TestClient,
    db_session: Session,
    ana_google: User,
    google: FakeGoogle,
    clock: FrozenClock,
    settings: Settings,
) -> None:
    _con_mfa(db_session, ana_google, clock, settings)
    assert _google(client, intent="reauth") == "/perfil?reauth=codigo"
    assert (
        client.post(
            "/api/v1/me/mfa/disable", json={"code": "000000"}, headers=_csrf(client)
        ).status_code
        == 403
    )
    # Sin el código no basta.
    reauth = "/api/v1/auth/reauthenticate"
    assert client.post(reauth, json={"code": "000000"}, headers=_csrf(client)).status_code == 401
    code = pyotp.TOTP(SECRET).at(clock.now())
    assert client.post(reauth, json={"code": code}, headers=_csrf(client)).status_code == 204
    clock.advance(timedelta(seconds=30))
    code = pyotp.TOTP(SECRET).at(clock.now())
    response = client.post("/api/v1/me/mfa/disable", json={"code": code}, headers=_csrf(client))
    assert response.status_code == 204


def test_codigo_sin_pasar_por_google(
    client: TestClient,
    db_session: Session,
    ana_google: User,
    clock: FrozenClock,
    settings: Settings,
) -> None:
    _con_mfa(db_session, ana_google, clock, settings)
    code = pyotp.TOTP(SECRET).at(clock.now())
    response = client.post(
        "/api/v1/auth/reauthenticate", json={"code": code}, headers=_csrf(client)
    )
    assert response.status_code == 401


def test_paso_por_google_vence_a_los_5_minutos(
    client: TestClient,
    db_session: Session,
    ana_google: User,
    clock: FrozenClock,
    settings: Settings,
) -> None:
    _con_mfa(db_session, ana_google, clock, settings)
    _google(client, intent="reauth")
    clock.advance(timedelta(minutes=5))
    code = pyotp.TOTP(SECRET).at(clock.now())
    response = client.post(
        "/api/v1/auth/reauthenticate", json={"code": code}, headers=_csrf(client)
    )
    assert response.status_code == 401


def test_reautenticacion_con_otra_cuenta_de_google(
    client: TestClient, ana_google: User, google: FakeGoogle
) -> None:
    google.identity = replace(ANA_GOOGLE, subject="google-de-otra-persona")
    assert _google(client, intent="reauth") == "/perfil?reauth=error"
    assert _setup(client) == 403


def test_reautenticacion_cancelada(
    client: TestClient, ana_google: User, google: FakeGoogle
) -> None:
    state = _start(client, intent="reauth")
    assert _callback(client, state, error="access_denied") == "/perfil?reauth=error"


def test_reautenticacion_antigua_en_google(
    client: TestClient, ana_google: User, google: FakeGoogle, clock: FrozenClock
) -> None:
    hace_una_hora = int((clock.now() - timedelta(hours=1)).timestamp())
    google.identity = replace(ANA_GOOGLE, auth_time=hace_una_hora)
    assert _google(client, intent="reauth") == "/perfil?reauth=error"
    google.identity = replace(ANA_GOOGLE, auth_time=int(clock.now().timestamp()))
    assert _google(client, intent="reauth") == "/perfil?reauth=ok"


def test_reautenticacion_desde_otra_sesion(
    client: TestClient,
    db_session: Session,
    ana_google: User,
    google: FakeGoogle,
    clock: FrozenClock,
) -> None:
    state = _start(client, intent="reauth")
    raw, _ = create_session(db_session, ana_google.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)  # el callback llega con otra sesión
    assert _callback(client, state) == "/perfil?reauth=error"


def test_reautenticacion_sin_sesion(
    client: TestClient, db_session: Session, google: FakeGoogle
) -> None:
    response = client.get(START, follow_redirects=False, params={"intent": "reauth"})
    assert response.status_code == 302
    assert response.headers["location"] == f"{WEB}/iniciar-sesion"
    assert db_session.scalar(select(func.count()).select_from(OAuthFlow)) == 0
