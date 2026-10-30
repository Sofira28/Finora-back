"""Cliente OIDC real de Google contra respuestas simuladas con respx (T-AUTH-BE-10).

Valida PKCE, `state`, `nonce` y la validación completa del ID token (ADR-0002 §1).
"""

import base64
import hashlib
import json
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import RSAKey
from pydantic import SecretStr

from finora.auth.google import (
    DISCOVERY_URL,
    AuthlibGoogleClient,
    GoogleAuthError,
    get_google_client,
)
from finora.config import Settings

CLIENT_ID = "finora-test.apps.googleusercontent.com"
REDIRECT = "http://localhost:5173/api/v1/auth/google/callback"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - URL, no una clave
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
NONCE = "nonce-de-prueba"
VERIFIER = "v" * 64

KEY = RSAKey.generate_key(2048, parameters={"kid": "clave-1"})
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "clave-2"})


def _claims(**changes: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "1234567890",
        "email": "ana@gmail.com",
        "email_verified": True,
        "name": "Ana Gómez",
        "iat": now,
        "exp": now + 3600,
        "nonce": NONCE,
    }
    claims.update(changes)
    return {k: v for k, v in claims.items() if v is not None}


def _id_token(key: RSAKey = KEY, **changes: Any) -> str:
    return jwt.encode({"alg": "RS256", "kid": key.kid}, _claims(**changes), key)


def _jwks(*keys: RSAKey) -> dict[str, Any]:
    return {"keys": [k.as_dict(private=False) for k in keys]}


@pytest.fixture
def google() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        router.get(DISCOVERY_URL).respond(
            json={
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": AUTH_URL,
                "token_endpoint": TOKEN_URL,
                "jwks_uri": JWKS_URL,
            }
        )
        router.get(JWKS_URL).respond(json=_jwks(KEY))
        yield router


@pytest.fixture
def cliente() -> AuthlibGoogleClient:
    return AuthlibGoogleClient(CLIENT_ID, "secreto-de-prueba")


def _exchange(cliente: AuthlibGoogleClient, google: respx.MockRouter, id_token: str) -> Any:
    google.post(TOKEN_URL).respond(json={"access_token": "x", "id_token": id_token})
    return cliente.exchange_code(
        redirect_uri=REDIRECT, code="codigo", code_verifier=VERIFIER, nonce=NONCE
    )


# --- URL de autorización ------------------------------------------------------------------


def test_url_de_autorizacion_con_pkce_state_y_nonce(
    cliente: AuthlibGoogleClient, google: respx.MockRouter
) -> None:
    url = cliente.authorization_url(
        redirect_uri=REDIRECT, state="estado", nonce=NONCE, code_verifier=VERIFIER, reauth=False
    )
    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == AUTH_URL
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=")
    assert query == {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid email profile",
        "state": "estado",
        "nonce": NONCE,
        "code_challenge": challenge.decode(),
        "code_challenge_method": "S256",
    }


def test_reautenticacion_pide_volver_a_autenticar(
    cliente: AuthlibGoogleClient, google: respx.MockRouter
) -> None:
    url = cliente.authorization_url(
        redirect_uri=REDIRECT, state="e", nonce=NONCE, code_verifier=VERIFIER, reauth=True
    )
    query = parse_qs(urlparse(url).query)
    assert query["max_age"] == ["0"]
    assert query["prompt"] == ["select_account"]


# --- Intercambio y validación del ID token ------------------------------------------------


def test_intercambio_valido(cliente: AuthlibGoogleClient, google: respx.MockRouter) -> None:
    identity = _exchange(cliente, google, _id_token(auth_time=123))
    assert (identity.subject, identity.email, identity.email_verified) == (
        "1234567890",
        "ana@gmail.com",
        True,
    )
    assert (identity.name, identity.auth_time) == ("Ana Gómez", 123)
    [llamada] = [c for c in google.calls if c.request.url == TOKEN_URL]
    peticion = parse_qs(llamada.request.content.decode())
    assert peticion["grant_type"] == ["authorization_code"]
    assert peticion["code"] == ["codigo"]
    assert peticion["code_verifier"] == [VERIFIER]
    assert peticion["redirect_uri"] == [REDIRECT]


def test_emisor_sin_esquema_tambien_es_valido(
    cliente: AuthlibGoogleClient, google: respx.MockRouter
) -> None:
    identity = _exchange(cliente, google, _id_token(iss="accounts.google.com"))
    assert identity.subject == "1234567890"


def test_correo_no_verificado_se_informa(
    cliente: AuthlibGoogleClient, google: respx.MockRouter
) -> None:
    assert not _exchange(cliente, google, _id_token(email_verified=False)).email_verified


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(lambda: _id_token(OTHER_KEY), id="firma-de-otra-clave"),
        pytest.param(lambda: _id_token(aud="otra-app"), id="aud"),
        pytest.param(lambda: _id_token(iss="https://evil.example"), id="iss"),
        pytest.param(lambda: _id_token(exp=int(time.time()) - 3600), id="vencido"),
        pytest.param(lambda: _id_token(nonce="otro"), id="nonce"),
        pytest.param(lambda: _id_token(nonce=None), id="sin-nonce"),
        pytest.param(lambda: _id_token(email=None), id="sin-correo"),
        pytest.param(lambda: "no.es.jwt", id="basura"),
    ],
)
def test_id_token_invalido(
    cliente: AuthlibGoogleClient, google: respx.MockRouter, token: Any
) -> None:
    with pytest.raises(GoogleAuthError):
        _exchange(cliente, google, token())


def test_alg_none_rechazado(cliente: AuthlibGoogleClient, google: respx.MockRouter) -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(_claims()).encode()).rstrip(b"=").decode()
    with pytest.raises(GoogleAuthError):
        _exchange(cliente, google, f"{header}.{payload}.")


def test_rotacion_de_claves(cliente: AuthlibGoogleClient, google: respx.MockRouter) -> None:
    _exchange(cliente, google, _id_token())  # carga y guarda en memoria la clave 1
    google.get(JWKS_URL).respond(json=_jwks(KEY, OTHER_KEY))
    identity = _exchange(cliente, google, _id_token(OTHER_KEY))
    assert identity.subject == "1234567890"


def test_google_rechaza_el_codigo(cliente: AuthlibGoogleClient, google: respx.MockRouter) -> None:
    google.post(TOKEN_URL).respond(400, json={"error": "invalid_grant"})
    with pytest.raises(GoogleAuthError):
        cliente.exchange_code(
            redirect_uri=REDIRECT, code="viejo", code_verifier=VERIFIER, nonce=NONCE
        )


def test_respuesta_sin_id_token(cliente: AuthlibGoogleClient, google: respx.MockRouter) -> None:
    google.post(TOKEN_URL).respond(json={"access_token": "x"})
    with pytest.raises(GoogleAuthError):
        cliente.exchange_code(redirect_uri=REDIRECT, code="c", code_verifier=VERIFIER, nonce=NONCE)


def test_google_caido(cliente: AuthlibGoogleClient) -> None:
    with respx.mock() as router:
        router.get(DISCOVERY_URL).mock(side_effect=httpx.ConnectError("sin red"))
        with pytest.raises(GoogleAuthError):
            cliente.authorization_url(
                redirect_uri=REDIRECT, state="e", nonce=NONCE, code_verifier=VERIFIER, reauth=False
            )


# --- Configuración ------------------------------------------------------------------------


def test_sin_credenciales_no_hay_cliente(settings: Settings) -> None:
    assert get_google_client(settings) is None
    settings.google_client_id = CLIENT_ID
    settings.google_client_secret = SecretStr("secreto")
    assert isinstance(get_google_client(settings), AuthlibGoogleClient)
