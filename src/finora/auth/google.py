"""Cliente OpenID Connect de Google (ADR-0002 §1).

Authorization Code con PKCE (S256), `state` y `nonce`. Solo se piden `openid email profile` y
no se guarda ningún token de Google: del intercambio solo se usa el ID token, que se valida
completo (firma con las claves publicadas por Google, `iss`, `aud`, `exp`, `iat` y `nonce`).

La interfaz `GoogleOidcClient` permite reemplazar el cliente real por uno falso en las pruebas.
Todas las peticiones HTTP pasan por un único `httpx.Client` inyectable; de Authlib se usan
solo las funciones que arman la URL y el desafío PKCE (sus clientes HTTP usan `httpx2`).
"""

import logging
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any, Protocol

import httpx
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import Depends
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from finora.config import Settings, get_settings

logger = logging.getLogger(__name__)

DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")
SCOPE = "openid email profile"
_TIMEOUT = 10.0
_CACHE_SECONDS = 3600
_LEEWAY_SECONDS = 60


class GoogleAuthError(Exception):
    """El intercambio con Google falló o el ID token no es válido."""


@dataclass(frozen=True)
class GoogleIdentity:
    subject: str
    email: str
    email_verified: bool
    name: str
    auth_time: int | None = None


class GoogleOidcClient(Protocol):
    def authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, code_verifier: str, reauth: bool
    ) -> str: ...

    def exchange_code(
        self, *, redirect_uri: str, code: str, code_verifier: str, nonce: str
    ) -> GoogleIdentity: ...


def identity_from_claims(claims: dict[str, Any]) -> GoogleIdentity:
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise GoogleAuthError("El ID token no trae correo")
    name = claims.get("name")
    auth_time = claims.get("auth_time")
    return GoogleIdentity(
        subject=str(claims["sub"]),
        email=email,
        email_verified=claims.get("email_verified") is True,
        name=name if isinstance(name, str) else "",
        auth_time=auth_time if isinstance(auth_time, int) else None,
    )


class AuthlibGoogleClient:
    """Cliente real. Los metadatos y las claves de Google se guardan en memoria una hora."""

    def __init__(self, client_id: str, client_secret: str, http: httpx.Client | None = None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = http or httpx.Client(timeout=_TIMEOUT)
        self._metadata: tuple[float, dict[str, Any]] | None = None
        self._keys: tuple[float, KeySet] | None = None

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            response = self._http.get(url)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GoogleAuthError(f"No se pudo leer {url}") from exc
        return data

    def _discovery(self) -> dict[str, Any]:
        if self._metadata is None or time.monotonic() - self._metadata[0] > _CACHE_SECONDS:
            self._metadata = (time.monotonic(), self._get_json(DISCOVERY_URL))
        return self._metadata[1]

    def _key_set(self, *, refresh: bool = False) -> KeySet:
        if refresh or self._keys is None or time.monotonic() - self._keys[0] > _CACHE_SECONDS:
            jwks = self._get_json(self._discovery()["jwks_uri"])
            self._keys = (time.monotonic(), KeySet.import_key_set(jwks))  # type: ignore[arg-type]
        return self._keys[1]

    def authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, code_verifier: str, reauth: bool
    ) -> str:
        extra: dict[str, Any] = {"nonce": nonce}
        if reauth:
            # Pide a Google volver a autenticar al usuario (se revisa `auth_time` al volver).
            extra.update(prompt="select_account", max_age=0)
        url = prepare_grant_uri(
            self._discovery()["authorization_endpoint"],
            self._client_id,
            "code",
            redirect_uri=redirect_uri,
            scope=SCOPE,
            state=state,
            code_challenge=create_s256_code_challenge(code_verifier),
            code_challenge_method="S256",
            **extra,
        )
        return str(url)

    def exchange_code(
        self, *, redirect_uri: str, code: str, code_verifier: str, nonce: str
    ) -> GoogleIdentity:
        try:
            response = self._http.post(
                self._discovery()["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code_verifier": code_verifier,
                },
            )
            response.raise_for_status()
            token = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise GoogleAuthError("Google rechazó el código de autorización") from exc
        id_token = token.get("id_token") if isinstance(token, dict) else None
        if not isinstance(id_token, str):
            raise GoogleAuthError("La respuesta de Google no trae ID token")
        return identity_from_claims(self.validate_id_token(id_token, nonce))

    def validate_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        try:
            try:
                decoded = jwt.decode(id_token, self._key_set(), algorithms=["RS256"])
            except JoseError:
                # Google rota sus claves: un `kid` desconocido obliga a recargarlas una vez.
                decoded = jwt.decode(id_token, self._key_set(refresh=True), algorithms=["RS256"])
            registry = jwt.JWTClaimsRegistry(
                leeway=_LEEWAY_SECONDS,
                iss={"essential": True, "values": list(ISSUERS)},
                aud={"essential": True, "value": self._client_id},
                sub={"essential": True},
                exp={"essential": True},
                iat={"essential": True},
                nonce={"essential": True, "value": nonce},
            )
            registry.validate(decoded.claims)
        except JoseError as exc:
            raise GoogleAuthError("ID token inválido") from exc
        return decoded.claims


@lru_cache
def _real_client(client_id: str, client_secret: str) -> AuthlibGoogleClient:
    return AuthlibGoogleClient(client_id, client_secret)


def get_google_client(
    settings: Annotated[Settings, Depends(get_settings)],
) -> GoogleOidcClient | None:
    """Dependencia FastAPI: None si no hay credenciales (la funcionalidad queda apagada)."""
    if settings.google_client_id is None or settings.google_client_secret is None:
        return None
    return _real_client(settings.google_client_id, settings.google_client_secret.get_secret_value())
