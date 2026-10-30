"""Configuración leída de variables de entorno (prefijo FINORA_)."""

import base64
import binascii
import logging
import secrets
from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

MFA_KEY_BYTES = 32  # AES-256-GCM


def _decode_mfa_key(value: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(value.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValueError("FINORA_MFA_ENCRYPTION_KEY debe estar en base64 URL-safe") from exc
    if len(key) != MFA_KEY_BYTES:
        raise ValueError(f"FINORA_MFA_ENCRYPTION_KEY debe decodificar a {MFA_KEY_BYTES} bytes")
    return key


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FINORA_", env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: str = "postgresql+psycopg://finora:finora@localhost:5432/finora"

    # Origen de finora-web: destino de las redirecciones y único Origin permitido.
    web_url: str = "http://localhost:5173"

    # Correo (ADR-0002): por defecto apunta a Mailpit local.
    smtp_host: str = "localhost"
    smtp_port: int = Field(default=1025, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    email_from: str = "FINORA <no-responder@finora.local>"

    # Google (OpenID Connect). Sin ambas credenciales, el inicio con Google se desactiva.
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None

    # Clave AES-256 en base64 URL-safe para cifrar los secretos TOTP.
    mfa_encryption_key: SecretStr | None = None

    privacy_policy_version: str = Field(default="0", min_length=1)

    # Solo si hay un proxy de confianza delante se lee la IP de X-Forwarded-For.
    trusted_proxy: bool = False

    # Límites por IP (RNF-AUTH-04): inicio de sesión por 15 minutos; registro, recuperación
    # y reenvío de correos por hora.
    rate_limit_login_per_ip: int = Field(default=20, ge=1)
    rate_limit_email_per_ip: int = Field(default=10, ge=1)

    @field_validator("web_url")
    @classmethod
    def _normalize_web_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("FINORA_WEB_URL debe empezar por http:// o https://")
        return value.rstrip("/")

    @field_validator(
        "smtp_username",
        "smtp_password",
        "google_client_id",
        "google_client_secret",
        "mfa_encryption_key",
        mode="before",
    )
    @classmethod
    def _empty_as_none(cls, value: object) -> object:
        # Una variable definida pero vacía en .env equivale a no configurarla.
        return None if value == "" else value

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if (self.google_client_id is None) != (self.google_client_secret is None):
            raise ValueError(
                "FINORA_GOOGLE_CLIENT_ID y FINORA_GOOGLE_CLIENT_SECRET van juntas o ninguna"
            )
        if self.mfa_encryption_key is not None:
            _decode_mfa_key(self.mfa_encryption_key.get_secret_value())
        elif self.environment != "development":
            raise ValueError(
                "FINORA_MFA_ENCRYPTION_KEY es obligatoria fuera del entorno development"
            )
        return self

    @property
    def google_enabled(self) -> bool:
        return self.google_client_id is not None

    @property
    def mfa_key(self) -> bytes:
        if self.mfa_encryption_key is not None:
            return _decode_mfa_key(self.mfa_encryption_key.get_secret_value())
        return _ephemeral_mfa_key()


@lru_cache
def _ephemeral_mfa_key() -> bytes:
    # Solo en development sin clave: los secretos TOTP dejan de servir al reiniciar.
    logger.warning(
        "FINORA_MFA_ENCRYPTION_KEY no está definida; se usa una clave temporal de desarrollo"
    )
    return secrets.token_bytes(MFA_KEY_BYTES)


@lru_cache
def get_settings() -> Settings:
    return Settings()
