"""Pruebas de la configuración por entorno (T-AUTH-BE-01)."""

import base64
import os
import secrets

import pytest
from pydantic import ValidationError

from finora.config import Settings

CLAVE_MFA = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture(autouse=True)
def _entorno_limpio(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sin .env (directorio sin él) ni variables FINORA_ heredadas del sistema.
    monkeypatch.chdir("/")
    for nombre in list(os.environ):
        if nombre.startswith("FINORA_"):
            monkeypatch.delenv(nombre)


def test_arranca_en_development_sin_google_ni_smtp_de_produccion() -> None:
    settings = Settings()
    assert settings.environment == "development"
    assert settings.google_enabled is False
    assert (settings.smtp_host, settings.smtp_port) == ("localhost", 1025)
    assert settings.web_url == "http://localhost:5173"
    assert settings.privacy_policy_version == "0"
    assert settings.trusted_proxy is False


def test_variables_vacias_equivalen_a_no_configuradas() -> None:
    settings = Settings(
        google_client_id="",
        google_client_secret="",  # type: ignore[arg-type]
        smtp_username="",
        mfa_encryption_key="",  # type: ignore[arg-type]
    )
    assert settings.google_enabled is False
    assert settings.smtp_username is None
    assert settings.mfa_encryption_key is None


@pytest.mark.parametrize("entorno", ["test", "production"])
def test_clave_mfa_obligatoria_fuera_de_development(entorno: str) -> None:
    with pytest.raises(ValidationError, match="FINORA_MFA_ENCRYPTION_KEY es obligatoria"):
        Settings(environment=entorno)  # type: ignore[arg-type]


def test_production_con_clave_mfa_valida() -> None:
    settings = Settings(environment="production", mfa_encryption_key=CLAVE_MFA)  # type: ignore[arg-type]
    assert settings.mfa_key == base64.urlsafe_b64decode(CLAVE_MFA)


def test_development_sin_clave_usa_una_temporal_estable() -> None:
    settings = Settings()
    assert len(settings.mfa_key) == 32
    assert settings.mfa_key == Settings().mfa_key


@pytest.mark.parametrize(
    "clave",
    [
        "no-es-base64!",
        base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(),  # AES-128: muy corta
    ],
)
def test_rechaza_clave_mfa_invalida(clave: str) -> None:
    with pytest.raises(ValidationError, match="FINORA_MFA_ENCRYPTION_KEY debe"):
        Settings(mfa_encryption_key=clave)  # type: ignore[arg-type]


def test_google_requiere_ambas_credenciales() -> None:
    with pytest.raises(ValidationError, match="van juntas"):
        Settings(google_client_id="id.apps.googleusercontent.com")
    with pytest.raises(ValidationError, match="van juntas"):
        Settings(google_client_secret="secreto")  # type: ignore[arg-type]  # noqa: S106 - valor falso


def test_google_habilitado_con_ambas_credenciales() -> None:
    settings = Settings(
        google_client_id="id.apps.googleusercontent.com",
        google_client_secret="secreto",  # type: ignore[arg-type]  # noqa: S106 - valor falso
    )
    assert settings.google_enabled is True


def test_rechaza_entorno_desconocido() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="prod")  # type: ignore[arg-type]


def test_web_url_se_normaliza_sin_barra_final() -> None:
    assert Settings(web_url="https://app.finora.co/").web_url == "https://app.finora.co"


def test_web_url_debe_ser_http() -> None:
    with pytest.raises(ValidationError, match="FINORA_WEB_URL"):
        Settings(web_url="app.finora.co")


@pytest.mark.parametrize("puerto", [0, 70000])
def test_puerto_smtp_fuera_de_rango(puerto: int) -> None:
    with pytest.raises(ValidationError):
        Settings(smtp_port=puerto)


def test_lee_variables_de_entorno(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FINORA_ENVIRONMENT", "test")
    monkeypatch.setenv("FINORA_MFA_ENCRYPTION_KEY", CLAVE_MFA)
    monkeypatch.setenv("FINORA_TRUSTED_PROXY", "true")
    settings = Settings()
    assert settings.environment == "test"
    assert settings.trusted_proxy is True
