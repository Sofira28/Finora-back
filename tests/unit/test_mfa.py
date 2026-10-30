"""Primitivas de MFA: cifrado del secreto, TOTP y códigos de recuperación (T-AUTH-BE-09)."""

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from cryptography.exceptions import InvalidTag

from finora.auth import mfa

KEY = bytes(range(32))
NOW = datetime(2026, 10, 29, 15, 0, 10, tzinfo=UTC)


def test_secreto_cifrado_y_ligado_al_usuario() -> None:
    user_id = uuid.uuid4()
    secret = mfa.generate_secret()
    blob = mfa.encrypt_secret(KEY, user_id, secret)
    assert secret.encode() not in blob
    assert mfa.decrypt_secret(KEY, user_id, blob) == secret
    # Nonce aleatorio: cifrar dos veces da resultados distintos.
    assert mfa.encrypt_secret(KEY, user_id, secret) != blob
    with pytest.raises(InvalidTag):
        mfa.decrypt_secret(KEY, uuid.uuid4(), blob)  # copiado a otra fila
    with pytest.raises(InvalidTag):
        mfa.decrypt_secret(bytes(32), user_id, blob)  # otra clave


def test_secreto_de_160_bits() -> None:
    secret = mfa.generate_secret()
    assert len(secret) == 32
    assert mfa.generate_secret() != secret


def test_uri_de_aprovisionamiento() -> None:
    uri = mfa.provisioning_uri("JBSWY3DPEHPK3PXP", "ana@correo.com")
    parsed = urlparse(uri)
    assert (parsed.scheme, parsed.netloc) == ("otpauth", "totp")
    assert parsed.path == "/FINORA:ana%40correo.com"
    assert parse_qs(parsed.query) == {"secret": ["JBSWY3DPEHPK3PXP"], "issuer": ["FINORA"]}


# --- TOTP ---------------------------------------------------------------------------------

SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - secreto TOTP de prueba


def _code(at: datetime) -> str:
    return pyotp.TOTP(SECRET).at(at)


def test_acepta_el_intervalo_actual_y_uno_a_cada_lado() -> None:
    step = mfa.current_step(NOW)
    for delta, expected in ((-30, step - 1), (0, step), (30, step + 1)):
        code = _code(NOW + timedelta(seconds=delta))
        assert mfa.match_totp(SECRET, code, NOW, None) == expected


@pytest.mark.parametrize("delta", [-60, 60])
def test_rechaza_fuera_de_la_ventana(delta: int) -> None:
    assert mfa.match_totp(SECRET, _code(NOW + timedelta(seconds=delta)), NOW, None) is None


def test_no_acepta_un_intervalo_ya_usado_ni_anteriores() -> None:
    step = mfa.current_step(NOW)
    assert mfa.match_totp(SECRET, _code(NOW), NOW, last_used_step=step) is None
    previous = _code(NOW - timedelta(seconds=30))
    assert mfa.match_totp(SECRET, previous, NOW, last_used_step=step - 1) is None
    following = _code(NOW + timedelta(seconds=30))
    assert mfa.match_totp(SECRET, following, NOW, last_used_step=step) == step + 1


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", "12 34 5x"])
def test_formato_invalido(code: str) -> None:
    assert mfa.match_totp(SECRET, code, NOW, None) is None


def test_tolera_espacios_al_pegar() -> None:
    code = _code(NOW)
    assert mfa.match_totp(SECRET, f" {code[:3]} {code[3:]} ", NOW, None) is not None


# --- Códigos de recuperación --------------------------------------------------------------


def test_diez_codigos_distintos_con_formato_legible() -> None:
    codes = mfa.generate_recovery_codes()
    assert len(codes) == len(set(codes)) == 10
    for code in codes:
        assert len(code) == 11 and code[5] == "-"
        assert mfa.is_recovery_code_format(code)


def test_hash_tolera_minusculas_espacios_y_guion() -> None:
    expected = mfa.hash_recovery_code(KEY, "ABCDE-FGH23")
    for variant in ("abcde-fgh23", "ABCDEFGH23", " abcde fgh23 "):
        assert mfa.hash_recovery_code(KEY, variant) == expected
    assert mfa.hash_recovery_code(bytes(32), "ABCDE-FGH23") != expected
    assert "ABCDE" not in expected


@pytest.mark.parametrize("code", ["123456", "ABCDE-FGHI", "ABCDE-FGHI18", "ABCDE-FGH!J"])
def test_formato_de_codigo_de_recuperacion_invalido(code: str) -> None:
    assert not mfa.is_recovery_code_format(code)
