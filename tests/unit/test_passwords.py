"""Pruebas de contraseñas y correo (T-AUTH-BE-03, RN-AUTH-01/02, VAL-AUTH-02, RNF-AUTH-01)."""

import pytest
from argon2 import PasswordHasher

from finora.auth.passwords import (
    PasswordPolicyError,
    PasswordRule,
    hash_password,
    needs_rehash,
    normalize_email,
    validate_password,
    verify_password,
)

VALIDA = "caballo correcto batería grapa"


@pytest.mark.parametrize(
    ("entrada", "esperado"),
    [("Ana@Correo.com", "ana@correo.com"), ("  ana@correo.com \n", "ana@correo.com")],
)
def test_normaliza_correo(entrada: str, esperado: str) -> None:
    assert normalize_email(entrada) == esperado


@pytest.mark.parametrize(
    ("password", "regla"),
    [
        ("a" * 11, PasswordRule.TOO_SHORT),
        ("a" * 129, PasswordRule.TOO_LONG),
        ("q1w2e3r4t5y6", PasswordRule.TOO_COMMON),
        ("Q1W2E3R4T5Y6", PasswordRule.TOO_COMMON),  # sin distinguir mayúsculas
        ("ana.perez.2026@correo.com", PasswordRule.MATCHES_EMAIL),
        ("ANA.PEREZ.2026", PasswordRule.MATCHES_EMAIL),  # parte local del correo
    ],
)
def test_politica_rechaza(password: str, regla: PasswordRule) -> None:
    with pytest.raises(PasswordPolicyError) as exc:
        validate_password(password, email="Ana.Perez.2026@correo.com")
    assert exc.value.rule == regla
    assert exc.value.message


@pytest.mark.parametrize("password", [VALIDA, "a" * 12 + "x", "🌱" * 12, "x" * 128])
def test_politica_acepta(password: str) -> None:
    validate_password(password, email="ana@correo.com")


def test_longitud_en_caracteres_no_en_bytes() -> None:
    validate_password("ñ" * 12)  # 24 bytes en UTF-8, 12 caracteres
    with pytest.raises(PasswordPolicyError):
        validate_password("ñ" * 11)


def test_mensaje_es_co() -> None:
    with pytest.raises(PasswordPolicyError, match="al menos 12 caracteres"):
        validate_password("corta")


def test_hash_argon2id_y_verificacion() -> None:
    hashed = hash_password(VALIDA)
    assert hashed.startswith("$argon2id$")
    assert VALIDA not in hashed
    assert verify_password(hashed, VALIDA)
    assert not verify_password(hashed, VALIDA + "x")


def test_nfkc_hace_equivalentes_las_formas_unicode() -> None:
    compuesta, descompuesta = "contraseña segura", "contraseña segura"
    assert verify_password(hash_password(compuesta), descompuesta)


def test_sin_hash_devuelve_false() -> None:
    # Cuenta inexistente o solo con Google: se verifica contra el hash de relleno.
    assert verify_password(None, VALIDA) is False
    assert verify_password(None, "finora-hash-de-relleno") is False


def test_hash_invalido_devuelve_false() -> None:
    assert verify_password("no-es-un-hash", VALIDA) is False


def test_detecta_parametros_viejos() -> None:
    viejo = PasswordHasher(time_cost=1, memory_cost=8192).hash(VALIDA)
    assert needs_rehash(viejo)
    assert not needs_rehash(hash_password(VALIDA))
    assert verify_password(viejo, VALIDA)
