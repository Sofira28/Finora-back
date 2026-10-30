"""Contraseñas y correo: hash Argon2id, política RN-AUTH-02 y normalización RN-AUTH-01.

Política según NIST SP 800-63B: longitud mínima y máxima, sin reglas de composición y
rechazo de contraseñas comunes o filtradas. Antes de medir, comparar o calcular el hash,
la contraseña se normaliza con NFKC para que la misma contraseña escrita con distintas
secuencias Unicode sea equivalente.
"""

import unicodedata
from enum import StrEnum
from functools import lru_cache
from importlib import resources

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 12
MAX_LENGTH = 128

# Parámetros por defecto de argon2-cffi (Argon2id, RFC 9106 perfil de baja memoria).
_hasher = PasswordHasher()


class PasswordRule(StrEnum):
    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    TOO_COMMON = "too_common"
    MATCHES_EMAIL = "matches_email"


# Mensajes de VAL-AUTH-02 (es-CO).
MESSAGES: dict[PasswordRule, str] = {
    PasswordRule.TOO_SHORT: f"La contraseña debe tener al menos {MIN_LENGTH} caracteres.",
    PasswordRule.TOO_LONG: f"La contraseña no puede tener más de {MAX_LENGTH} caracteres.",
    PasswordRule.TOO_COMMON: "Esta contraseña es muy común. Elige otra.",
    PasswordRule.MATCHES_EMAIL: "La contraseña no puede ser tu correo.",
}


class PasswordPolicyError(ValueError):
    def __init__(self, rule: PasswordRule) -> None:
        super().__init__(MESSAGES[rule])
        self.rule = rule
        self.message = MESSAGES[rule]


def normalize_email(email: str) -> str:
    """RN-AUTH-01: sin espacios en los extremos y en minúsculas."""
    return email.strip().lower()


def _normalize_password(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    # Lista local derivada de SecLists (ver common_passwords.LICENSE); sin llamadas externas.
    text = resources.files("finora.auth").joinpath("common_passwords.txt").read_text("utf-8")
    return frozenset(text.splitlines())


def validate_password(password: str, *, email: str | None = None) -> None:
    """Aplica RN-AUTH-02 completa. Lanza PasswordPolicyError con la primera regla incumplida."""
    normalized = _normalize_password(password)
    length = len(normalized)  # caracteres Unicode, no bytes
    if length < MIN_LENGTH:
        raise PasswordPolicyError(PasswordRule.TOO_SHORT)
    if length > MAX_LENGTH:
        raise PasswordPolicyError(PasswordRule.TOO_LONG)

    folded = normalized.lower()
    if email is not None:
        address = normalize_email(email)
        local_part = address.partition("@")[0]
        if folded in {address, local_part}:
            raise PasswordPolicyError(PasswordRule.MATCHES_EMAIL)
    if folded in _common_passwords():
        raise PasswordPolicyError(PasswordRule.TOO_COMMON)


def hash_password(password: str) -> str:
    return _hasher.hash(_normalize_password(password))


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash("finora-hash-de-relleno")


def verify_password(password_hash: str | None, password: str) -> bool:
    """Compara en tiempo similar exista o no la cuenta (RNF-AUTH-03).

    Sin hash (cuenta inexistente o solo con Google) se verifica contra un hash de relleno
    y se devuelve False, para que el tiempo de respuesta no revele nada.
    """
    try:
        _hasher.verify(password_hash or _dummy_hash(), _normalize_password(password))
    except VerifyMismatchError, VerificationError, InvalidHashError:
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    """True si el hash usa parámetros distintos a los actuales y debe recalcularse."""
    return _hasher.check_needs_rehash(password_hash)
