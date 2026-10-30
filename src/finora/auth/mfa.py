"""Verificación en dos pasos con TOTP y códigos de recuperación (RF-AUTH-10 a 13, RN-AUTH-06).

- El secreto TOTP se cifra con AES-256-GCM (FINORA_MFA_ENCRYPTION_KEY); el id del usuario
  va como dato asociado, así que un secreto copiado a otra fila no se puede descifrar.
- Se acepta el intervalo actual y uno a cada lado (±30 s), nunca uno ya usado.
- Los códigos de recuperación (50 bits cada uno) se guardan como HMAC-SHA256 con la misma
  clave del servidor: rápido de verificar y, sin la clave, inútil para probar códigos
  aunque se filtre la BD.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import uuid
from datetime import datetime

import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ISSUER = "FINORA"
TOTP_INTERVAL = 30
TOTP_WINDOW = 1  # intervalos aceptados a cada lado del actual
RECOVERY_CODE_COUNT = 10
_RECOVERY_CODE_CHARS = 10
_NONCE_BYTES = 12
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


# --- Secreto TOTP -------------------------------------------------------------------------


def generate_secret() -> str:
    return pyotp.random_base32()  # 32 caracteres base32: 160 bits


def encrypt_secret(key: bytes, user_id: uuid.UUID, secret: str) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, secret.encode("ascii"), user_id.bytes)


def decrypt_secret(key: bytes, user_id: uuid.UUID, blob: bytes) -> str:
    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ciphertext, user_id.bytes).decode("ascii")


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def current_step(now: datetime) -> int:
    return int(now.timestamp()) // TOTP_INTERVAL


def match_totp(secret: str, code: str, now: datetime, last_used_step: int | None) -> int | None:
    """Intervalo en el que `code` es válido, o None. Nunca acepta un intervalo ya usado."""
    code = re.sub(r"\s", "", code)
    if not re.fullmatch(r"\d{6}", code):
        return None
    totp = pyotp.TOTP(secret)
    now_step = current_step(now)
    for step in range(now_step - TOTP_WINDOW, now_step + TOTP_WINDOW + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(totp.at(step * TOTP_INTERVAL), code):
            return step
    return None


# --- Códigos de recuperación --------------------------------------------------------------


def generate_recovery_codes() -> list[str]:
    """Códigos con formato ABCDE-FGHIJ (10 caracteres base32 legibles)."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_BASE32) for _ in range(_RECOVERY_CODE_CHARS))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def is_recovery_code_format(code: str) -> bool:
    normalized = normalize_recovery_code(code)
    return len(normalized) == _RECOVERY_CODE_CHARS and all(c in _BASE32 for c in normalized)


def hash_recovery_code(key: bytes, code: str) -> str:
    digest = hmac.new(key, normalize_recovery_code(code).encode("ascii"), hashlib.sha256)
    return base64.b64encode(digest.digest()).decode("ascii")
