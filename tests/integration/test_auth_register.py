"""Registro, verificación y reenvío (T-AUTH-BE-07).

CA-AUTH-01, CA-AUTH-03 (registro y reenvío), RF-AUTH-01 a 03, VAL-AUTH-01 a 04, VAL-AUTH-09.
"""

import re
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.auth.models import DataConsent, SecurityEvent, User
from finora.auth.passwords import hash_password, verify_password
from finora.clock import FrozenClock
from finora.config import Settings
from finora.email import EmailDeliveryError, InMemoryEmailSender, OutgoingEmail, get_email_sender

CLAVE = "caballo correcto batería grapa"
MENSAJE = {"message": "Te enviamos un correo para confirmar tu cuenta."}


def _registro(**cambios: Any) -> dict[str, Any]:
    datos = {
        "email": "ana@correo.com",
        "name": "Ana",
        "password": CLAVE,
        "privacy_policy_version": "0",
    }
    datos.update(cambios)
    return datos


def _token(correo: OutgoingEmail) -> str:
    encontrado = re.search(r"/verificar-correo\?token=([\w-]+)", correo.text)
    assert encontrado, correo.text
    return encontrado.group(1)


def _usuarios(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


# --- CA-AUTH-01 ---------------------------------------------------------------------------


def test_ca_auth_01_registro_verificacion_e_inicio_de_sesion(
    client: TestClient, email_outbox: InMemoryEmailSender
) -> None:
    response = client.post("/api/v1/auth/register", json=_registro())
    assert response.status_code == 202
    assert response.json() == MENSAJE

    [correo] = email_outbox.outbox
    assert correo.to == "ana@correo.com"
    assert correo.subject == "Confirma tu correo en FINORA"
    assert "http://localhost:5173/verificar-correo?token=" in correo.text

    login = {"email": "ana@correo.com", "password": CLAVE}
    assert client.post("/api/v1/auth/login", json=login).status_code == 403  # aún sin verificar
    assert (
        client.post("/api/v1/auth/verify-email", json={"token": _token(correo)}).status_code == 204
    )
    response = client.post("/api/v1/auth/login", json=login)
    assert response.status_code == 200
    assert response.json() == {"next": "app"}


def test_registro_guarda_datos_normalizados_y_consentimiento(
    client: TestClient, db_session: Session, clock: FrozenClock
) -> None:
    client.post("/api/v1/auth/register", json=_registro(email=" Ana@Correo.com", name="  Ana  "))
    user = db_session.scalars(select(User)).one()
    assert (user.email, user.name, user.email_verified_at) == ("ana@correo.com", "Ana", None)
    assert user.password_hash is not None and user.password_hash.startswith("$argon2id$")
    assert verify_password(user.password_hash, CLAVE)
    consentimiento = db_session.scalars(select(DataConsent)).one()
    assert (consentimiento.user_id, consentimiento.policy_version) == (user.id, "0")
    assert consentimiento.accepted_at == clock.now()
    evento = db_session.scalars(select(SecurityEvent)).one()
    assert (evento.type, evento.user_id) == ("registered", user.id)


# --- Validaciones (VAL-AUTH-01 a 03) ------------------------------------------------------


@pytest.mark.parametrize("email", ["", "ana", "ana@", "@correo.com", "ana correo@x.co"])
def test_val_auth_01_correo_invalido(client: TestClient, email: str) -> None:
    response = client.post("/api/v1/auth/register", json=_registro(email=email))
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "email"]


@pytest.mark.parametrize(
    ("password", "tipo", "mensaje"),
    [
        ("corta", "too_short", "La contraseña debe tener al menos 12 caracteres."),
        ("x" * 129, "too_long", "La contraseña no puede tener más de 128 caracteres."),
        ("q1w2e3r4t5y6", "too_common", "Esta contraseña es muy común. Elige otra."),
        ("ana@correo.com", "matches_email", "La contraseña no puede ser tu correo."),
    ],
)
def test_val_auth_02_politica_de_contrasena(
    client: TestClient, db_session: Session, password: str, tipo: str, mensaje: str
) -> None:
    response = client.post("/api/v1/auth/register", json=_registro(password=password))
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "validation_failed"
    assert body["errors"] == [{"loc": ["body", "password"], "type": tipo, "message": mensaje}]
    assert _usuarios(db_session) == 0


@pytest.mark.parametrize("name", ["", "   ", "a" * 101])
def test_val_auth_03_nombre_invalido(client: TestClient, name: str) -> None:
    response = client.post("/api/v1/auth/register", json=_registro(name=name))
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "name"]


def test_politica_de_datos_debe_ser_la_vigente(client: TestClient, db_session: Session) -> None:
    response = client.post("/api/v1/auth/register", json=_registro(privacy_policy_version="9"))
    assert response.status_code == 422
    assert response.json()["errors"][0]["type"] == "policy_not_accepted"
    assert _usuarios(db_session) == 0


def test_campos_desconocidos_se_rechazan(client: TestClient) -> None:
    # Nadie puede fijar, por ejemplo, el correo como verificado.
    response = client.post("/api/v1/auth/register", json=_registro(email_verified=True))
    assert response.status_code == 422


# --- Registro duplicado (VAL-AUTH-04, CA-AUTH-03) -----------------------------------------


def test_registro_con_correo_verificado_responde_igual_y_avisa(
    client: TestClient, db_session: Session, email_outbox: InMemoryEmailSender, clock: FrozenClock
) -> None:
    original = hash_password("otra clave muy larga 1")
    db_session.add(
        User(
            email="ana@correo.com",
            name="Ana Original",
            password_hash=original,
            email_verified_at=clock.now(),
            created_at=clock.now(),
        )
    )
    db_session.flush()

    duplicado = client.post("/api/v1/auth/register", json=_registro(name="Intruso"))
    nuevo = client.post("/api/v1/auth/register", json=_registro(email="luis@correo.com"))
    assert (duplicado.status_code, duplicado.json()) == (nuevo.status_code, nuevo.json())

    aviso = email_outbox.outbox[0]
    assert (aviso.to, aviso.subject) == ("ana@correo.com", "Ya tienes una cuenta en FINORA")
    assert "Hola, Ana Original:" in aviso.text
    ana = db_session.scalars(select(User).where(User.email == "ana@correo.com")).one()
    assert (ana.name, ana.password_hash) == ("Ana Original", original)


def test_registro_con_correo_sin_verificar_reenvia_sin_cambiar_datos(
    client: TestClient, db_session: Session, email_outbox: InMemoryEmailSender
) -> None:
    client.post("/api/v1/auth/register", json=_registro())
    primer_token = _token(email_outbox.outbox[0])
    otra = _registro(name="Otra", password="otra clave muy larga 2")  # noqa: S106 - de prueba
    response = client.post("/api/v1/auth/register", json=otra)
    assert response.json() == MENSAJE
    segundo = email_outbox.outbox[1]
    assert segundo.subject == "Confirma tu correo en FINORA"
    assert "Hola, Ana:" in segundo.text
    # El enlace anterior deja de servir (RN-AUTH-04).
    assert client.post("/api/v1/auth/verify-email", json={"token": primer_token}).status_code == 400
    assert (
        client.post("/api/v1/auth/verify-email", json={"token": _token(segundo)}).status_code == 204
    )
    ana = db_session.scalars(select(User)).one()
    assert verify_password(ana.password_hash, CLAVE)


# --- Verificación (VAL-AUTH-09) -----------------------------------------------------------


def test_enlace_usado_o_inventado(client: TestClient, email_outbox: InMemoryEmailSender) -> None:
    client.post("/api/v1/auth/register", json=_registro())
    token = _token(email_outbox.outbox[0])
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 204
    for valor in (token, "inventado"):
        response = client.post("/api/v1/auth/verify-email", json={"token": valor})
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_token"
        assert response.json()["title"] == "Este enlace ya no es válido. Solicita uno nuevo."


def test_enlace_vence_a_las_24_horas(
    client: TestClient, email_outbox: InMemoryEmailSender, clock: FrozenClock
) -> None:
    client.post("/api/v1/auth/register", json=_registro())
    clock.advance(timedelta(hours=24))
    token = _token(email_outbox.outbox[0])
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 400


# --- Reenvío ------------------------------------------------------------------------------


def test_reenvio_solo_a_cuentas_sin_verificar_y_sin_revelar_nada(
    client: TestClient, email_outbox: InMemoryEmailSender
) -> None:
    client.post("/api/v1/auth/register", json=_registro())
    client.post("/api/v1/auth/register", json=_registro(email="luis@correo.com"))
    client.post("/api/v1/auth/verify-email", json={"token": _token(email_outbox.outbox[1])})
    email_outbox.outbox.clear()

    respuestas = [
        client.post("/api/v1/auth/verify-email/resend", json={"email": correo})
        for correo in ("ANA@correo.com", "luis@correo.com", "nadie@correo.com")
    ]
    assert {(r.status_code, r.json()["message"]) for r in respuestas} == {
        (202, "Si tu cuenta está pendiente de confirmar, te enviamos un nuevo enlace.")
    }
    assert [c.to for c in email_outbox.outbox] == ["ana@correo.com"]


# --- Límites y robustez -------------------------------------------------------------------


def test_limite_por_ip_en_registro_y_reenvio(client: TestClient, settings: Settings) -> None:
    settings.rate_limit_email_per_ip = 2
    assert client.post("/api/v1/auth/register", json=_registro()).status_code == 202
    resend = {"email": "ana@correo.com"}
    assert client.post("/api/v1/auth/verify-email/resend", json=resend).status_code == 202
    response = client.post("/api/v1/auth/register", json=_registro(email="luis@correo.com"))
    assert response.status_code == 429
    assert response.headers["retry-after"] == "3600"


def test_fallo_del_correo_no_rompe_el_registro(client: TestClient) -> None:
    class SenderRoto:
        def send(self, email: OutgoingEmail) -> None:
            raise EmailDeliveryError("SMTP caído")

    client.app.dependency_overrides[get_email_sender] = SenderRoto  # type: ignore[attr-defined]
    response = client.post("/api/v1/auth/register", json=_registro())
    assert (response.status_code, response.json()) == (202, MENSAJE)


def test_sin_origin_se_rechaza(client: TestClient) -> None:
    del client.headers["Origin"]
    response = client.post("/api/v1/auth/register", json=_registro())
    assert response.status_code == 403
    assert response.json()["code"] == "csrf_failed"
