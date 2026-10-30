"""Limitación de intentos (T-AUTH-BE-06, RNF-AUTH-04, VAL-AUTH-07; base de CA-AUTH-09)."""

from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.requests import Request

from finora.auth.models import LoginAttempt
from finora.auth.rate_limit import (
    ACCOUNT_FAILURES,
    account_key,
    check,
    client_ip,
    email_ip_limit,
    ip_key,
    login_ip_limit,
    purge_attempts,
    record,
    too_many_attempts,
)
from finora.clock import FrozenClock
from finora.config import Settings
from finora.errors import ApiProblemError

CUENTA = account_key("ana@correo.com")


def _fallar(db: Session, clock: FrozenClock, veces: int, key: str = CUENTA) -> None:
    for _ in range(veces):
        record(db, key, ACCOUNT_FAILURES, clock.now())


def test_cuatro_fallos_no_bloquean(db_session: Session, clock: FrozenClock) -> None:
    _fallar(db_session, clock, 4)
    check(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())


def test_cinco_fallos_bloquean_15_minutos(db_session: Session, clock: FrozenClock) -> None:
    _fallar(db_session, clock, 5)
    with pytest.raises(ApiProblemError) as exc:
        check(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())
    assert exc.value.status == 429
    assert exc.value.code == "too_many_attempts"
    assert exc.value.headers == {"Retry-After": "900"}

    clock.advance(timedelta(minutes=14, seconds=59))
    with pytest.raises(ApiProblemError):
        check(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())
    clock.advance(timedelta(seconds=1))
    check(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())


def test_retry_after_segun_el_fallo_mas_antiguo(db_session: Session, clock: FrozenClock) -> None:
    for _ in range(5):
        record(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())
        clock.advance(timedelta(minutes=2))
    # El primer fallo fue hace 10 minutos: faltan 5 para que salga de la ventana.
    with pytest.raises(ApiProblemError) as exc:
        check(db_session, CUENTA, ACCOUNT_FAILURES, clock.now())
    assert exc.value.headers == {"Retry-After": "300"}


def test_claves_y_tipos_son_independientes(
    db_session: Session, clock: FrozenClock, settings: Settings
) -> None:
    _fallar(db_session, clock, 5)
    check(db_session, account_key("luis@correo.com"), ACCOUNT_FAILURES, clock.now())
    check(db_session, CUENTA, login_ip_limit(settings), clock.now())


def test_clave_de_cuenta_normaliza_y_no_expone_el_correo() -> None:
    assert account_key(" Ana@Correo.com ") == CUENTA
    assert "ana" not in CUENTA
    assert CUENTA.startswith("account:")


def test_limites_por_ip_configurables(db_session: Session, clock: FrozenClock) -> None:
    settings = Settings(rate_limit_login_per_ip=3, rate_limit_email_per_ip=2, _env_file=None)  # type: ignore[call-arg]
    login, correo = login_ip_limit(settings), email_ip_limit(settings)
    assert (login.max_attempts, login.window) == (3, timedelta(minutes=15))
    assert (correo.max_attempts, correo.window) == (2, timedelta(hours=1))
    clave = ip_key("203.0.113.7")
    for _ in range(2):
        record(db_session, clave, correo, clock.now())
    with pytest.raises(ApiProblemError) as exc:
        check(db_session, clave, correo, clock.now())
    assert exc.value.headers == {"Retry-After": "3600"}


def test_valores_por_defecto(settings: Settings) -> None:
    assert login_ip_limit(settings).max_attempts == 20
    assert email_ip_limit(settings).max_attempts == 10


def test_purga_intentos_de_mas_de_una_hora(db_session: Session, clock: FrozenClock) -> None:
    _fallar(db_session, clock, 2)
    clock.advance(timedelta(minutes=59))
    _fallar(db_session, clock, 1)
    clock.advance(timedelta(minutes=1))
    purge_attempts(db_session, clock.now())
    assert db_session.scalar(select(func.count()).select_from(LoginAttempt)) == 1


# --- IP del cliente -----------------------------------------------------------------------


def _request(host: str | None, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": headers,
        "client": (host, 50000) if host else None,
    }
    return Request(scope)


@pytest.mark.parametrize(
    ("host", "forwarded", "confiar", "esperado"),
    [
        ("203.0.113.7", None, False, "203.0.113.7"),
        ("2001:db8::1", None, False, "2001:db8::1"),
        ("testclient", None, False, None),
        (None, None, False, None),
        # Sin proxy de confianza, X-Forwarded-For se ignora (lo puede falsificar el cliente).
        ("10.0.0.2", "198.51.100.9", False, "10.0.0.2"),
        # Con proxy de confianza, vale la última IP: la que agregó el proxy.
        ("10.0.0.2", "1.1.1.1, 198.51.100.9", True, "198.51.100.9"),
        ("10.0.0.2", "no-es-ip", True, None),
    ],
)
def test_ip_del_cliente(
    host: str | None, forwarded: str | None, confiar: bool, esperado: str | None
) -> None:
    settings = Settings(trusted_proxy=confiar, _env_file=None)  # type: ignore[call-arg]
    assert client_ip(_request(host, forwarded), settings) == esperado


def test_clave_de_ip_desconocida() -> None:
    assert ip_key(None) == "ip:unknown"


# --- Respuesta HTTP -----------------------------------------------------------------------


def test_respuesta_429_con_retry_after(app: FastAPI) -> None:
    @app.get("/api/v1/_limite")
    def limite() -> None:
        raise too_many_attempts(120)

    response = TestClient(app).get("/api/v1/_limite")
    assert response.status_code == 429
    assert response.headers["retry-after"] == "120"
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "too_many_attempts"
    assert response.json()["title"] == "Demasiados intentos. Intenta de nuevo en unos minutos."
