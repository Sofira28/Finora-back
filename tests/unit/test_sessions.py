"""Reglas de expiración y cookie de sesión (T-AUTH-BE-05, RF-AUTH-07, RNF-AUTH-02)."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Response

from finora.auth.models import AuthSession
from finora.auth.sessions import (
    COOKIE_NAME,
    SessionStage,
    clear_session_cookie,
    is_expired,
    is_recently_reauthenticated,
    set_session_cookie,
)

INICIO = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)


def _sesion(stage: SessionStage = SessionStage.ACTIVE, **cambios: object) -> AuthSession:
    datos: dict[str, object] = {
        "stage": stage,
        "created_at": INICIO,
        "last_activity_at": INICIO,
        "expires_at": INICIO + (timedelta(days=7) if stage == "active" else timedelta(minutes=5)),
    }
    datos.update(cambios)
    return AuthSession(**datos)


@pytest.mark.parametrize(
    ("transcurrido", "vencida"),
    [
        (timedelta(minutes=29, seconds=59), False),
        (timedelta(minutes=30), True),  # CA-AUTH-05
    ],
)
def test_inactividad_de_30_minutos(transcurrido: timedelta, vencida: bool) -> None:
    assert is_expired(_sesion(), INICIO + transcurrido) is vencida


def test_maximo_de_7_dias_aunque_haya_actividad() -> None:
    # CA-AUTH-06: actividad hace un minuto, pero ya pasaron 7 días.
    limite = INICIO + timedelta(days=7)
    sesion = _sesion(last_activity_at=limite - timedelta(minutes=1))
    assert is_expired(sesion, limite - timedelta(seconds=1)) is False
    assert is_expired(sesion, limite) is True


@pytest.mark.parametrize("etapa", [SessionStage.MFA_PENDING, SessionStage.LINK_PENDING])
def test_sesiones_parciales_duran_5_minutos(etapa: SessionStage) -> None:
    sesion = _sesion(etapa)
    assert is_expired(sesion, INICIO + timedelta(minutes=4, seconds=59)) is False
    assert is_expired(sesion, INICIO + timedelta(minutes=5)) is True


@pytest.mark.parametrize(
    ("reautenticada", "vigente"),
    [
        (None, False),
        (INICIO, True),
        (INICIO - timedelta(minutes=4, seconds=59), True),
        (INICIO - timedelta(minutes=5), False),
    ],
)
def test_reautenticacion_reciente(reautenticada: datetime | None, vigente: bool) -> None:
    sesion = _sesion(reauthenticated_at=reautenticada)
    assert is_recently_reauthenticated(sesion, INICIO) is vigente


def test_cookie_segura_sin_max_age() -> None:
    response = Response()
    set_session_cookie(response, "valor")
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE_NAME}=valor;")
    for atributo in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
        assert atributo in cookie
    assert "Max-Age" not in cookie
    assert "expires" not in cookie.lower()


def test_borrar_cookie() -> None:
    response = Response()
    clear_session_cookie(response)
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f'{COOKIE_NAME}="";')
    assert "Max-Age=0" in cookie
    assert "Secure" in cookie
