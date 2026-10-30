"""Pruebas del reloj inyectable (T-AUTH-BE-01)."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from finora.clock import FrozenClock, SystemClock, get_clock

INICIO = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def test_reloj_del_sistema_devuelve_utc() -> None:
    ahora = SystemClock().now()
    assert ahora.utcoffset() == timedelta(0)


def test_dependencia_devuelve_reloj_del_sistema() -> None:
    assert isinstance(get_clock(), SystemClock)


def test_reloj_detenido_no_avanza_solo() -> None:
    reloj = FrozenClock(INICIO)
    assert reloj.now() == INICIO
    assert reloj.now() == INICIO


def test_reloj_detenido_avanza_cuando_se_pide() -> None:
    reloj = FrozenClock(INICIO)
    reloj.advance(timedelta(minutes=30))
    assert reloj.now() == INICIO + timedelta(minutes=30)


def test_reloj_detenido_no_retrocede() -> None:
    reloj = FrozenClock(INICIO)
    with pytest.raises(ValueError):
        reloj.advance(timedelta(seconds=-1))


def test_reloj_detenido_rechaza_instantes_sin_utc() -> None:
    with pytest.raises(ValueError):
        FrozenClock(datetime(2026, 10, 29, 12, 0))  # noqa: DTZ001 - el caso a probar
    with pytest.raises(ValueError):
        FrozenClock(datetime(2026, 10, 29, 7, 0, tzinfo=timezone(timedelta(hours=-5))))
