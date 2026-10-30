"""Reloj inyectable (UTC) para que las expiraciones se puedan probar sin esperar."""

from datetime import UTC, datetime, timedelta
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Instante actual, siempre con zona horaria UTC."""
        ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """Reloj detenido que solo avanza cuando se le pide (pruebas)."""

    def __init__(self, start: datetime) -> None:
        if start.utcoffset() != timedelta(0):
            raise ValueError("FrozenClock requiere un instante en UTC")
        self._now = start.astimezone(UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        if delta < timedelta(0):
            raise ValueError("El reloj no retrocede")
        self._now += delta


_system_clock = SystemClock()


def get_clock() -> Clock:
    # Dependencia de FastAPI; las pruebas la reemplazan con dependency_overrides.
    return _system_clock
