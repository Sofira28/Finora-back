"""Formato de la petición de movimientos (T-TRX-BE-02): VAL-TRX-01, 02, 07, 08 y 11.

Las reglas que dependen del tipo o de otras filas las prueba el servicio.
"""

import uuid
from datetime import date
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from finora.transactions.schemas import TransactionRequest

BASE: dict[str, Any] = {"type": "expense", "date": "2026-10-29", "account_id": str(uuid.uuid4())}


def _valida(**datos: Any) -> TransactionRequest:
    return TransactionRequest.model_validate({**BASE, **datos})


def _error(**datos: Any) -> tuple[str, str]:
    with pytest.raises(ValidationError) as exc:
        _valida(**datos)
    [detalle] = exc.value.errors()
    return str(detalle["loc"][0]), detalle["type"]


def test_peticion_valida() -> None:
    peticion = _valida(
        amount="120000.5", category="groceries", description="  Mercado  ", note="Línea 1\r\nL2"
    )
    assert peticion.amount == Decimal("120000.5")
    assert peticion.date == date(2026, 10, 29)
    assert peticion.description == "Mercado"
    assert peticion.note == "Línea 1\nL2"


@pytest.mark.parametrize("monto", [120000, 120000.5, "0", "-1", "1.234", "1e5", "", "1.000"])
def test_monto_invalido(monto: Any) -> None:
    assert _error(amount=monto) == ("amount", "value_error")


@pytest.mark.parametrize("saldo", ["-150000", "0", "1250000.50"])
def test_saldo_real_admite_cero_y_negativos(saldo: str) -> None:
    assert _valida(type="adjustment", target_balance=saldo).target_balance == Decimal(saldo)


@pytest.mark.parametrize(
    "fecha", [20261029, "29/10/2026", "2026-02-30", "2026-10-29T10:00:00", "2026-1-9", None]
)
def test_fecha_invalida(fecha: Any) -> None:
    campo, _ = _error(date=fecha)
    assert campo == "date"


@pytest.mark.parametrize(
    ("descripcion", "tipo"),
    [("x" * 81, "string_too_long"), ("Mercado\nÉxito", "value_error"), ("A\x07", "value_error")],
)
def test_descripcion_invalida(descripcion: str, tipo: str) -> None:
    assert _error(description=descripcion) == ("description", tipo)


@pytest.mark.parametrize("vacio", ["", "   "])
def test_textos_vacios_son_ausentes(vacio: str) -> None:
    peticion = _valida(description=vacio, note=vacio)
    assert (peticion.description, peticion.note) == (None, None)


@pytest.mark.parametrize(
    ("nota", "tipo"), [("n" * 501, "string_too_long"), ("Con\x00nulo", "value_error")]
)
def test_nota_invalida(nota: str, tipo: str) -> None:
    assert _error(note=nota) == ("note", tipo)


def test_nota_de_500_caracteres() -> None:
    assert _valida(note="n" * 500).note == "n" * 500


@pytest.mark.parametrize(
    "datos",
    [
        {"type": "gasto"},
        {"category": "otra"},
        {"account_id": "no-es-uuid"},
        {"destination_account_id": "123"},
        {"currency": "COP"},  # campo desconocido (VAL-TRX-11)
    ],
)
def test_formato(datos: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        _valida(**datos)
