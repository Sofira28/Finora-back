"""Formato de las peticiones de /accounts (T-ACC-BE-02): VAL-ACC-01, 03, 04 (formato), 05 y 06."""

from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from finora.accounts.schemas import CreateAccountRequest, UpdateAccountRequest


def _crear(**cambios: Any) -> CreateAccountRequest:
    datos: dict[str, Any] = {"name": "Nómina", "type": "bank", "opening_balance": "2800000"}
    datos.update(cambios)
    return CreateAccountRequest.model_validate(datos)


def _campo_con_error(**cambios: Any) -> str:
    with pytest.raises(ValidationError) as exc:
        _crear(**cambios)
    return str(exc.value.errors()[0]["loc"][0])


# --- Montos (VAL-ACC-03, DP-API-03) -------------------------------------------------------


@pytest.mark.parametrize(
    ("texto", "valor"),
    [
        ("2800000", Decimal(2_800_000)),
        ("1250000.5", Decimal("1250000.5")),
        ("0.10", Decimal("0.10")),
        ("0", Decimal(0)),
        ("-150000", Decimal(-150_000)),
        ("999999999999999.99", Decimal("999999999999999.99")),
    ],
)
def test_montos_validos(texto: str, valor: Decimal) -> None:
    assert _crear(opening_balance=texto).opening_balance == valor


@pytest.mark.parametrize(
    "monto",
    [
        2800000,  # número JSON: no se acepta (podría venir como float)
        0.1,
        "1.250.000",  # formato de pantalla: lo convierte el frontend
        "1250000,50",
        "12.345",  # tres decimales
        "1e6",
        "",
        " 100",
        "+100",
        "1234567890123456",  # 16 dígitos enteros
        "NaN",
        True,
        None,
    ],
)
def test_montos_invalidos(monto: Any) -> None:
    assert _campo_con_error(opening_balance=monto) == "opening_balance"


@pytest.mark.parametrize("cupo", ["0", "-1", "0.00"])
def test_cupo_debe_ser_positivo(cupo: str) -> None:
    assert _campo_con_error(type="credit_card", credit_limit=cupo) == "credit_limit"


# --- Textos (VAL-ACC-01) ------------------------------------------------------------------


def test_nombre_sin_espacios_en_los_extremos() -> None:
    assert _crear(name="  Nómina  ").name == "Nómina"


@pytest.mark.parametrize("nombre", ["", "   ", "a" * 61, "Nómina\nFalsa", "Nó\tmina", "Ana\x00"])
def test_nombre_invalido(nombre: str) -> None:
    assert _campo_con_error(name=nombre) == "name"


def test_nombre_de_60_caracteres() -> None:
    assert _crear(name="a" * 60).name == "a" * 60


@pytest.mark.parametrize(
    ("entidad", "esperada"), [("", None), ("   ", None), (" Andino ", "Andino")]
)
def test_entidad_vacia_es_ninguna(entidad: str, esperada: str | None) -> None:
    assert _crear(institution=entidad).institution == esperada


@pytest.mark.parametrize("entidad", ["b" * 61, "Banco\r\nX"])
def test_entidad_invalida(entidad: str) -> None:
    assert _campo_con_error(institution=entidad) == "institution"


# --- Tipo, días y campos permitidos -------------------------------------------------------


@pytest.mark.parametrize("tipo", ["corriente", "BANK", "", None])
def test_tipo_invalido(tipo: Any) -> None:
    assert _campo_con_error(type=tipo) == "type"


@pytest.mark.parametrize("dia", [0, 32, "28", 28.0, True])
def test_dia_invalido(dia: Any) -> None:
    assert _campo_con_error(type="credit_card", statement_day=dia) == "statement_day"


def test_campos_desconocidos_se_rechazan() -> None:
    assert _campo_con_error(user_id="0193") == "user_id"


def test_la_edicion_no_admite_el_tipo() -> None:
    """VAL-ACC-06 / RN-ACC-08."""
    with pytest.raises(ValidationError) as exc:
        UpdateAccountRequest.model_validate({"type": "cash"})
    assert exc.value.errors()[0]["loc"] == ("type",)


def test_la_edicion_distingue_lo_enviado() -> None:
    cambios = UpdateAccountRequest.model_validate({"institution": None, "name": " Nueva "})
    assert cambios.model_fields_set == {"institution", "name"}
    assert (cambios.name, cambios.institution) == ("Nueva", None)
