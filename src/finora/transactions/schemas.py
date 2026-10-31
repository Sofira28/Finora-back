"""Modelos de request y response de /transactions (api-contracts.md §6; spec §9 y §10).

Un solo modelo de petición para los cuatro tipos, como en `accounts`: Pydantic valida el
formato de cada campo (422 con `loc` y `type`) y el servicio aplica qué campos lleva cada
tipo (VAL-TRX-11) y las reglas con otras filas, con mensajes es-CO. Así los errores de
campo tienen siempre `loc: ["body", "<campo>"]`.
"""

import re
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    StringConstraints,
    WithJsonSchema,
)

from finora.accounts.schemas import Amount, ApiAmount
from finora.transactions.models import Category, TransactionType
from finora.validation import reject_control_characters, strip_control_characters

DESCRIPTION_MAX = 80
NOTE_MAX = 500


def _positive(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("Escribe un monto mayor que cero, p. ej. 1.250.000.")
    return value


def _blank_as_none(value: Any) -> Any:
    # Texto vacío o solo con espacios: el campo no se envió.
    return None if isinstance(value, str) and not value.strip() else value


def _note_lines(value: str) -> str:
    """VAL-TRX-08: la nota admite saltos de línea, pero ningún otro carácter de control."""
    unified = value.replace("\r\n", "\n")
    if strip_control_characters(unified.replace("\n", "")) != unified.replace("\n", ""):
        raise ValueError("La nota no puede tener caracteres de control.")
    return unified


PositiveAmount = Annotated[Amount, AfterValidator(_positive)]
# Fecha ISO `AAAA-MM-DD` (DP-API-04). Ni números (Pydantic los tomaría como instantes Unix)
# ni fechas con hora.
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parse_date(value: Any) -> date:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError("Elige una fecha entre el 01/01/2000 y hoy.")
    return date.fromisoformat(value)  # rechaza días que no existen (ValueError)


AccountingDate = Annotated[
    date,
    BeforeValidator(_parse_date),
    WithJsonSchema({"type": "string", "format": "date", "examples": ["2026-10-30"]}),
]
_DescriptionText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=DESCRIPTION_MAX),
    AfterValidator(reject_control_characters),
]
_NoteText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=NOTE_MAX),
    AfterValidator(_note_lines),
]
Description = Annotated[_DescriptionText | None, BeforeValidator(_blank_as_none)]
Note = Annotated[_NoteText | None, BeforeValidator(_blank_as_none)]


class TransactionRequest(BaseModel):
    """RF-TRX-01 a 03 y 07 (POST y PUT). Campos por tipo: api-contracts.md §6.3."""

    model_config = ConfigDict(extra="forbid")

    type: TransactionType
    amount: PositiveAmount | None = None
    # Ajuste: saldo real de la cuenta (en tarjetas, la deuda real); puede ser negativo.
    target_balance: Amount | None = None
    date: AccountingDate
    account_id: uuid.UUID
    destination_account_id: uuid.UUID | None = None
    category: Category | None = None
    description: Description = None
    note: Note = None


# --- Respuestas (api-contracts.md §6.2 y §6.4) ---------------------------------------------


class TransactionResponse(BaseModel):
    id: uuid.UUID
    type: TransactionType
    # Positivo; en ajustes, la diferencia firmada.
    amount: ApiAmount
    date: date
    account_id: uuid.UUID
    destination_account_id: uuid.UUID | None
    category: Category | None
    description: str | None
    note: str | None
    created_at: datetime
    updated_at: datetime


class SummaryResponse(BaseModel):
    """RN-TRX-05, sobre todos los movimientos que cumplen los filtros."""

    count: int
    income: ApiAmount
    expense: ApiAmount
    # Ahorro neto: puede ser negativo (SUP-TRX-03).
    savings: ApiAmount
    transfers: ApiAmount


class TransactionPageResponse(BaseModel):
    items: list[TransactionResponse]
    total: int
    next_cursor: str | None
    summary: SummaryResponse
