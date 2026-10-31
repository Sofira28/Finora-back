"""Modelos de request y response de /accounts (specs/api-contracts.md §5; spec §9 y §10).

Pydantic valida el formato (422 con `loc` y `type`); las reglas que dependen del tipo de
cuenta o de otras cuentas las aplica el servicio, con mensajes es-CO.
"""

import re
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    WithJsonSchema,
)

from finora.accounts.models import AccountType
from finora.validation import reject_control_characters

# SUP-ACC-02: hasta 2 decimales; 15 dígitos enteros caben en NUMERIC(19,4).
AMOUNT_PATTERN = r"^-?\d{1,15}(\.\d{1,2})?$"
_AMOUNT = re.compile(AMOUNT_PATTERN)


def _parse_amount(value: Any) -> Decimal:
    # Solo cadena decimal (DP-API-03): un número JSON llega como float y no es seguro.
    if not isinstance(value, str) or not _AMOUNT.fullmatch(value):
        raise ValueError("Escribe un monto válido, p. ej. 1.250.000.")
    return Decimal(value)


def _positive(value: Decimal) -> Decimal:
    if value <= 0:
        raise ValueError("El cupo debe ser mayor que cero.")
    return value


def _blank_as_none(value: Any) -> Any:
    # Entidad vacía o solo con espacios: la cuenta no tiene entidad.
    return None if isinstance(value, str) and not value.strip() else value


Amount = Annotated[
    Decimal,
    BeforeValidator(_parse_amount),
    WithJsonSchema({"type": "string", "pattern": AMOUNT_PATTERN, "examples": ["1250000.50"]}),
]
PositiveAmount = Annotated[Amount, AfterValidator(_positive)]

# SUP-ACC-01: 1 a 60 caracteres, sin espacios en los extremos ni caracteres de control.
AccountName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=60),
    AfterValidator(reject_control_characters),
]
Institution = Annotated[
    AccountName | None,
    BeforeValidator(_blank_as_none),
]
Day = Annotated[int, Field(strict=True, ge=1, le=31)]

CARD_FIELDS = ("credit_limit", "statement_day", "payment_due_day")


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateAccountRequest(_Request):
    """RF-ACC-01. Los campos de tarjeta son obligatorios en tarjetas y prohibidos en el resto."""

    name: AccountName
    type: AccountType
    institution: Institution = None
    # En tarjetas, la deuda actual (RN-ACC-02).
    opening_balance: Amount
    credit_limit: PositiveAmount | None = None
    statement_day: Day | None = None
    payment_due_day: Day | None = None


class UpdateAccountRequest(_Request):
    """RF-ACC-05/06: solo cambia lo que se envía. El tipo no se puede cambiar (RN-ACC-08).

    `institution: null` borra la entidad; `null` en los demás campos es un error.
    """

    name: AccountName | None = None
    institution: Institution = None
    opening_balance: Amount | None = None
    credit_limit: PositiveAmount | None = None
    statement_day: Day | None = None
    payment_due_day: Day | None = None


# --- Respuestas (api-contracts.md §5.2) ---------------------------------------------------

# Salida: cadena decimal con 2 decimales (`"2800000.00"`), nunca número JSON.
ApiAmount = Annotated[
    str, WithJsonSchema({"type": "string", "pattern": AMOUNT_PATTERN, "examples": ["1250000.00"]})
]


class CreditCardResponse(BaseModel):
    credit_limit: ApiAmount
    available_credit: ApiAmount
    usage_percent: int
    over_limit: bool
    statement_day: int
    payment_due_day: int


class AccountResponse(BaseModel):
    id: uuid.UUID
    name: str
    type: AccountType
    institution: str | None
    opening_balance: ApiAmount
    # Saldo actual; en tarjetas, la deuda (RN-ACC-02).
    balance: ApiAmount
    has_movements: bool
    archived: bool
    credit_card: CreditCardResponse | None
    created_at: datetime


class TotalsResponse(BaseModel):
    available_balance: ApiAmount
    net_worth: ApiAmount
    credit_card_debt: ApiAmount


class AccountListResponse(BaseModel):
    accounts: list[AccountResponse]
    totals: TotalsResponse
