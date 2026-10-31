"""Efecto de un movimiento en el saldo de sus cuentas (FEAT-TRX, RN-TRX-02 a 05).

Funciones puras sobre `Money` (Decimal, nunca float). La tabla de signos es la única
fuente de la regla: BE-03 genera desde ella el `CASE` de SQL que suma los saldos.

| Tipo / papel                 | Cuenta que no es tarjeta | Tarjeta (saldo = deuda) |
|------------------------------|--------------------------|-------------------------|
| `expense`, cuenta            | - monto                  | + monto                 |
| `income`, cuenta             | + monto                  | - monto                 |
| `transfer`, cuenta de origen | - monto                  | + monto                 |
| `transfer`, destino          | + monto                  | - monto                 |
| `adjustment`, cuenta         | + monto firmado          | + monto firmado         |
"""

from enum import StrEnum

from finora.accounts.models import AccountType
from finora.domain.money import Money
from finora.transactions.models import TransactionType


class Role(StrEnum):
    """Papel de la cuenta en el movimiento."""

    ACCOUNT = "account"  # `account_id`: la cuenta del movimiento (origen en transferencias)
    DESTINATION = "destination"  # `destination_account_id`: solo transferencias


class TransferKind(StrEnum):
    """Clasificación de una transferencia para el resumen (RN-TRX-05)."""

    SAVINGS = "savings"  # hacia ahorro o inversión desde otro tipo de cuenta
    SAVINGS_WITHDRAWAL = "savings_withdrawal"  # desde ahorro o inversión hacia otro tipo
    OTHER = "other"  # el resto: entre cuentas líquidas, pagos y avances de tarjeta, etc.


SAVINGS_TYPES = frozenset({AccountType.SAVINGS, AccountType.INVESTMENT})

# Signo del efecto en una cuenta que no es tarjeta, por tipo y papel.
SIGNS: dict[tuple[TransactionType, Role], int] = {
    (TransactionType.EXPENSE, Role.ACCOUNT): -1,
    (TransactionType.INCOME, Role.ACCOUNT): 1,
    (TransactionType.TRANSFER, Role.ACCOUNT): -1,
    (TransactionType.TRANSFER, Role.DESTINATION): 1,
    (TransactionType.ADJUSTMENT, Role.ACCOUNT): 1,
}

# En las tarjetas el saldo es la deuda (RN-ACC-02): el signo se invierte, salvo en el
# ajuste, cuyo monto ya es la diferencia firmada con el saldo de la tarjeta (RN-TRX-04).
CARD_INVERTED = frozenset(t for t in TransactionType if t != TransactionType.ADJUSTMENT)


def sign(type: TransactionType, role: Role, account_type: AccountType) -> int:
    """Signo con el que `amount` se suma al saldo de la cuenta."""
    try:
        base = SIGNS[(type, role)]
    except KeyError:
        raise ValueError(f"Un movimiento {type} no tiene cuenta con papel {role}.") from None
    if account_type == AccountType.CREDIT_CARD and type in CARD_INVERTED:
        return -base
    return base


def effect(type: TransactionType, amount: Money, role: Role, account_type: AccountType) -> Money:
    """Cuánto cambia el saldo de la cuenta por este movimiento (RN-TRX-02 a 04)."""
    return amount * sign(type, role, account_type)


def classify_transfer(origin: AccountType, destination: AccountType) -> TransferKind:
    """Ahorro, retiro de ahorro u otra transferencia (RN-TRX-05, SUP-TRX-03).

    Mover dinero entre dos cuentas de ahorro o inversión no es ahorro nuevo.
    """
    to_savings, from_savings = destination in SAVINGS_TYPES, origin in SAVINGS_TYPES
    if to_savings and not from_savings:
        return TransferKind.SAVINGS
    if from_savings and not to_savings:
        return TransferKind.SAVINGS_WITHDRAWAL
    return TransferKind.OTHER
