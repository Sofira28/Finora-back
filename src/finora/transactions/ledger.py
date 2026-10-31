"""Suma del efecto de los movimientos en cada cuenta, en SQL (FEAT-TRX, RN-TRX-06; ADR-0005).

Los saldos no se guardan: se calculan al leer con una consulta agregada por papel (cuenta
y destino). El `CASE` se genera desde la tabla de `effects`, la misma que usan las
funciones puras, así que la regla solo existe en un lugar.
"""

import uuid
from collections.abc import Iterable
from decimal import Decimal

from sqlalchemy import ColumnElement, Select, and_, case, func, select
from sqlalchemy.orm import Session

from finora.accounts.models import Account, AccountType
from finora.domain.money import Money
from finora.transactions.effects import CARD_INVERTED, SIGNS, Role
from finora.transactions.models import Transaction

CURRENCY = "COP"

_ROLE_COLUMN = {
    Role.ACCOUNT: Transaction.account_id,
    Role.DESTINATION: Transaction.destination_account_id,
}


def signed_amount(role: Role) -> ColumnElement[Decimal]:
    """`amount` con el signo de su efecto en la cuenta del papel `role` (unida como `Account`)."""
    base = case(
        *[(Transaction.type == t.value, s) for (t, r), s in SIGNS.items() if r == role],
        else_=0,
    )
    card = case(
        (
            and_(
                Account.type == AccountType.CREDIT_CARD.value,
                Transaction.type.in_([t.value for t in CARD_INVERTED]),
            ),
            -1,
        ),
        else_=1,
    )
    return Transaction.amount * base * card


def _by_role(
    role: Role,
    user_id: uuid.UUID,
    account_ids: Iterable[uuid.UUID] | None,
    exclude_id: uuid.UUID | None,
) -> Select[uuid.UUID | None, Decimal]:
    column = _ROLE_COLUMN[role]
    query = (
        select(column, func.sum(signed_amount(role)))
        .join(Account, Account.id == column)
        .where(Transaction.user_id == user_id, Account.user_id == user_id)
        .group_by(column)
    )
    if account_ids is not None:
        query = query.where(column.in_(list(account_ids)))
    if exclude_id is not None:
        query = query.where(Transaction.id != exclude_id)
    return query


def effects_by_account(
    db: Session,
    user_id: uuid.UUID,
    account_ids: Iterable[uuid.UUID] | None = None,
    *,
    exclude_id: uuid.UUID | None = None,
) -> dict[uuid.UUID, Money]:
    """Efecto total de los movimientos en cada cuenta del usuario.

    Las cuentas sin movimientos no aparecen. `exclude_id` deja fuera un movimiento (el
    ajuste que se está editando, RN-TRX-04).
    """
    ids = None if account_ids is None else list(account_ids)
    totals: dict[uuid.UUID, Money] = {}
    for role in Role:
        for account_id, amount in db.execute(_by_role(role, user_id, ids, exclude_id)):
            if account_id is None:  # el JOIN lo impide; solo para el tipo
                continue
            totals[account_id] = totals.get(account_id, Money.zero(CURRENCY)) + Money(
                amount, CURRENCY
            )
    return totals
