"""Cálculos de saldos, totales y tarjetas (FEAT-ACC, RN-ACC-02 a 06 y 09).

Funciones puras sobre `Money` (Decimal, nunca float). Solo el backend calcula estos
valores; el frontend los muestra tal cual (RNF-ACC-02).

- Saldo disponible: bancarias, billeteras y efectivo activas. No incluye ahorro,
  inversión ni el cupo libre de las tarjetas (RN-ACC-03).
- Patrimonio neto: todas las cuentas activas que no son tarjeta, menos lo que se debe en
  tarjetas; un saldo a favor en una tarjeta suma (RN-ACC-04 y 05).
- Deuda en tarjetas: solo deudas (un saldo a favor no la reduce por debajo de lo que se
  debe en las demás tarjetas).
- En una tarjeta, el saldo es la deuda (RN-ACC-02).
"""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal

from finora.accounts.models import AccountType
from finora.domain.money import Money

CURRENCY = "COP"

AVAILABLE_TYPES = frozenset({AccountType.BANK, AccountType.WALLET, AccountType.CASH})


@dataclass(frozen=True)
class AccountBalance:
    """Lo que necesitan los totales de cada cuenta."""

    type: AccountType
    balance: Money
    archived: bool


@dataclass(frozen=True)
class Totals:
    available_balance: Money
    net_worth: Money
    credit_card_debt: Money


@dataclass(frozen=True)
class CardStatus:
    available_credit: Money
    usage_percent: int
    over_limit: bool


def _zero() -> Money:
    return Money.zero(CURRENCY)


def _sum(amounts: Iterable[Money]) -> Money:
    total = _zero()
    for amount in amounts:
        total += amount
    return total


def current_balance(opening_balance: Money, movements: Money | None = None) -> Money:
    """Saldo actual = saldo inicial + efecto de los movimientos (RN-ACC-02).

    Hasta que exista `transactions` no hay movimientos y el saldo es el inicial.
    """
    return opening_balance + (movements or _zero())


def totals(accounts: Iterable[AccountBalance]) -> Totals:
    """Totales del usuario con sus cuentas activas (RN-ACC-03 a 05 y 09)."""
    active = [a for a in accounts if not a.archived]
    cards = [a.balance for a in active if a.type == AccountType.CREDIT_CARD]
    assets = [a.balance for a in active if a.type != AccountType.CREDIT_CARD]
    return Totals(
        available_balance=_sum(a.balance for a in active if a.type in AVAILABLE_TYPES),
        net_worth=_sum(assets) - _sum(cards),
        credit_card_debt=_sum(debt for debt in cards if debt > _zero()),
    )


def card_status(debt: Money, credit_limit: Money) -> CardStatus:
    """Cupo disponible, porcentaje de uso y cupo superado de una tarjeta (RF-ACC-03).

    - Cupo disponible = cupo - deuda, nunca negativo; un saldo a favor lo aumenta.
    - Uso = deuda ÷ cupo en porcentaje entero, redondeado al par (ROUND_HALF_EVEN);
      0 con saldo a favor y puede pasar de 100 si se superó el cupo (VAL-ACC-10).
    """
    if credit_limit <= _zero():
        raise ValueError("El cupo de una tarjeta debe ser mayor que cero.")
    available = credit_limit - debt
    usage = Decimal(0)
    if debt > _zero():
        usage = (debt.amount * 100 / credit_limit.amount).quantize(
            Decimal(1), rounding=ROUND_HALF_EVEN
        )
    return CardStatus(
        available_credit=available if available > _zero() else _zero(),
        usage_percent=int(usage),
        over_limit=debt > credit_limit,
    )
