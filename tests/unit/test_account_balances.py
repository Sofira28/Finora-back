"""Saldos, totales y tarjetas (T-ACC-BE-01): RN-ACC-02 a 05 y 09; CA-ACC-01, 02, 03 y 07."""

from decimal import Decimal

import pytest

from finora.accounts.balances import (
    AccountBalance,
    Totals,
    card_status,
    current_balance,
    totals,
)
from finora.accounts.models import AccountType
from finora.domain.money import Money

BANK, WALLET, CASH = AccountType.BANK, AccountType.WALLET, AccountType.CASH
SAVINGS, INVESTMENT, CARD = AccountType.SAVINGS, AccountType.INVESTMENT, AccountType.CREDIT_CARD


def cop(amount: str | int) -> Money:
    return Money(amount, "COP")


def cuenta(tipo: AccountType, saldo: str | int, *, archivada: bool = False) -> AccountBalance:
    return AccountBalance(type=tipo, balance=cop(saldo), archived=archivada)


def montos(t: Totals) -> tuple[Decimal, Decimal, Decimal]:
    return (t.available_balance.amount, t.net_worth.amount, t.credit_card_debt.amount)


# --- Saldo actual (RN-ACC-02) -------------------------------------------------------------


def test_sin_movimientos_el_saldo_es_el_inicial() -> None:
    assert current_balance(cop(2_800_000)) == cop(2_800_000)


def test_los_movimientos_se_suman_al_inicial() -> None:
    assert current_balance(cop(820_000), cop(-300_000)) == cop(520_000)


# --- Totales ------------------------------------------------------------------------------


def test_ca_acc_01_totales() -> None:
    resultado = totals(
        [
            cuenta(BANK, 2_800_000),
            cuenta(CASH, 90_000),
            cuenta(INVESTMENT, 12_000_000),
            cuenta(CARD, 820_000),
        ]
    )
    assert montos(resultado) == (Decimal(2_890_000), Decimal(14_070_000), Decimal(820_000))


def test_saldo_disponible_solo_bancarias_billeteras_y_efectivo() -> None:
    resultado = totals(
        [
            cuenta(BANK, 1_000),
            cuenta(WALLET, 200),
            cuenta(CASH, 30),
            cuenta(SAVINGS, 4_000_000),
            cuenta(INVESTMENT, 5_000_000),
        ]
    )
    assert resultado.available_balance == cop(1_230)
    assert resultado.net_worth == cop(9_001_230)


def test_ca_acc_03_el_cupo_no_es_saldo_disponible() -> None:
    resultado = totals([cuenta(CARD, 0)])  # cupo de $ 6.000.000 sin usar
    assert montos(resultado) == (Decimal(0), Decimal(0), Decimal(0))


def test_sin_cuentas_todo_en_cero() -> None:
    assert montos(totals([])) == (Decimal(0), Decimal(0), Decimal(0))


def test_las_archivadas_no_cuentan() -> None:
    resultado = totals(
        [
            cuenta(BANK, 1_000),
            cuenta(WALLET, 250_000, archivada=True),
            cuenta(SAVINGS, 9_000, archivada=True),
            cuenta(CARD, 500, archivada=True),
        ]
    )
    assert montos(resultado) == (Decimal(1_000), Decimal(1_000), Decimal(0))


def test_saldos_negativos_restan() -> None:
    resultado = totals([cuenta(BANK, -150_000), cuenta(CASH, 50_000)])  # sobregiro
    assert resultado.available_balance == cop(-100_000)
    assert resultado.net_worth == cop(-100_000)


def test_saldo_a_favor_en_tarjeta_suma_al_patrimonio_y_no_a_la_deuda() -> None:
    resultado = totals([cuenta(BANK, 1_000), cuenta(CARD, 300), cuenta(CARD, -50)])
    assert resultado.credit_card_debt == cop(300)
    assert resultado.net_worth == cop(750)  # 1.000 - 300 + 50
    assert resultado.available_balance == cop(1_000)


def test_ca_acc_07_suma_exacta_de_decimales() -> None:
    resultado = totals([cuenta(BANK, "0.10"), cuenta(WALLET, "0.20")])
    assert resultado.available_balance.amount == Decimal("0.30")
    assert resultado.net_worth.amount == Decimal("0.30")


def test_montos_grandes_sin_perder_precision() -> None:
    resultado = totals([cuenta(INVESTMENT, "999999999999999.9999"), cuenta(CARD, "0.0001")])
    assert resultado.net_worth.amount == Decimal("999999999999999.9998")


# --- Tarjetas (RF-ACC-03) -----------------------------------------------------------------


def test_ca_acc_02_estado_de_la_tarjeta() -> None:
    estado = card_status(cop(820_000), cop(6_000_000))  # 13,67 %
    assert estado.available_credit == cop(5_180_000)
    assert estado.usage_percent == 14
    assert estado.over_limit is False


@pytest.mark.parametrize(
    ("deuda", "porcentaje"),
    [(25, 12), (27, 14), (35, 18), ("0.5", 0), (1, 0), (3, 2)],  # cupo 200
)
def test_uso_redondeado_al_par(deuda: int | str, porcentaje: int) -> None:
    assert card_status(cop(deuda), cop(200)).usage_percent == porcentaje


def test_sin_deuda() -> None:
    estado = card_status(cop(0), cop(6_000_000))
    assert (estado.available_credit, estado.usage_percent, estado.over_limit) == (
        cop(6_000_000),
        0,
        False,
    )


def test_deuda_igual_al_cupo_no_lo_supera() -> None:
    estado = card_status(cop(6_000_000), cop(6_000_000))
    assert (estado.available_credit, estado.usage_percent, estado.over_limit) == (
        cop(0),
        100,
        False,
    )


def test_val_acc_10_deuda_sobre_el_cupo() -> None:
    estado = card_status(cop(7_000_000), cop(6_000_000))
    assert estado.available_credit == cop(0)
    assert estado.usage_percent == 117
    assert estado.over_limit is True


def test_saldo_a_favor_aumenta_el_cupo_disponible() -> None:
    estado = card_status(cop(-50_000), cop(6_000_000))
    assert estado.available_credit == cop(6_050_000)
    assert estado.usage_percent == 0
    assert estado.over_limit is False


@pytest.mark.parametrize("cupo", [0, -1])
def test_cupo_debe_ser_positivo(cupo: int) -> None:
    with pytest.raises(ValueError, match="cupo"):
        card_status(cop(0), cop(cupo))
