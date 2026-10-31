"""Efecto en saldos y clasificación de transferencias (T-TRX-BE-01).

RN-TRX-02 a 05; CA-TRX-01 a 06 y 12 calculados con los totales de `accounts`.
"""

from decimal import Decimal

import pytest

from finora.accounts.balances import AccountBalance, card_status, totals
from finora.accounts.models import AccountType
from finora.domain.money import Money
from finora.transactions.effects import (
    SIGNS,
    Role,
    TransferKind,
    classify_transfer,
    effect,
    sign,
)
from finora.transactions.models import TransactionType

BANK, WALLET, CASH = AccountType.BANK, AccountType.WALLET, AccountType.CASH
SAVINGS, INVESTMENT, CARD = AccountType.SAVINGS, AccountType.INVESTMENT, AccountType.CREDIT_CARD
EXPENSE, INCOME = TransactionType.EXPENSE, TransactionType.INCOME
TRANSFER, ADJUSTMENT = TransactionType.TRANSFER, TransactionType.ADJUSTMENT
ACCOUNT, DESTINATION = Role.ACCOUNT, Role.DESTINATION
NO_CARD = [BANK, WALLET, CASH, SAVINGS, INVESTMENT]


def cop(amount: str | int) -> Money:
    return Money(amount, "COP")


# --- Tabla de efectos (plan.md §2) ---------------------------------------------------------


@pytest.mark.parametrize("tipo_cuenta", NO_CARD)
@pytest.mark.parametrize(
    ("tipo", "papel", "esperado"),
    [
        (EXPENSE, ACCOUNT, -100),
        (INCOME, ACCOUNT, 100),
        (TRANSFER, ACCOUNT, -100),
        (TRANSFER, DESTINATION, 100),
        (ADJUSTMENT, ACCOUNT, 100),
    ],
)
def test_cuentas_que_no_son_tarjeta(
    tipo_cuenta: AccountType, tipo: TransactionType, papel: Role, esperado: int
) -> None:
    assert effect(tipo, cop(100), papel, tipo_cuenta) == cop(esperado)


@pytest.mark.parametrize(
    ("tipo", "papel", "esperado"),
    [
        (EXPENSE, ACCOUNT, 100),  # compra: la deuda sube
        (INCOME, ACCOUNT, -100),  # devolución: la deuda baja
        (TRANSFER, ACCOUNT, 100),  # avance: la deuda sube
        (TRANSFER, DESTINATION, -100),  # pago de la tarjeta: la deuda baja
        (ADJUSTMENT, ACCOUNT, 100),  # el ajuste ya viene firmado
    ],
)
def test_tarjetas(tipo: TransactionType, papel: Role, esperado: int) -> None:
    assert effect(tipo, cop(100), papel, CARD) == cop(esperado)


@pytest.mark.parametrize("tipo_cuenta", [BANK, CARD])
def test_ajuste_negativo(tipo_cuenta: AccountType) -> None:
    assert effect(ADJUSTMENT, cop(-15_000), ACCOUNT, tipo_cuenta) == cop(-15_000)


@pytest.mark.parametrize("tipo", [EXPENSE, INCOME, ADJUSTMENT])
def test_solo_las_transferencias_tienen_destino(tipo: TransactionType) -> None:
    with pytest.raises(ValueError, match="papel"):
        sign(tipo, DESTINATION, BANK)


def test_la_tabla_cubre_todos_los_tipos() -> None:
    assert {tipo for tipo, _ in SIGNS} == set(TransactionType)


@pytest.mark.parametrize("tipo_cuenta", NO_CARD)
def test_una_transferencia_no_crea_ni_destruye_valor(tipo_cuenta: AccountType) -> None:
    """Entre cuentas que no son tarjeta, lo que sale de una entra en la otra."""
    salida = effect(TRANSFER, cop(500), ACCOUNT, tipo_cuenta)
    entrada = effect(TRANSFER, cop(500), DESTINATION, BANK)
    assert salida + entrada == cop(0)


# --- Clasificación de transferencias (RN-TRX-05) -------------------------------------------


@pytest.mark.parametrize(
    ("origen", "destino", "clase"),
    [
        (BANK, SAVINGS, TransferKind.SAVINGS),
        (CASH, INVESTMENT, TransferKind.SAVINGS),
        (CARD, SAVINGS, TransferKind.SAVINGS),  # avance hacia ahorro
        (SAVINGS, BANK, TransferKind.SAVINGS_WITHDRAWAL),
        (INVESTMENT, CARD, TransferKind.SAVINGS_WITHDRAWAL),  # pagar la tarjeta con ahorros
        (SAVINGS, INVESTMENT, TransferKind.OTHER),  # sigue siendo ahorro
        (BANK, CASH, TransferKind.OTHER),
        (BANK, CARD, TransferKind.OTHER),  # pago de tarjeta
        (CARD, CARD, TransferKind.OTHER),  # compra de cartera
    ],
)
def test_clasificacion(origen: AccountType, destino: AccountType, clase: TransferKind) -> None:
    assert classify_transfer(origen, destino) is clase


# --- Criterios de aceptación con los totales de `accounts` ---------------------------------

# CA-ACC-01: Nómina, Efectivo, CDT y Tarjeta Órbita.
INICIALES = {
    "Nómina": (BANK, 2_800_000),
    "Efectivo": (CASH, 90_000),
    "CDT": (INVESTMENT, 12_000_000),
    "Órbita": (CARD, 820_000),
}

Movimiento = tuple[TransactionType, int, str, str | None]


def saldos(*movimientos: Movimiento) -> dict[str, Money]:
    resultado = {nombre: cop(saldo) for nombre, (_, saldo) in INICIALES.items()}
    for tipo, monto, cuenta, destino in movimientos:
        resultado[cuenta] += effect(tipo, cop(monto), ACCOUNT, INICIALES[cuenta][0])
        if destino:
            resultado[destino] += effect(tipo, cop(monto), DESTINATION, INICIALES[destino][0])
    return resultado


def disponible_y_patrimonio(s: dict[str, Money]) -> tuple[Money, Money]:
    t = totals(AccountBalance(INICIALES[n][0], saldo, archived=False) for n, saldo in s.items())
    return t.available_balance, t.net_worth


def test_contexto_comun() -> None:
    assert disponible_y_patrimonio(saldos()) == (cop(2_890_000), cop(14_070_000))


def test_ca_trx_01_gasto() -> None:
    s = saldos((EXPENSE, 120_000, "Nómina", None))
    assert s["Nómina"] == cop(2_680_000)
    assert disponible_y_patrimonio(s) == (cop(2_770_000), cop(13_950_000))


def test_ca_trx_02_transferencia_entre_cuentas_liquidas() -> None:
    s = saldos((TRANSFER, 200_000, "Nómina", "Efectivo"))
    assert (s["Nómina"], s["Efectivo"]) == (cop(2_600_000), cop(290_000))
    assert disponible_y_patrimonio(s) == (cop(2_890_000), cop(14_070_000))


def test_ca_trx_03_ahorro() -> None:
    s = saldos((TRANSFER, 500_000, "Nómina", "CDT"))
    assert disponible_y_patrimonio(s) == (cop(2_390_000), cop(14_070_000))
    assert classify_transfer(BANK, INVESTMENT) is TransferKind.SAVINGS


def test_ca_trx_04_compra_con_tarjeta() -> None:
    s = saldos((EXPENSE, 300_000, "Órbita", None))
    assert s["Órbita"] == cop(1_120_000)
    assert card_status(s["Órbita"], cop(6_000_000)).available_credit == cop(4_880_000)
    assert disponible_y_patrimonio(s) == (cop(2_890_000), cop(13_770_000))


def test_ca_trx_05_pago_de_tarjeta() -> None:
    s = saldos((TRANSFER, 820_000, "Nómina", "Órbita"))
    assert s["Órbita"] == cop(0)
    assert disponible_y_patrimonio(s) == (cop(2_070_000), cop(14_070_000))


def test_ca_trx_06_ajuste() -> None:
    s = saldos((ADJUSTMENT, -15_000, "Efectivo", None))
    assert s["Efectivo"] == cop(75_000)
    assert disponible_y_patrimonio(s)[1] == cop(14_055_000)


def test_pago_mayor_que_la_deuda_deja_saldo_a_favor() -> None:
    s = saldos((TRANSFER, 1_000_000, "Nómina", "Órbita"))
    assert s["Órbita"] == cop(-180_000)


def test_ca_trx_12_precision() -> None:
    nomina = cop(2_800_000)
    for monto in ("0.10", "0.20"):
        nomina += effect(INCOME, cop(monto), ACCOUNT, BANK)
    assert nomina.amount == Decimal("2800000.30")
