"""Tabla `transactions`: migración y restricciones (T-TRX-DB-01, plan.md §5, ADR-0005)."""

import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, delete, func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from finora.accounts.models import Account
from finora.auth.models import User
from finora.db.rls import bind_user
from finora.transactions.models import Transaction

TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)


@pytest.fixture
def ana(db_session: Session) -> User:
    user = User(email="ana@correo.com", name="Ana", created_at=TEST_NOW)
    db_session.add(user)
    db_session.flush()
    bind_user(db_session, user.id)
    return user


def _cuenta(user: User, name: str) -> Account:
    return Account(
        user_id=user.id,
        name=name,
        type="bank",
        opening_balance=Decimal(1000),
        created_at=TEST_NOW,
        updated_at=TEST_NOW,
    )


@pytest.fixture
def cuentas(db_session: Session, ana: User) -> tuple[Account, Account]:
    nomina, efectivo = _cuenta(ana, "Nómina"), _cuenta(ana, "Efectivo")
    db_session.add_all([nomina, efectivo])
    db_session.flush()
    return nomina, efectivo


def _movimiento(user: User, cuenta: Account, **cambios: Any) -> Transaction:
    datos: dict[str, Any] = {
        "user_id": user.id,
        "type": "expense",
        "amount": Decimal(120_000),
        "occurred_on": date(2026, 10, 29),
        "account_id": cuenta.id,
        "category": "groceries",
        "description": "Mercado",
        "search_text": "mercado",
        "created_at": TEST_NOW,
        "updated_at": TEST_NOW,
    }
    datos.update(cambios)
    return Transaction(**datos)


def _falla(db_session: Session, movimiento: Transaction) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(movimiento)
        db_session.flush()


# --- Migración ----------------------------------------------------------------------------


def test_finora_app_tiene_permisos_y_rls(engine: Engine) -> None:
    with engine.connect() as conn:
        for permiso in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            consulta = text(
                f"SELECT has_table_privilege('finora_app', 'transactions', '{permiso}')"
            )
            assert conn.execute(consulta).scalar_one() is True
        rls, dueno = conn.execute(
            text(
                "SELECT c.relrowsecurity, pg_get_userbyid(c.relowner) "
                "FROM pg_class c WHERE c.relname = 'transactions'"
            )
        ).one()
        assert rls is True
        assert dueno != "finora_app"
        politicas = conn.execute(
            text("SELECT policyname FROM pg_policies WHERE tablename = 'transactions'")
        ).scalars()
        assert list(politicas) == ["transactions_owner"]


def test_migracion_baja_y_vuelve_a_subir(engine: Engine, alembic_cfg: Config) -> None:
    command.downgrade(alembic_cfg, "0004_accounts")
    try:
        inspector = inspect(engine)
        assert "transactions" not in inspector.get_table_names()
        unicas = {u["name"] for u in inspector.get_unique_constraints("accounts")}
        assert "uq_accounts_id_user_id" not in unicas
    finally:
        command.upgrade(alembic_cfg, "head")
    assert "transactions" in inspect(engine).get_table_names()


# --- Restricciones ------------------------------------------------------------------------


def test_un_movimiento_de_cada_tipo(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    nomina, efectivo = cuentas
    db_session.add_all(
        [
            _movimiento(ana, nomina),
            _movimiento(ana, nomina, type="income", category="salary"),
            _movimiento(
                ana,
                nomina,
                type="transfer",
                destination_account_id=efectivo.id,
                category=None,
                description=None,
            ),
            _movimiento(ana, efectivo, type="adjustment", amount=Decimal(-15_000), category=None),
        ]
    )
    db_session.flush()


def test_conserva_cuatro_decimales(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    movimiento = _movimiento(ana, cuentas[0], amount=Decimal("0.1") + Decimal("0.2"))
    db_session.add(movimiento)
    db_session.flush()
    db_session.expire(movimiento)
    assert movimiento.amount == Decimal("0.3000")


@pytest.mark.parametrize(
    "cambios",
    [
        {"type": "gasto"},
        {"amount": Decimal(0)},
        {"amount": Decimal(-1)},
        {"type": "adjustment", "category": None, "amount": Decimal(0)},
        {"occurred_on": date(1999, 12, 31)},
        # Categoría: obligatoria y del tipo en gastos e ingresos; nunca en los demás.
        {"category": None},
        {"category": "salary"},
        {"category": "otra"},
        {"type": "income", "category": None},
        {"type": "income", "category": "groceries"},
        {"type": "adjustment", "amount": Decimal(1)},
        # Textos.
        {"description": ""},
        {"description": " Mercado"},
        {"description": "a" * 81},
        {"note": ""},
        {"note": "n" * 501},
    ],
)
def test_restricciones(
    db_session: Session, ana: User, cuentas: tuple[Account, Account], cambios: dict[str, Any]
) -> None:
    _falla(db_session, _movimiento(ana, cuentas[0], **cambios))


def test_sin_categoria_en_gastos_e_ingresos(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    db_session.add_all(
        [
            _movimiento(ana, cuentas[0], category="uncategorized"),
            _movimiento(ana, cuentas[0], type="income", category="uncategorized"),
        ]
    )
    db_session.flush()


def test_destino_solo_en_transferencias_y_distinto_del_origen(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    nomina, efectivo = cuentas
    transferencia = {"type": "transfer", "category": None}
    _falla(db_session, _movimiento(ana, nomina, **transferencia))  # sin destino
    _falla(db_session, _movimiento(ana, nomina, **transferencia, destination_account_id=nomina.id))
    _falla(db_session, _movimiento(ana, nomina, destination_account_id=efectivo.id))  # gasto


def test_cuenta_inexistente(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    otra = _cuenta(ana, "Fantasma")  # nunca guardada
    otra.id = uuid.uuid7()
    _falla(db_session, _movimiento(ana, otra))


def test_no_se_puede_borrar_una_cuenta_con_movimientos(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    """RN-TRX-10: también como destino de una transferencia."""
    nomina, efectivo = cuentas
    db_session.add(
        _movimiento(
            ana,
            nomina,
            type="transfer",
            destination_account_id=efectivo.id,
            category=None,
        )
    )
    db_session.flush()
    for cuenta in cuentas:
        with pytest.raises(IntegrityError), db_session.begin_nested():
            db_session.execute(delete(Account).where(Account.id == cuenta.id))


def test_borrar_el_ultimo_movimiento_permite_borrar_la_cuenta(
    db_session: Session, ana: User, cuentas: tuple[Account, Account]
) -> None:
    nomina, _ = cuentas
    movimiento = _movimiento(ana, nomina)
    db_session.add(movimiento)
    db_session.flush()
    db_session.delete(movimiento)
    db_session.flush()
    db_session.execute(delete(Account).where(Account.id == nomina.id))
    assert db_session.scalar(select(func.count()).select_from(Account)) == 1
