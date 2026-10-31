"""Tabla `accounts`: migración y restricciones (T-ACC-DB-02, plan.md §5)."""

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from finora.accounts.models import Account
from finora.auth.models import User
from finora.db.rls import bind_user

TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)
TARJETA = {"credit_limit": Decimal(6_000_000), "statement_day": 28, "payment_due_day": 18}


@pytest.fixture
def ana(db_session: Session) -> User:
    user = User(email="ana@correo.com", name="Ana", created_at=TEST_NOW)
    db_session.add(user)
    db_session.flush()
    bind_user(db_session, user.id)
    return user


def _cuenta(user: User, **cambios: Any) -> Account:
    datos: dict[str, Any] = {
        "user_id": user.id,
        "name": "Nómina",
        "type": "bank",
        "opening_balance": Decimal(2_800_000),
        "created_at": TEST_NOW,
        "updated_at": TEST_NOW,
    }
    datos.update(cambios)
    return Account(**datos)


def _falla(db_session: Session, cuenta: Account) -> None:
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(cuenta)
        db_session.flush()


# --- Migración ----------------------------------------------------------------------------


def test_finora_app_tiene_permisos_por_defecto_sobre_la_tabla(engine: Engine) -> None:
    with engine.connect() as conn:
        for permiso in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            consulta = text(f"SELECT has_table_privilege('finora_app', 'accounts', '{permiso}')")
            assert conn.execute(consulta).scalar_one() is True
        rls, dueno = conn.execute(
            text(
                "SELECT c.relrowsecurity, pg_get_userbyid(c.relowner) "
                "FROM pg_class c WHERE c.relname = 'accounts'"
            )
        ).one()
        assert rls is True
        assert dueno != "finora_app"
        politica = conn.execute(
            text("SELECT count(*) FROM pg_policies WHERE tablename = 'accounts'")
        ).scalar_one()
        assert politica == 1


def test_migracion_baja_y_vuelve_a_subir(engine: Engine, alembic_cfg: Config) -> None:
    command.downgrade(alembic_cfg, "0003_app_role")
    try:
        assert "accounts" not in inspect(engine).get_table_names()
    finally:
        command.upgrade(alembic_cfg, "head")
    assert "accounts" in inspect(engine).get_table_names()


# --- Restricciones ------------------------------------------------------------------------


def test_cuenta_y_tarjeta_validas(db_session: Session, ana: User) -> None:
    db_session.add_all(
        [
            _cuenta(ana),
            _cuenta(ana, name="Órbita", type="credit_card", institution="Banco Andino", **TARJETA),
        ]
    )
    db_session.flush()
    guardada = db_session.scalars(text("SELECT opening_balance FROM accounts LIMIT 1")).one()
    assert guardada == Decimal("2800000.0000")


def test_conserva_cuatro_decimales(db_session: Session, ana: User) -> None:
    cuenta = _cuenta(ana, opening_balance=Decimal("0.1") + Decimal("0.2"))
    db_session.add(cuenta)
    db_session.flush()
    db_session.expire(cuenta)
    assert cuenta.opening_balance == Decimal("0.3000")


@pytest.mark.parametrize("tipo", ["corriente", "", "BANK"])
def test_tipo_invalido(db_session: Session, ana: User, tipo: str) -> None:
    _falla(db_session, _cuenta(ana, type=tipo))


@pytest.mark.parametrize("nombre", ["", " Nómina", "Nómina ", "a" * 61])
def test_nombre_invalido(db_session: Session, ana: User, nombre: str) -> None:
    _falla(db_session, _cuenta(ana, name=nombre))


@pytest.mark.parametrize("entidad", ["", " Banco", "b" * 61])
def test_entidad_invalida(db_session: Session, ana: User, entidad: str) -> None:
    _falla(db_session, _cuenta(ana, institution=entidad))


def test_nombre_unico_sin_distinguir_mayusculas(db_session: Session, ana: User) -> None:
    db_session.add(_cuenta(ana, name="Nómina"))
    db_session.flush()
    _falla(db_session, _cuenta(ana, name="NÓMINA"))


@pytest.mark.parametrize(
    "cambios",
    [
        {"type": "credit_card"},  # tarjeta sin sus datos
        {"type": "credit_card", **TARJETA, "statement_day": None},
        {"type": "bank", **TARJETA},  # datos de tarjeta en otra cuenta
        {"type": "cash", "credit_limit": Decimal(1)},
        {"type": "credit_card", **TARJETA, "credit_limit": Decimal(0)},
        {"type": "credit_card", **TARJETA, "statement_day": 0},
        {"type": "credit_card", **TARJETA, "payment_due_day": 32},
    ],
)
def test_datos_de_tarjeta(db_session: Session, ana: User, cambios: dict[str, Any]) -> None:
    _falla(db_session, _cuenta(ana, **cambios))


@pytest.mark.parametrize("saldo", [Decimal(0), Decimal(-150_000)])
def test_saldos_cero_y_negativos_permitidos(db_session: Session, ana: User, saldo: Decimal) -> None:
    db_session.add(_cuenta(ana, opening_balance=saldo))  # SUP-ACC-05
    db_session.flush()
