"""Pruebas de integración con PostgreSQL real (T-SETUP-DB-01, RF-SETUP-03/04)."""

from decimal import Decimal

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text

from finora.domain.money import Money


def test_conexion_en_utc(engine: Engine) -> None:
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1")).scalar_one() == 1
        assert conn.execute(text("SHOW timezone")).scalar_one() == "UTC"


def test_numeric_19_4_conserva_precision(engine: Engine) -> None:
    monto = Money("123456789012345.6789", "COP").for_storage()
    with engine.connect() as conn:
        leido = conn.execute(
            text("SELECT CAST(:v AS NUMERIC(19,4))"), {"v": monto.amount}
        ).scalar_one()
    assert isinstance(leido, Decimal)
    assert leido == Decimal("123456789012345.6789")


def test_alembic_aplica_migraciones(migrated_url: str, alembic_cfg: Config) -> None:
    # Idempotente: la BD de la sesión ya está en head.
    command.upgrade(alembic_cfg, "head")
