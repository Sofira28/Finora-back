"""Tabla de movimientos (FEAT-TRX, plan.md §5; specs/database.md §5.3; ADR-0005).

Un movimiento es una fila, también las transferencias (cuenta de origen y de destino).
Los saldos no se guardan: se calculan al leer. Además del filtro por `user_id` en el
código, tiene RLS (política `transactions_owner`, migración `0005_transactions`).
"""

import uuid
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Numeric,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from finora.db import Base


class TransactionType(StrEnum):
    """RN-TRX-01."""

    EXPENSE = "expense"
    INCOME = "income"
    TRANSFER = "transfer"
    ADJUSTMENT = "adjustment"


class Category(StrEnum):
    """Catálogo fijo inicial (RN-TRX-07, CD-10); `budgets` lo reemplazará."""

    HOUSING = "housing"
    GROCERIES = "groceries"
    TRANSPORT = "transport"
    RESTAURANTS = "restaurants"
    UTILITIES = "utilities"
    HEALTH = "health"
    ENTERTAINMENT = "entertainment"
    SUBSCRIPTIONS = "subscriptions"
    DEBTS = "debts"
    SALARY = "salary"
    FREELANCE = "freelance"
    OTHER_INCOME = "other_income"
    UNCATEGORIZED = "uncategorized"


# Categorías permitidas en cada tipo; "sin categoría" sirve para ambos.
EXPENSE_CATEGORIES = frozenset(
    {
        Category.HOUSING,
        Category.GROCERIES,
        Category.TRANSPORT,
        Category.RESTAURANTS,
        Category.UTILITIES,
        Category.HEALTH,
        Category.ENTERTAINMENT,
        Category.SUBSCRIPTIONS,
        Category.DEBTS,
        Category.UNCATEGORIZED,
    }
)
INCOME_CATEGORIES = frozenset(
    {Category.SALARY, Category.FREELANCE, Category.OTHER_INCOME, Category.UNCATEGORIZED}
)

# Fecha mínima de un movimiento (RN-TRX-09, SUP-TRX-02). La máxima (hoy) la valida el
# servicio, porque depende del reloj.
MIN_DATE = date(2000, 1, 1)


def _in(values: frozenset[Category] | type[StrEnum]) -> str:
    return ", ".join(f"'{v}'" for v in sorted(values))


# Montos con precisión segura (DP-DB-02).
_MONEY = Numeric(19, 4)


class Transaction(Base):
    __tablename__ = "transactions"
    __table_args__ = (
        CheckConstraint(f"type IN ({_in(TransactionType)})", name="type"),
        # Positivo; el ajuste guarda la diferencia firmada (RN-TRX-04).
        CheckConstraint(
            "CASE WHEN type = 'adjustment' THEN amount <> 0 ELSE amount > 0 END",
            name="amount_sign",
        ),
        CheckConstraint(f"occurred_on >= DATE '{MIN_DATE.isoformat()}'", name="occurred_on_min"),
        # Destino solo en transferencias, y distinto del origen (RN-TRX-11).
        CheckConstraint(
            "(type = 'transfer') = (destination_account_id IS NOT NULL)",
            name="destination_only_transfer",
        ),
        CheckConstraint("destination_account_id <> account_id", name="destination_not_origin"),
        # Categoría solo en gastos e ingresos, y del tipo correspondiente (RN-TRX-07).
        # `IS NOT NULL` explícito: `NULL IN (...)` es NULL, y un CHECK con NULL pasa.
        CheckConstraint(
            "CASE type "
            f"WHEN 'expense' THEN category IS NOT NULL AND category IN ({_in(EXPENSE_CATEGORIES)}) "
            f"WHEN 'income' THEN category IS NOT NULL AND category IN ({_in(INCOME_CATEGORIES)}) "
            "ELSE category IS NULL END",
            name="category_by_type",
        ),
        CheckConstraint(
            "description IS NULL OR "
            "(description = btrim(description) AND char_length(description) BETWEEN 1 AND 80)",
            name="description_length",
        ),
        CheckConstraint("note IS NULL OR char_length(note) BETWEEN 1 AND 500", name="note_length"),
        # FK compuestas: las cuentas del movimiento son del mismo usuario. NO ACTION impide
        # borrar una cuenta con movimientos (RN-TRX-10); la cascada desde `users` borra
        # cuentas y movimientos en la misma sentencia.
        ForeignKeyConstraint(
            ["account_id", "user_id"],
            ["accounts.id", "accounts.user_id"],
            name="fk_transactions_account_id_user_id_accounts",
        ),
        ForeignKeyConstraint(
            ["destination_account_id", "user_id"],
            ["accounts.id", "accounts.user_id"],
            name="fk_transactions_destination_account_id_user_id_accounts",
        ),
    )

    # UUIDv7: no secuencial para quien lo ve, ordenado por tiempo para los índices.
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(Text)
    amount: Mapped[Decimal] = mapped_column(_MONEY)
    # Fecha contable, sin hora (DP-DB-07).
    occurred_on: Mapped[date] = mapped_column(Date)
    # En transferencias, la cuenta de origen.
    account_id: Mapped[uuid.UUID] = mapped_column(index=True)
    destination_account_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    category: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    # Descripción y nota en minúsculas y sin tildes, para buscar (SUP-TRX-04).
    search_text: Mapped[str] = mapped_column(Text)
    # Instantes en UTC (DP-DB-07), puestos por el Clock.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# Listado por usuario, del más reciente al más antiguo, con desempate estable. Todas las
# columnas en el mismo sentido: el cursor avanza con una comparación de tuplas y el índice
# sirve leído hacia adelante (`date_desc`) o hacia atrás (`date_asc`).
Index(
    "ix_transactions_user_id_occurred_on",
    Transaction.user_id,
    Transaction.occurred_on.desc(),
    Transaction.created_at.desc(),
    Transaction.id.desc(),
)
