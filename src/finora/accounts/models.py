"""Tabla de cuentas (FEAT-ACC, plan.md §5; specs/database.md §5.2).

Primera tabla financiera: además del filtro por `user_id` en el código, tiene RLS
(política `accounts_owner`, ADR-0004), que se crea en la migración `0004_accounts`.
"""

import uuid
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from finora.db import Base


class AccountType(StrEnum):
    """RN-ACC-01."""

    BANK = "bank"
    WALLET = "wallet"
    CASH = "cash"
    SAVINGS = "savings"
    INVESTMENT = "investment"
    CREDIT_CARD = "credit_card"


_TYPES = ", ".join(f"'{t}'" for t in AccountType)
_CARD_FIELDS = ("credit_limit", "statement_day", "payment_due_day")

# Montos con precisión segura (DP-DB-02).
_MONEY = Numeric(19, 4)


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        CheckConstraint(f"type IN ({_TYPES})", name="type"),
        CheckConstraint(
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 60", name="name_length"
        ),
        CheckConstraint(
            "institution IS NULL OR "
            "(institution = btrim(institution) AND char_length(institution) BETWEEN 1 AND 60)",
            name="institution_length",
        ),
        # Los datos de tarjeta van todos si es tarjeta y ninguno si no lo es.
        CheckConstraint(
            "CASE WHEN type = 'credit_card' "
            f"THEN {' AND '.join(f'{c} IS NOT NULL' for c in _CARD_FIELDS)} "
            f"ELSE {' AND '.join(f'{c} IS NULL' for c in _CARD_FIELDS)} END",
            name="credit_card_fields",
        ),
        CheckConstraint("credit_limit > 0", name="credit_limit_positive"),
        CheckConstraint("statement_day BETWEEN 1 AND 31", name="statement_day_range"),
        CheckConstraint("payment_due_day BETWEEN 1 AND 31", name="payment_due_day_range"),
    )

    # UUIDv7: no secuencial para quien lo ve, ordenado por tiempo para los índices.
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    # El índice único de abajo empieza por user_id y sirve también para buscar por usuario.
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(Text)
    institution: Mapped[str | None] = mapped_column(Text)
    # En tarjetas, la deuda inicial (RN-ACC-02).
    opening_balance: Mapped[Decimal] = mapped_column(_MONEY)
    credit_limit: Mapped[Decimal | None] = mapped_column(_MONEY)
    statement_day: Mapped[int | None] = mapped_column(SmallInteger)
    payment_due_day: Mapped[int | None] = mapped_column(SmallInteger)
    # Vacío = activa (RN-ACC-09). Instantes en UTC (DP-DB-07), puestos por el Clock.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# Nombre único por usuario sin distinguir mayúsculas (VAL-ACC-02).
Index("uq_accounts_user_id_name_lower", Account.user_id, func.lower(Account.name), unique=True)
