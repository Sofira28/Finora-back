"""transactions: tabla de movimientos con RLS (FEAT-TRX, ADR-0005)

Revision ID: 0005_transactions
Revises: 0004_accounts
Create Date: 2026-10-30 23:21:15.659748

Un movimiento por fila, también las transferencias. Las FK compuestas
(cuenta, usuario) → accounts (id, user_id) garantizan que las cuentas son del mismo
usuario que el movimiento; son NO ACTION, así que una cuenta con movimientos no se puede
borrar, mientras que la cascada desde `users` borra cuentas y movimientos en la misma
sentencia. finora_app recibe los permisos por los privilegios por defecto de
0003_app_role.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Identificadores de la revisión, usados por Alembic.
revision: str = "0005_transactions"
down_revision: str | Sequence[str] | None = "0004_accounts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_EXPENSE = (
    "'debts', 'entertainment', 'groceries', 'health', 'housing', 'restaurants', "
    "'subscriptions', 'transport', 'uncategorized', 'utilities'"
)
_INCOME = "'freelance', 'other_income', 'salary', 'uncategorized'"


def upgrade() -> None:
    """Aplica la migración."""
    # Primero la única: es el destino de las FK compuestas.
    op.create_unique_constraint("uq_accounts_id_user_id", "accounts", ["id", "user_id"])
    op.create_table(
        "transactions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("amount", sa.Numeric(precision=19, scale=4), nullable=False),
        sa.Column("occurred_on", sa.Date(), nullable=False),
        sa.Column("account_id", sa.Uuid(), nullable=False),
        sa.Column("destination_account_id", sa.Uuid(), nullable=True),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("search_text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "type IN ('adjustment', 'expense', 'income', 'transfer')",
            name=op.f("ck_transactions_type"),
        ),
        sa.CheckConstraint(
            "CASE WHEN type = 'adjustment' THEN amount <> 0 ELSE amount > 0 END",
            name=op.f("ck_transactions_amount_sign"),
        ),
        sa.CheckConstraint(
            "occurred_on >= DATE '2000-01-01'", name=op.f("ck_transactions_occurred_on_min")
        ),
        sa.CheckConstraint(
            "(type = 'transfer') = (destination_account_id IS NOT NULL)",
            name=op.f("ck_transactions_destination_only_transfer"),
        ),
        sa.CheckConstraint(
            "destination_account_id <> account_id",
            name=op.f("ck_transactions_destination_not_origin"),
        ),
        sa.CheckConstraint(
            "CASE type "
            f"WHEN 'expense' THEN category IS NOT NULL AND category IN ({_EXPENSE}) "
            f"WHEN 'income' THEN category IS NOT NULL AND category IN ({_INCOME}) "
            "ELSE category IS NULL END",
            name=op.f("ck_transactions_category_by_type"),
        ),
        sa.CheckConstraint(
            "description IS NULL OR "
            "(description = btrim(description) AND char_length(description) BETWEEN 1 AND 80)",
            name=op.f("ck_transactions_description_length"),
        ),
        sa.CheckConstraint(
            "note IS NULL OR char_length(note) BETWEEN 1 AND 500",
            name=op.f("ck_transactions_note_length"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_transactions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["account_id", "user_id"],
            ["accounts.id", "accounts.user_id"],
            name="fk_transactions_account_id_user_id_accounts",
        ),
        sa.ForeignKeyConstraint(
            ["destination_account_id", "user_id"],
            ["accounts.id", "accounts.user_id"],
            name="fk_transactions_destination_account_id_user_id_accounts",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_transactions")),
    )
    op.create_index(
        "ix_transactions_user_id_occurred_on",
        "transactions",
        [
            "user_id",
            sa.literal_column("occurred_on DESC"),
            sa.literal_column("created_at DESC"),
            "id",
        ],
    )
    op.create_index(op.f("ix_transactions_account_id"), "transactions", ["account_id"])
    op.create_index(
        op.f("ix_transactions_destination_account_id"), "transactions", ["destination_account_id"]
    )
    op.execute("ALTER TABLE transactions ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY transactions_owner ON transactions "
        "USING (user_id = nullif(current_setting('finora.user_id', true), '')::uuid) "
        "WITH CHECK (user_id = nullif(current_setting('finora.user_id', true), '')::uuid)"
    )


def downgrade() -> None:
    """Revierte la migración."""
    op.execute("DROP POLICY transactions_owner ON transactions")
    op.drop_table("transactions")  # sus índices se van con ella
    op.drop_constraint("uq_accounts_id_user_id", "accounts", type_="unique")
