"""accounts: tabla de cuentas y tarjetas con RLS (FEAT-ACC, ADR-0004)

Revision ID: 0004_accounts
Revises: 0003_app_role
Create Date: 2026-10-30 21:06:46.094279

finora_app recibe los permisos sobre la tabla por los privilegios por defecto de
0003_app_role. La política deja ver y escribir solo las filas del usuario fijado en
`finora.user_id`; sin usuario, ninguna.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Identificadores de la revisión, usados por Alembic.
revision: str = "0004_accounts"
down_revision: str | Sequence[str] | None = "0003_app_role"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Aplica la migración."""
    op.create_table(
        "accounts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("institution", sa.Text(), nullable=True),
        sa.Column("opening_balance", sa.Numeric(precision=19, scale=4), nullable=False),
        sa.Column("credit_limit", sa.Numeric(precision=19, scale=4), nullable=True),
        sa.Column("statement_day", sa.SmallInteger(), nullable=True),
        sa.Column("payment_due_day", sa.SmallInteger(), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "CASE WHEN type = 'credit_card' "
            "THEN credit_limit IS NOT NULL AND statement_day IS NOT NULL "
            "AND payment_due_day IS NOT NULL "
            "ELSE credit_limit IS NULL AND statement_day IS NULL AND payment_due_day IS NULL END",
            name=op.f("ck_accounts_credit_card_fields"),
        ),
        sa.CheckConstraint(
            "type IN ('bank', 'wallet', 'cash', 'savings', 'investment', 'credit_card')",
            name=op.f("ck_accounts_type"),
        ),
        sa.CheckConstraint("credit_limit > 0", name=op.f("ck_accounts_credit_limit_positive")),
        sa.CheckConstraint(
            "institution IS NULL OR "
            "(institution = btrim(institution) AND char_length(institution) BETWEEN 1 AND 60)",
            name=op.f("ck_accounts_institution_length"),
        ),
        sa.CheckConstraint(
            "name = btrim(name) AND char_length(name) BETWEEN 1 AND 60",
            name=op.f("ck_accounts_name_length"),
        ),
        sa.CheckConstraint(
            "payment_due_day BETWEEN 1 AND 31", name=op.f("ck_accounts_payment_due_day_range")
        ),
        sa.CheckConstraint(
            "statement_day BETWEEN 1 AND 31", name=op.f("ck_accounts_statement_day_range")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_accounts_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_accounts")),
    )
    op.create_index(
        "uq_accounts_user_id_name_lower",
        "accounts",
        ["user_id", sa.literal_column("lower(name)")],
        unique=True,
    )
    op.execute("ALTER TABLE accounts ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY accounts_owner ON accounts "
        "USING (user_id = nullif(current_setting('finora.user_id', true), '')::uuid) "
        "WITH CHECK (user_id = nullif(current_setting('finora.user_id', true), '')::uuid)"
    )


def downgrade() -> None:
    """Revierte la migración."""
    op.execute("DROP POLICY accounts_owner ON accounts")
    op.drop_index("uq_accounts_user_id_name_lower", table_name="accounts")
    op.drop_table("accounts")
