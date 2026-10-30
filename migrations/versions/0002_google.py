"""auth: consentimiento en el flujo de Google y reautenticación con Google pendiente de MFA

Revision ID: 0002_google
Revises: 0001_auth
Create Date: 2026-10-30 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# Identificadores de la revisión, usados por Alembic.
revision: str = "0002_google"
down_revision: str | Sequence[str] | None = "0001_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Aplica la migración."""
    op.add_column("oauth_flows", sa.Column("privacy_policy_version", sa.Text(), nullable=True))
    op.add_column(
        "auth_sessions", sa.Column("google_reauth_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    """Revierte la migración."""
    op.drop_column("auth_sessions", "google_reauth_at")
    op.drop_column("oauth_flows", "privacy_policy_version")
