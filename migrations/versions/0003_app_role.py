"""rls: rol de aplicación finora_app sin privilegios (ADR-0004)

Revision ID: 0003_app_role
Revises: 0002_google
Create Date: 2026-10-30 18:00:00.000000

El rol es global del servidor y lo comparten varias bases de datos (desarrollo, E2E,
pruebas): se crea solo si no existe y el downgrade le quita los permisos de esta base de
datos, pero no lo borra.
"""

from collections.abc import Sequence

from alembic import op

# Identificadores de la revisión, usados por Alembic.
revision: str = "0003_app_role"
down_revision: str | Sequence[str] | None = "0002_google"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Aplica la migración."""
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'finora_app') THEN
                CREATE ROLE finora_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
            END IF;
        END
        $$
        """
    )
    # Quien migra (dueño de las tablas) debe poder hacer SET ROLE al rol de aplicación.
    op.execute("GRANT finora_app TO CURRENT_USER WITH SET TRUE")
    op.execute("GRANT USAGE ON SCHEMA public TO finora_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO finora_app")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO finora_app")
    # La tabla de Alembic es solo del dueño.
    op.execute("REVOKE ALL ON alembic_version FROM finora_app")
    # Tablas y secuencias que creen las migraciones siguientes.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO finora_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO finora_app"
    )


def downgrade() -> None:
    """Revierte la migración."""
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM finora_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE USAGE, SELECT ON SEQUENCES FROM finora_app"
    )
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM finora_app")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM finora_app")
    op.execute("REVOKE USAGE ON SCHEMA public FROM finora_app")
