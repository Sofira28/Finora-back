"""Entorno de Alembic: toma la URL de FINORA_DATABASE_URL y los metadatos de finora.db."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from finora.config import get_settings
from finora.db import Base, create_db_engine
from finora.db.models import load_all_models

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

load_all_models()
target_metadata = Base.metadata


def _database_url() -> str:
    # Permite que las pruebas inyecten la URL; si no, se usa la configuración por entorno.
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_db_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
