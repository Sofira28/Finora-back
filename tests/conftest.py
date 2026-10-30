"""Fixtures compartidas (T-AUTH-DB-01).

- PostgreSQL real (Testcontainers), un contenedor por sesión de pytest con las migraciones
  aplicadas.
- db_session: cada prueba corre dentro de una transacción que se revierte al final; los
  commit de la aplicación solo liberan savepoints.
- client: la app con BD, reloj, correo y configuración de prueba.

Las pruebas que usan la BD reciben el marcador `db` automáticamente.
"""

import base64
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from testcontainers.community.postgres import PostgresContainer

from finora.clock import FrozenClock, get_clock
from finora.config import Settings, get_settings
from finora.db import create_db_engine, get_db_session
from finora.email import InMemoryEmailSender, get_email_sender
from finora.main import create_app

# Instante fijo de inicio de las pruebas: jueves 29/10/2026, 10:00 en Bogotá.
TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)
TEST_MFA_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()
TEST_WEB_URL = "http://localhost:5173"

_DB_FIXTURES = {
    "postgres_url",
    "alembic_cfg",
    "migrated_url",
    "engine",
    "db_session",
    "app",
    "client",
}


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if _DB_FIXTURES & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.db)


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    with PostgresContainer("postgres:18-alpine", driver="psycopg") as postgres:
        yield postgres.get_connection_url()


@pytest.fixture(scope="session")
def alembic_cfg(postgres_url: str) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", postgres_url)
    return config


@pytest.fixture(scope="session")
def migrated_url(postgres_url: str, alembic_cfg: Config) -> str:
    command.upgrade(alembic_cfg, "head")
    return postgres_url


@pytest.fixture(scope="session")
def engine(migrated_url: str) -> Iterator[Engine]:
    engine = create_db_engine(migrated_url)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    with engine.connect() as connection:
        transaction = connection.begin()
        session = Session(
            bind=connection, join_transaction_mode="create_savepoint", expire_on_commit=False
        )
        try:
            yield session
        finally:
            session.close()
            transaction.rollback()


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(TEST_NOW)


@pytest.fixture
def email_outbox() -> InMemoryEmailSender:
    return InMemoryEmailSender()


@pytest.fixture
def settings() -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        environment="test",
        web_url=TEST_WEB_URL,
        mfa_encryption_key=TEST_MFA_KEY,  # type: ignore[arg-type]
    )


@pytest.fixture
def app(
    settings: Settings,
    db_session: Session,
    clock: FrozenClock,
    email_outbox: InMemoryEmailSender,
) -> FastAPI:
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db_session] = lambda: db_session
    app.dependency_overrides[get_clock] = lambda: clock
    app.dependency_overrides[get_email_sender] = lambda: email_outbox
    return app


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    # base_url https: la cookie de sesión es Secure (RNF-AUTH-02). Origin como el navegador.
    with TestClient(app, base_url="https://testserver", headers={"Origin": TEST_WEB_URL}) as client:
        yield client
