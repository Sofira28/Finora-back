from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, Pool, create_engine
from sqlalchemy.orm import Session, sessionmaker

from finora.config import get_settings


def create_db_engine(database_url: str, poolclass: type[Pool] | None = None) -> Engine:
    # Todas las conexiones trabajan en UTC (DP-DB-07).
    return create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=poolclass,
        connect_args={"options": "-c timezone=UTC"},
    )


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@lru_cache
def _default_session_factory() -> sessionmaker[Session]:
    return session_factory(create_db_engine(get_settings().database_url))


def get_db_session() -> Iterator[Session]:
    # Dependencia de FastAPI: una sesión por petición; las pruebas la reemplazan.
    with _default_session_factory()() as session:
        yield session
