from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, Pool, create_engine
from sqlalchemy.orm import Session, sessionmaker

from finora.config import get_settings
from finora.db.rls import use_app_role


def create_db_engine(
    database_url: str, poolclass: type[Pool] | None = None, *, app_role: bool = False
) -> Engine:
    """Motor de PostgreSQL. `app_role=True` para la API (RLS, ADR-0004); Alembic usa el dueño."""
    # Todas las conexiones trabajan en UTC (DP-DB-07).
    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=poolclass,
        connect_args={"options": "-c timezone=UTC"},
    )
    if app_role:
        use_app_role(engine)
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


@lru_cache
def _default_session_factory() -> sessionmaker[Session]:
    return session_factory(create_db_engine(get_settings().database_url, app_role=True))


def get_db_session() -> Iterator[Session]:
    # Dependencia de FastAPI: una sesión por petición; las pruebas la reemplazan.
    with _default_session_factory()() as session:
        yield session
