"""Rol de aplicación y usuario actual para RLS (T-ACC-DB-01, ADR-0004)."""

import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from finora.auth.dependencies import user_db
from finora.auth.models import User
from finora.clock import FrozenClock
from finora.db.rls import bind_user, unbind_user

CURRENT_USER_ID = text("SELECT current_setting('finora.user_id', true)")


def _usuario_fijado(session: Session) -> str | None:
    valor = session.execute(CURRENT_USER_ID).scalar_one()
    return valor or None  # '' y NULL significan "sin usuario"


def test_la_api_trabaja_como_finora_app_sin_privilegios(engine: Engine) -> None:
    with engine.connect() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "finora_app"
        superusuario, salta_rls = conn.execute(
            text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
        ).one()
        assert (superusuario, salta_rls) == (False, False)
        # No es dueño de ninguna tabla: las políticas RLS se le aplican siempre.
        propias = conn.execute(
            text("SELECT count(*) FROM pg_tables WHERE tableowner = 'finora_app'")
        ).scalar_one()
        assert propias == 0


def test_finora_app_puede_usar_las_tablas_pero_no_la_de_alembic(engine: Engine) -> None:
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM users")).scalar_one() >= 0
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text("SELECT * FROM alembic_version"))


def test_sin_usuario_fijado_no_hay_valor(engine: Engine) -> None:
    with Session(engine) as session:
        assert _usuario_fijado(session) is None


def test_el_usuario_se_mantiene_tras_commit_y_no_pasa_a_otra_sesion(engine: Engine) -> None:
    usuario = uuid.uuid7()
    with Session(engine) as session:
        bind_user(session, usuario)
        assert _usuario_fijado(session) == str(usuario)
        session.commit()
        # Transacción nueva: el evento after_begin lo vuelve a fijar.
        assert _usuario_fijado(session) == str(usuario)
        unbind_user(session)
        assert _usuario_fijado(session) is None
        session.commit()
        assert _usuario_fijado(session) is None

    with Session(engine) as session:
        bind_user(session, usuario)
        session.execute(text("SELECT 1"))
        # Sin unbind ni commit: la sesión se cierra con la transacción abierta.

    # La conexión vuelve al pool; quien la reutilice no hereda el usuario.
    with Session(engine) as otra:
        assert _usuario_fijado(otra) is None


def test_la_dependencia_user_db_fija_y_libera_el_usuario(
    db_session: Session, clock: FrozenClock
) -> None:
    user = User(email="ana@correo.com", name="Ana", password_hash=None, created_at=clock.now())
    db_session.add(user)
    db_session.flush()

    dependencia = user_db(user, db_session)
    sesion = next(dependencia)
    assert sesion is db_session
    assert _usuario_fijado(db_session) == str(user.id)
    # FastAPI reanuda el generador al terminar la petición: corre el `finally`.
    assert next(dependencia, None) is None
    assert _usuario_fijado(db_session) is None


def test_una_politica_rls_falla_cerrado(db_session: Session) -> None:
    """El mecanismo completo con una tabla temporal: sin usuario no se ve ni escribe nada."""
    db_session.execute(text("CREATE TEMP TABLE datos (user_id uuid NOT NULL, valor text)"))
    # FORCE: finora_app es dueño de la tabla temporal y, sin FORCE, el dueño no tiene RLS.
    db_session.execute(text("ALTER TABLE datos ENABLE ROW LEVEL SECURITY"))
    db_session.execute(text("ALTER TABLE datos FORCE ROW LEVEL SECURITY"))
    db_session.execute(
        text(
            "CREATE POLICY propios ON datos USING "
            "(user_id = nullif(current_setting('finora.user_id', true), '')::uuid)"
        )
    )
    ana, luis = uuid.uuid7(), uuid.uuid7()
    insertar = text("INSERT INTO datos VALUES (:user_id, 'x')")

    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.execute(insertar, {"user_id": ana})  # sin usuario fijado

    bind_user(db_session, ana)
    db_session.execute(insertar, {"user_id": ana})
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.execute(insertar, {"user_id": luis})  # a nombre de otro
    assert db_session.execute(text("SELECT count(*) FROM datos")).scalar_one() == 1

    bind_user(db_session, luis)
    assert db_session.execute(text("SELECT count(*) FROM datos")).scalar_one() == 0
    unbind_user(db_session)
    assert db_session.execute(text("SELECT count(*) FROM datos")).scalar_one() == 0


def test_la_migracion_del_rol_baja_y_vuelve_a_subir(engine: Engine, alembic_cfg: Config) -> None:
    privilegio = text("SELECT has_table_privilege('finora_app', 'users', 'SELECT')")
    command.downgrade(alembic_cfg, "0002_google")
    try:
        with engine.connect() as conn:
            assert conn.execute(privilegio).scalar_one() is False
    finally:
        command.upgrade(alembic_cfg, "head")
    with engine.connect() as conn:
        assert conn.execute(privilegio).scalar_one() is True
