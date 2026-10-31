"""Row-Level Security: rol de aplicación y usuario actual en la BD (ADR-0004, DP-DB-06).

- La API trabaja con el rol `finora_app` (sin SUPERUSER ni BYPASSRLS y no dueño de las
  tablas), así que las políticas RLS sí se aplican. Alembic usa el rol dueño.
- El usuario de la petición se guarda en `Session.info` y se fija con `set_config(..., true)`
  al comenzar cada transacción: los `commit` intermedios no lo pierden y, al ser local a la
  transacción, nunca pasa a otra petición que reutilice la conexión del pool.
- Sin usuario fijado, las políticas no dejan ver ni escribir ninguna fila (falla cerrado).
"""

import uuid
from typing import Any

from sqlalchemy import Connection, Engine, event, text
from sqlalchemy.orm import Session, SessionTransaction

APP_ROLE = "finora_app"
USER_SETTING = "finora.user_id"
_USER_KEY = "finora_user_id"

_SET_USER = text(f"SELECT set_config('{USER_SETTING}', :user_id, true)")


def use_app_role(engine: Engine) -> None:
    """Cada conexión nueva del motor trabaja como `finora_app`."""

    @event.listens_for(engine, "connect")
    def _set_role(dbapi_connection: Any, _record: object) -> None:
        with dbapi_connection.cursor() as cursor:
            cursor.execute(f"SET ROLE {APP_ROLE}")
        # Fuera de una transacción: un ROLLBACK posterior no deshace el SET ROLE.
        dbapi_connection.commit()


def bind_user(session: Session, user_id: uuid.UUID) -> None:
    """Fija el usuario de la petición para esta transacción y las siguientes de la sesión."""
    session.info[_USER_KEY] = str(user_id)
    if session.in_transaction():
        session.execute(_SET_USER, {"user_id": str(user_id)})


def unbind_user(session: Session) -> None:
    """Olvida el usuario; si hay una transacción abierta, también deja de valer en ella."""
    if session.info.pop(_USER_KEY, None) is not None and session.in_transaction():
        session.execute(_SET_USER, {"user_id": ""})


@event.listens_for(Session, "after_begin")
def _apply_user(session: Session, _transaction: SessionTransaction, connection: Connection) -> None:
    user_id = session.info.get(_USER_KEY)
    if user_id is not None:
        connection.execute(_SET_USER, {"user_id": user_id})
