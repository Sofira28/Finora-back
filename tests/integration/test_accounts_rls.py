"""Aislamiento de `accounts` con RLS, aun sin filtro en la consulta (T-ACC-DB-02, ADR-0004)."""

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from finora.accounts.models import Account
from finora.auth.models import User
from finora.db.rls import bind_user, unbind_user

TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)


def _usuario(db_session: Session, email: str) -> User:
    user = User(email=email, name=email.split("@")[0], created_at=TEST_NOW)
    db_session.add(user)
    db_session.flush()
    return user


def _cuenta(user: User, name: str) -> Account:
    return Account(
        user_id=user.id,
        name=name,
        type="bank",
        opening_balance=Decimal(1000),
        created_at=TEST_NOW,
        updated_at=TEST_NOW,
    )


@pytest.fixture
def usuarios(db_session: Session) -> tuple[User, User]:
    """Ana con dos cuentas y Luis con una; al terminar no queda usuario fijado."""
    ana, luis = _usuario(db_session, "ana@correo.com"), _usuario(db_session, "luis@correo.com")
    bind_user(db_session, ana.id)
    db_session.add_all([_cuenta(ana, "Nómina"), _cuenta(ana, "Efectivo")])
    db_session.flush()
    bind_user(db_session, luis.id)
    db_session.add(_cuenta(luis, "Nómina"))  # mismo nombre: la unicidad es por usuario
    db_session.flush()
    unbind_user(db_session)
    return ana, luis


def _cuantas(db_session: Session) -> int:
    # A propósito sin WHERE: solo RLS separa a los usuarios.
    return db_session.scalar(select(func.count()).select_from(Account)) or 0


def test_cada_usuario_ve_solo_sus_cuentas(db_session: Session, usuarios: tuple[User, User]) -> None:
    ana, luis = usuarios
    bind_user(db_session, ana.id)
    assert _cuantas(db_session) == 2
    assert set(db_session.scalars(select(Account.user_id))) == {ana.id}
    bind_user(db_session, luis.id)
    assert _cuantas(db_session) == 1


def test_sin_usuario_no_se_ve_ninguna(db_session: Session, usuarios: tuple[User, User]) -> None:
    assert _cuantas(db_session) == 0


def test_no_se_puede_crear_a_nombre_de_otro(
    db_session: Session, usuarios: tuple[User, User]
) -> None:
    ana, luis = usuarios
    bind_user(db_session, ana.id)
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.add(_cuenta(luis, "Intrusa"))
        db_session.flush()


def test_no_se_puede_crear_sin_usuario(db_session: Session, usuarios: tuple[User, User]) -> None:
    ana, _ = usuarios
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.add(_cuenta(ana, "Sin sesión"))
        db_session.flush()


def test_editar_o_borrar_sin_filtro_no_toca_cuentas_ajenas(
    db_session: Session, usuarios: tuple[User, User]
) -> None:
    ana, luis = usuarios
    bind_user(db_session, ana.id)
    editadas = db_session.execute(update(Account).values(name=Account.name + " (editada)"))
    borradas = db_session.execute(delete(Account).where(Account.name.like("%editada%")))
    assert editadas.rowcount == 2  # type: ignore[attr-defined]
    assert borradas.rowcount == 2  # type: ignore[attr-defined]

    bind_user(db_session, luis.id)
    assert db_session.scalars(select(Account.name)).all() == ["Nómina"]


def test_no_se_puede_pasar_una_cuenta_a_otro_usuario(
    db_session: Session, usuarios: tuple[User, User]
) -> None:
    ana, luis = usuarios
    bind_user(db_session, ana.id)
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.execute(update(Account).values(user_id=luis.id))


def test_borrar_el_usuario_borra_sus_cuentas(
    db_session: Session, usuarios: tuple[User, User]
) -> None:
    """RN-ACC-11: la cascada funciona aunque la petición no tenga usuario fijado."""
    ana, luis = usuarios
    db_session.delete(ana)  # como DELETE /me, que no usa UserDb
    db_session.flush()

    bind_user(db_session, ana.id)
    assert _cuantas(db_session) == 0
    bind_user(db_session, luis.id)
    assert _cuantas(db_session) == 1
