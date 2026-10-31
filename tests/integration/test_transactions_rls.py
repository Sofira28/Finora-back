"""Aislamiento de `transactions`: RLS y FK compuestas (T-TRX-DB-01, ADR-0004 y 0005)."""

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from finora.accounts.models import Account
from finora.auth.models import User
from finora.db.rls import bind_user, unbind_user
from finora.transactions.models import Transaction

TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)


def _usuario(db_session: Session, email: str) -> User:
    user = User(email=email, name=email.split("@")[0], created_at=TEST_NOW)
    db_session.add(user)
    db_session.flush()
    return user


def _cuenta(db_session: Session, user: User, name: str) -> Account:
    cuenta = Account(
        user_id=user.id,
        name=name,
        type="bank",
        opening_balance=Decimal(1000),
        created_at=TEST_NOW,
        updated_at=TEST_NOW,
    )
    db_session.add(cuenta)
    db_session.flush()
    return cuenta


def _gasto(user: User, cuenta: Account) -> Transaction:
    return Transaction(
        user_id=user.id,
        type="expense",
        amount=Decimal(1000),
        occurred_on=date(2026, 10, 29),
        account_id=cuenta.id,
        category="groceries",
        description="Mercado",
        search_text="mercado",
        created_at=TEST_NOW,
        updated_at=TEST_NOW,
    )


Datos = tuple[User, User, Account, Account]


@pytest.fixture
def datos(db_session: Session) -> Datos:
    """Ana con dos gastos y Luis con uno; al terminar no queda usuario fijado."""
    ana, luis = _usuario(db_session, "ana@correo.com"), _usuario(db_session, "luis@correo.com")
    bind_user(db_session, ana.id)
    nomina_ana = _cuenta(db_session, ana, "Nómina")
    db_session.add_all([_gasto(ana, nomina_ana), _gasto(ana, nomina_ana)])
    db_session.flush()
    bind_user(db_session, luis.id)
    nomina_luis = _cuenta(db_session, luis, "Nómina")
    db_session.add(_gasto(luis, nomina_luis))
    db_session.flush()
    unbind_user(db_session)
    return ana, luis, nomina_ana, nomina_luis


def _cuantos(db_session: Session) -> int:
    # A propósito sin WHERE: solo RLS separa a los usuarios.
    return db_session.scalar(select(func.count()).select_from(Transaction)) or 0


def test_cada_usuario_ve_solo_sus_movimientos(db_session: Session, datos: Datos) -> None:
    ana, luis, _, _ = datos
    bind_user(db_session, ana.id)
    assert _cuantos(db_session) == 2
    assert set(db_session.scalars(select(Transaction.user_id))) == {ana.id}
    bind_user(db_session, luis.id)
    assert _cuantos(db_session) == 1


def test_sin_usuario_no_se_ve_ninguno(db_session: Session, datos: Datos) -> None:
    assert _cuantos(db_session) == 0


def test_no_se_puede_crear_a_nombre_de_otro(db_session: Session, datos: Datos) -> None:
    ana, luis, _, nomina_luis = datos
    bind_user(db_session, ana.id)
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.add(_gasto(luis, nomina_luis))
        db_session.flush()


def test_no_se_puede_usar_una_cuenta_de_otro(db_session: Session, datos: Datos) -> None:
    """La FK compuesta lo impide aunque la fila sea del usuario fijado."""
    ana, _, _, nomina_luis = datos
    bind_user(db_session, ana.id)
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(_gasto(ana, nomina_luis))
        db_session.flush()


def test_no_se_puede_transferir_a_una_cuenta_de_otro(db_session: Session, datos: Datos) -> None:
    ana, _, nomina_ana, nomina_luis = datos
    bind_user(db_session, ana.id)
    transferencia = _gasto(ana, nomina_ana)
    transferencia.type, transferencia.category = "transfer", None
    transferencia.destination_account_id = nomina_luis.id
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(transferencia)
        db_session.flush()


def test_editar_o_borrar_sin_filtro_no_toca_movimientos_ajenos(
    db_session: Session, datos: Datos
) -> None:
    ana, luis, _, _ = datos
    bind_user(db_session, ana.id)
    editados = db_session.execute(update(Transaction).values(note="editado"))
    borrados = db_session.execute(delete(Transaction))
    assert editados.rowcount == 2  # type: ignore[attr-defined]
    assert borrados.rowcount == 2  # type: ignore[attr-defined]

    bind_user(db_session, luis.id)
    assert db_session.scalars(select(Transaction.note)).all() == [None]


def test_no_se_puede_pasar_un_movimiento_a_otro_usuario(db_session: Session, datos: Datos) -> None:
    ana, luis, _, _ = datos
    bind_user(db_session, ana.id)
    with pytest.raises(DBAPIError, match="row-level security"), db_session.begin_nested():
        db_session.execute(update(Transaction).values(user_id=luis.id))


def test_borrar_el_usuario_borra_sus_cuentas_y_movimientos(
    db_session: Session, datos: Datos
) -> None:
    """RN-AUTH-07: la cascada pasa aunque las FK a `accounts` sean NO ACTION."""
    ana, luis, _, _ = datos
    db_session.delete(ana)  # como DELETE /me, que no usa UserDb
    db_session.flush()

    bind_user(db_session, ana.id)
    assert _cuantos(db_session) == 0
    assert db_session.scalar(select(func.count()).select_from(Account)) == 0
    bind_user(db_session, luis.id)
    assert _cuantos(db_session) == 1
