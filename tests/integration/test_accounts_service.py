"""Casos de uso de cuentas (T-ACC-BE-02): RF-ACC-01, 05 a 09; RN-ACC-08 a 10; VAL-ACC-01 a 09."""

from datetime import timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from finora.accounts import service
from finora.accounts.models import Account
from finora.accounts.schemas import CreateAccountRequest, UpdateAccountRequest
from finora.auth.models import User
from finora.clock import FrozenClock
from finora.db.rls import bind_user
from finora.errors import ApiProblemError

TARJETA = {"credit_limit": "6000000", "statement_day": 28, "payment_due_day": 18}


def _usuario(db: Session, clock: FrozenClock, email: str) -> User:
    user = User(email=email, name=email.split("@")[0], created_at=clock.now())
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    user = _usuario(db_session, clock, "ana@correo.com")
    bind_user(db_session, user.id)
    return user


def _crear(db: Session, user: User, clock: FrozenClock, **datos: Any) -> Account:
    base: dict[str, Any] = {"name": "Nómina", "type": "bank", "opening_balance": "2800000"}
    base.update(datos)
    return service.create_account(
        db, user.id, CreateAccountRequest.model_validate(base), clock.now()
    )


def _editar(db: Session, user: User, cuenta: Account, clock: FrozenClock, **datos: Any) -> Account:
    cambios = UpdateAccountRequest.model_validate(datos)
    return service.update_account(db, user.id, cuenta.id, cambios, clock.now())


def _error(funcion: Any, *args: Any, **kwargs: Any) -> ApiProblemError:
    with pytest.raises(ApiProblemError) as exc:
        funcion(*args, **kwargs)
    return exc.value


def _campo(error: ApiProblemError) -> tuple[int, str, str, str]:
    [detalle] = error.extra["errors"]
    return (error.status, error.code, detalle["loc"][1], detalle["message"])


# --- Crear (RF-ACC-01) --------------------------------------------------------------------


def test_crear_cuenta_y_tarjeta(db_session: Session, ana: User, clock: FrozenClock) -> None:
    nomina = _crear(db_session, ana, clock, institution="Banco Andino")
    orbita = _crear(
        db_session,
        ana,
        clock,
        name="Órbita",
        type="credit_card",
        opening_balance="820000",
        **TARJETA,
    )

    assert (nomina.type, nomina.institution, nomina.opening_balance) == (
        "bank",
        "Banco Andino",
        Decimal("2800000.0000"),
    )
    assert nomina.credit_limit is None and nomina.archived_at is None
    assert nomina.created_at == nomina.updated_at == clock.now()
    assert (orbita.opening_balance, orbita.credit_limit) == (Decimal(820_000), Decimal(6_000_000))
    assert (orbita.statement_day, orbita.payment_due_day) == (28, 18)
    assert [c.name for c in service.list_accounts(db_session, ana.id)] == ["Nómina", "Órbita"]


@pytest.mark.parametrize(
    ("falta", "mensaje"),
    [
        ("credit_limit", "Indica el cupo de la tarjeta."),
        ("statement_day", "Elige un día entre 1 y 31."),
        ("payment_due_day", "Elige un día entre 1 y 31."),
    ],
)
def test_val_acc_04_tarjeta_sin_sus_datos(
    db_session: Session, ana: User, clock: FrozenClock, falta: str, mensaje: str
) -> None:
    datos = {k: v for k, v in TARJETA.items() if k != falta}
    error = _error(_crear, db_session, ana, clock, type="credit_card", **datos)
    assert _campo(error) == (422, "validation_failed", falta, mensaje)


@pytest.mark.parametrize("campo", ["credit_limit", "statement_day", "payment_due_day"])
def test_val_acc_05_datos_de_tarjeta_en_otra_cuenta(
    db_session: Session, ana: User, clock: FrozenClock, campo: str
) -> None:
    error = _error(_crear, db_session, ana, clock, type="savings", **{campo: TARJETA[campo]})
    assert _campo(error)[:3] == (422, "validation_failed", campo)


@pytest.mark.parametrize("repetido", ["Nómina", "NÓMINA", "nómina"])
def test_val_acc_02_nombre_repetido(
    db_session: Session, ana: User, clock: FrozenClock, repetido: str
) -> None:
    _crear(db_session, ana, clock)
    error = _error(_crear, db_session, ana, clock, name=repetido, type="cash")
    assert _campo(error) == (
        409,
        "account_name_taken",
        "name",
        "Ya tienes una cuenta con ese nombre.",
    )
    assert error.title == "Ya tienes una cuenta con ese nombre."


def test_nombre_repetido_tambien_entre_archivadas(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    cuenta = _crear(db_session, ana, clock)
    service.archive_account(db_session, ana.id, cuenta.id, clock.now())
    assert _error(_crear, db_session, ana, clock).code == "account_name_taken"


def test_otro_usuario_puede_usar_el_mismo_nombre(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    _crear(db_session, ana, clock)
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    assert _crear(db_session, luis, clock).name == "Nómina"


def test_tope_de_cuentas(
    db_session: Session, ana: User, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "MAX_ACCOUNTS", 3)
    for i in range(3):
        _crear(db_session, ana, clock, name=f"Cuenta {i}")
    error = _error(_crear, db_session, ana, clock, name="Una más")
    assert (error.status, error.code) == (409, "account_limit_reached")
    assert error.title == "Llegaste al máximo de 3 cuentas. Elimina las que ya no uses."


def test_el_tope_real_es_100() -> None:
    assert service.MAX_ACCOUNTS == 100


def test_nombre_tomado_a_la_vez_por_otra_peticion(
    db_session: Session, ana: User, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Si la comprobación previa no lo ve, el índice único responde igual y nada queda a medias."""
    _crear(db_session, ana, clock)
    monkeypatch.setattr(service, "_name_in_use", lambda *_args, **_kwargs: False)
    error = _error(_crear, db_session, ana, clock, name="NÓMINA")
    assert error.code == "account_name_taken"
    assert len(service.list_accounts(db_session, ana.id)) == 1


# --- Consultar y aislamiento (VAL-ACC-09) -------------------------------------------------


def test_cuenta_de_otro_usuario_es_inexistente(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    cuenta = _crear(db_session, ana, clock)
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    acciones = [
        lambda: service.get_account(db_session, luis.id, cuenta.id),
        lambda: _editar(db_session, luis, cuenta, clock, name="Mía"),
        lambda: service.archive_account(db_session, luis.id, cuenta.id, clock.now()),
        lambda: service.restore_account(db_session, luis.id, cuenta.id, clock.now()),
        lambda: service.delete_account(db_session, luis.id, cuenta.id),
    ]
    for accion in acciones:
        error = _error(accion)
        assert (error.status, error.code, error.title) == (
            404,
            "account_not_found",
            "No encontramos esa cuenta.",
        )
    assert service.list_accounts(db_session, luis.id) == []

    bind_user(db_session, ana.id)
    db_session.expire_all()
    assert service.get_account(db_session, ana.id, cuenta.id).name == "Nómina"


def test_el_servicio_filtra_aunque_rls_lo_permitiera(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    """Primera capa: con la sesión fijada en Ana, pedir como Luis no devuelve nada."""
    cuenta = _crear(db_session, ana, clock)
    luis = _usuario(db_session, clock, "luis@correo.com")
    assert _error(service.get_account, db_session, luis.id, cuenta.id).status == 404
    assert service.list_accounts(db_session, luis.id) == []


# --- Editar (RF-ACC-05/06) ----------------------------------------------------------------


def test_editar_nombre_entidad_y_saldo(db_session: Session, ana: User, clock: FrozenClock) -> None:
    cuenta = _crear(db_session, ana, clock, institution="Banco Andino")
    clock.advance(timedelta(minutes=5))
    _editar(db_session, ana, cuenta, clock, name="Nómina principal", opening_balance="3000000.5")
    assert (cuenta.name, cuenta.institution, cuenta.opening_balance) == (
        "Nómina principal",
        "Banco Andino",
        Decimal("3000000.5"),
    )
    assert cuenta.updated_at == clock.now() != cuenta.created_at

    _editar(db_session, ana, cuenta, clock, institution=None)
    assert cuenta.institution is None


def test_cambiar_mayusculas_del_propio_nombre(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    cuenta = _crear(db_session, ana, clock)
    assert _editar(db_session, ana, cuenta, clock, name="NÓMINA").name == "NÓMINA"


def test_editar_con_nombre_de_otra_cuenta(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    _crear(db_session, ana, clock)
    efectivo = _crear(db_session, ana, clock, name="Efectivo", type="cash")
    assert _error(_editar, db_session, ana, efectivo, clock, name="nómina").code == (
        "account_name_taken"
    )
    db_session.refresh(efectivo)
    assert efectivo.name == "Efectivo"


def test_editar_datos_de_tarjeta(db_session: Session, ana: User, clock: FrozenClock) -> None:
    orbita = _crear(db_session, ana, clock, name="Órbita", type="credit_card", **TARJETA)
    _editar(db_session, ana, orbita, clock, credit_limit="8000000", statement_day=30)
    assert (orbita.credit_limit, orbita.statement_day, orbita.payment_due_day) == (
        Decimal(8_000_000),
        30,
        18,
    )


@pytest.mark.parametrize("campo", ["credit_limit", "statement_day", "payment_due_day"])
def test_no_se_borran_datos_obligatorios(
    db_session: Session, ana: User, clock: FrozenClock, campo: str
) -> None:
    orbita = _crear(db_session, ana, clock, name="Órbita", type="credit_card", **TARJETA)
    assert _campo(_error(_editar, db_session, ana, orbita, clock, **{campo: None}))[:3] == (
        422,
        "validation_failed",
        campo,
    )


@pytest.mark.parametrize("campo", ["name", "opening_balance"])
def test_nombre_y_saldo_no_pueden_ser_nulos(
    db_session: Session, ana: User, clock: FrozenClock, campo: str
) -> None:
    cuenta = _crear(db_session, ana, clock)
    assert _campo(_error(_editar, db_session, ana, cuenta, clock, **{campo: None}))[:3] == (
        422,
        "validation_failed",
        campo,
    )


def test_datos_de_tarjeta_en_otra_cuenta_al_editar(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    cuenta = _crear(db_session, ana, clock)
    error = _error(_editar, db_session, ana, cuenta, clock, credit_limit="1000")
    assert _campo(error) == (
        422,
        "validation_failed",
        "credit_limit",
        "Este dato solo aplica a tarjetas de crédito.",
    )


def test_val_acc_07_saldo_inicial_con_movimientos(
    db_session: Session, ana: User, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    cuenta = _crear(db_session, ana, clock)
    monkeypatch.setattr(service, "movement_count", lambda *_args: 3)
    error = _error(_editar, db_session, ana, cuenta, clock, opening_balance="1")
    assert (error.status, error.code, error.title) == (
        409,
        "account_has_movements",
        "Esta cuenta ya tiene movimientos. Para corregir el saldo, registra un ajuste.",
    )
    # El mismo valor no es un cambio, y lo demás sí se puede editar.
    _editar(db_session, ana, cuenta, clock, opening_balance="2800000.00", name="Nómina 2")
    assert cuenta.name == "Nómina 2"


# --- Archivar y reactivar (RF-ACC-07/08) --------------------------------------------------


def test_archivar_y_reactivar(db_session: Session, ana: User, clock: FrozenClock) -> None:
    cuenta = _crear(db_session, ana, clock)
    clock.advance(timedelta(hours=1))
    archivada_en = clock.now()
    service.archive_account(db_session, ana.id, cuenta.id, clock.now())
    assert cuenta.archived_at == archivada_en

    clock.advance(timedelta(hours=1))
    service.archive_account(db_session, ana.id, cuenta.id, clock.now())  # idempotente
    assert cuenta.archived_at == archivada_en
    assert cuenta in service.list_accounts(db_session, ana.id)  # el listado trae ambas

    service.restore_account(db_session, ana.id, cuenta.id, clock.now())
    assert cuenta.archived_at is None
    assert cuenta.updated_at == clock.now()
    service.restore_account(db_session, ana.id, cuenta.id, clock.now())
    assert cuenta.archived_at is None


# --- Eliminar (RF-ACC-09, RN-ACC-10) ------------------------------------------------------


def test_eliminar_sin_movimientos(db_session: Session, ana: User, clock: FrozenClock) -> None:
    cuenta = _crear(db_session, ana, clock)
    service.delete_account(db_session, ana.id, cuenta.id)
    assert db_session.scalars(select(Account)).all() == []
    assert _error(service.get_account, db_session, ana.id, cuenta.id).status == 404


def test_val_acc_08_eliminar_con_movimientos(
    db_session: Session, ana: User, clock: FrozenClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    cuenta = _crear(db_session, ana, clock)
    monkeypatch.setattr(service, "movement_count", lambda *_args: 1)
    error = _error(service.delete_account, db_session, ana.id, cuenta.id)
    assert (error.status, error.code) == (409, "account_has_movements")
    assert error.title == (
        "Esta cuenta tiene movimientos. Puedes archivarla para ocultarla sin perder su historial."
    )
    assert service.get_account(db_session, ana.id, cuenta.id) is cuenta


def test_hoy_ninguna_cuenta_tiene_movimientos(
    db_session: Session, ana: User, clock: FrozenClock
) -> None:
    assert service.movement_count(db_session, _crear(db_session, ana, clock)) == 0
