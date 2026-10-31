"""Casos de uso de movimientos (T-TRX-BE-02).

RF-TRX-01 a 08; RN-TRX-02 a 11; VAL-TRX-01 a 11; CA-TRX-02 a 07 y 09 a 12 en el servicio.
El reloj de las pruebas marca el jueves 29/10/2026, 10:00 en Bogotá.
"""

import itertools
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from finora.accounts import service as accounts
from finora.accounts.models import Account, AccountType
from finora.accounts.schemas import CreateAccountRequest
from finora.auth.models import User
from finora.clock import FrozenClock
from finora.db.rls import bind_user
from finora.domain.money import Money
from finora.errors import ApiProblemError
from finora.transactions import service
from finora.transactions.effects import Role, effect
from finora.transactions.ledger import effects_by_account
from finora.transactions.models import Category, Transaction, TransactionType
from finora.transactions.schemas import TransactionRequest
from finora.transactions.service import Filters, Sort

HOY = "2026-10-29"
TARJETA = {"credit_limit": "6000000", "statement_day": 28, "payment_due_day": 18}


def _usuario(db: Session, clock: FrozenClock, email: str) -> User:
    user = User(email=email, name=email.split("@")[0], created_at=clock.now())
    db.add(user)
    db.flush()
    return user


def _cuenta(db: Session, user: User, clock: FrozenClock, **datos: Any) -> Account:
    return accounts.create_account(
        db, user.id, CreateAccountRequest.model_validate(datos), clock.now()
    )


class Cuentas:
    """CA-ACC-01: el contexto común de los criterios de aceptación."""

    def __init__(self, db: Session, user: User, clock: FrozenClock) -> None:
        self.nomina = _cuenta(
            db, user, clock, name="Nómina", type="bank", opening_balance="2800000"
        )
        self.efectivo = _cuenta(
            db, user, clock, name="Efectivo", type="cash", opening_balance="90000"
        )
        self.cdt = _cuenta(
            db, user, clock, name="CDT", type="investment", opening_balance="12000000"
        )
        self.orbita = _cuenta(
            db,
            user,
            clock,
            name="Tarjeta Órbita",
            type="credit_card",
            opening_balance="820000",
            **TARJETA,
        )


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    user = _usuario(db_session, clock, "ana@correo.com")
    bind_user(db_session, user.id)
    return user


@pytest.fixture
def c(db_session: Session, ana: User, clock: FrozenClock) -> Cuentas:
    return Cuentas(db_session, ana, clock)


def _peticion(**datos: Any) -> TransactionRequest:
    tipo = datos.get("type", "expense")
    base: dict[str, Any] = {"type": tipo, "date": HOY}
    if tipo in ("expense", "income"):
        base |= {
            "amount": "120000",
            "category": "groceries" if tipo == "expense" else "salary",
            "description": "Mercado" if tipo == "expense" else "Salario",
        }
    elif tipo == "transfer":
        base["amount"] = "200000"
    base.update(datos)
    return TransactionRequest.model_validate(
        {k: str(v.id) if isinstance(v, Account) else v for k, v in base.items()}
    )


def _crear(db: Session, user: User, clock: FrozenClock, **datos: Any) -> Transaction:
    return service.create_transaction(db, user.id, _peticion(**datos), clock.now())


def _reemplazar(
    db: Session, user: User, clock: FrozenClock, mov: Transaction, **datos: Any
) -> Transaction:
    return service.replace_transaction(db, user.id, mov.id, _peticion(**datos), clock.now())


def _error(funcion: Any, *args: Any, **kwargs: Any) -> ApiProblemError:
    with pytest.raises(ApiProblemError) as exc:
        funcion(*args, **kwargs)
    return exc.value


def _campo(error: ApiProblemError) -> tuple[int, str, str, str]:
    [detalle] = error.extra["errors"]
    return (error.status, error.code, detalle["loc"][1], detalle["message"])


def _saldo(db: Session, user: User, cuenta: Account) -> Money:
    efecto = effects_by_account(db, user.id, [cuenta.id]).get(cuenta.id, Money.zero("COP"))
    return Money(cuenta.opening_balance, "COP") + efecto


def _cop(monto: str | int) -> Money:
    return Money(monto, "COP")


# --- Crear (RF-TRX-01 a 03) ---------------------------------------------------------------


def test_crea_un_gasto(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    mov = _crear(
        db_session, ana, clock, account_id=c.nomina, description=" Café ÁRBOL ", note="Pago"
    )
    db_session.expire(mov)
    assert (mov.type, mov.amount, mov.occurred_on) == (
        "expense",
        Decimal(120_000),
        date(2026, 10, 29),
    )
    assert (mov.account_id, mov.destination_account_id) == (c.nomina.id, None)
    assert (mov.category, mov.description, mov.note) == ("groceries", "Café ÁRBOL", "Pago")
    assert mov.search_text == "cafe arbol\npago"
    assert mov.created_at == mov.updated_at == clock.now()
    assert _saldo(db_session, ana, c.nomina) == _cop(2_680_000)  # CA-TRX-01


def test_crea_una_transferencia_sin_descripcion(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    mov = _crear(
        db_session,
        ana,
        clock,
        type="transfer",
        account_id=c.nomina,
        destination_account_id=c.efectivo,
    )
    assert (mov.category, mov.description, mov.search_text) == (None, None, "")
    assert _saldo(db_session, ana, c.nomina) == _cop(2_600_000)  # CA-TRX-02
    assert _saldo(db_session, ana, c.efectivo) == _cop(290_000)


def test_pago_de_tarjeta(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    """CA-TRX-05."""
    _crear(
        db_session,
        ana,
        clock,
        type="transfer",
        amount="820000",
        account_id=c.nomina,
        destination_account_id=c.orbita,
    )
    assert _saldo(db_session, ana, c.orbita) == _cop(0)
    assert _saldo(db_session, ana, c.nomina) == _cop(1_980_000)


@pytest.mark.parametrize("fecha", ["2000-01-01", HOY])
def test_fechas_limite_permitidas(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock, fecha: str
) -> None:
    assert (
        _crear(db_session, ana, clock, account_id=c.nomina, date=fecha).occurred_on.isoformat()
        == fecha
    )


@pytest.mark.parametrize("fecha", ["1999-12-31", "2026-10-30"])
def test_fecha_fuera_de_rango(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock, fecha: str
) -> None:
    """VAL-TRX-02 (RN-TRX-09)."""
    error = _error(_crear, db_session, ana, clock, account_id=c.nomina, date=fecha)
    assert _campo(error) == (422, "validation_failed", "date", service.DATE_MESSAGE)


def test_hoy_es_el_dia_en_colombia(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """Jueves 29/10 a las 11:30 p. m. en Bogotá ya es viernes 30/10 en UTC."""
    clock.advance(datetime(2026, 10, 30, 4, 30, tzinfo=UTC) - clock.now())
    _crear(db_session, ana, clock, account_id=c.nomina, date="2026-10-29")
    error = _error(_crear, db_session, ana, clock, account_id=c.nomina, date="2026-10-30")
    assert _campo(error)[2] == "date"


# --- Campos por tipo (VAL-TRX-01, 05 a 07 y 11) -------------------------------------------


@pytest.mark.parametrize(
    ("datos", "campo", "tipo_error", "mensaje"),
    [
        ({"amount": None}, "amount", "missing", service.AMOUNT_MESSAGE),
        ({"category": None}, "category", "missing", service.CATEGORY_MESSAGE),
        ({"description": None}, "description", "missing", service.DESCRIPTION_MESSAGE),
        ({"description": "   "}, "description", "missing", service.DESCRIPTION_MESSAGE),
        ({"category": "salary"}, "category", "category_mismatch", service.CATEGORY_MESSAGE),
        ({"target_balance": "1"}, "target_balance", "not_allowed", service.NOT_ALLOWED_MESSAGE),
        (
            {"type": "income", "category": "groceries"},
            "category",
            "category_mismatch",
            service.CATEGORY_MESSAGE,
        ),
        (
            {"type": "transfer", "destination_account_id": None},
            "destination_account_id",
            "missing",
            service.DESTINATION_MESSAGE,
        ),
        (
            {"type": "transfer", "category": "groceries"},
            "category",
            "not_allowed",
            service.NOT_ALLOWED_MESSAGE,
        ),
        (
            {"type": "adjustment", "target_balance": None},
            "target_balance",
            "missing",
            service.TARGET_MESSAGE,
        ),
        (
            {"type": "adjustment", "target_balance": "1", "amount": "1"},
            "amount",
            "not_allowed",
            service.NOT_ALLOWED_MESSAGE,
        ),
    ],
)
def test_campos_por_tipo(
    db_session: Session,
    ana: User,
    c: Cuentas,
    clock: FrozenClock,
    datos: dict[str, Any],
    campo: str,
    tipo_error: str,
    mensaje: str,
) -> None:
    if datos.get("type") == "transfer" and "destination_account_id" not in datos:
        datos = {**datos, "destination_account_id": c.efectivo}
    error = _error(_crear, db_session, ana, clock, account_id=c.nomina, **datos)
    [detalle] = error.extra["errors"]
    assert (detalle["loc"], detalle["type"], detalle["message"]) == (
        ["body", campo],
        tipo_error,
        mensaje,
    )
    assert db_session.scalar(select(func.count()).select_from(Transaction)) == 0


def test_destino_en_un_gasto_no_aplica(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    error = _error(
        _crear, db_session, ana, clock, account_id=c.nomina, destination_account_id=c.efectivo
    )
    assert _campo(error)[2] == "destination_account_id"


def test_sin_categoria_sirve_para_gastos_e_ingresos(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    _crear(db_session, ana, clock, account_id=c.nomina, category="uncategorized")
    _crear(db_session, ana, clock, type="income", account_id=c.nomina, category="uncategorized")


# --- Cuentas (VAL-TRX-03 a 05, RN-TRX-08 y 11) --------------------------------------------


def test_cuenta_de_otro_usuario_o_inexistente(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    de_luis = _cuenta(db_session, luis, clock, name="Nómina", type="bank", opening_balance="1")
    bind_user(db_session, ana.id)

    for cambios in (
        {"account_id": de_luis},
        {"type": "transfer", "account_id": c.nomina, "destination_account_id": de_luis},
    ):
        error = _error(_crear, db_session, ana, clock, **cambios)
        assert _campo(error)[3] == service.ACCOUNT_MESSAGE
    error = _error(
        _crear, db_session, ana, clock, account_id="0193a1b2-0000-7000-8000-000000000000"
    )
    assert _campo(error) == (422, "validation_failed", "account_id", service.ACCOUNT_MESSAGE)


def test_cuenta_archivada(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    """VAL-TRX-04: ni como cuenta ni como destino."""
    accounts.archive_account(db_session, ana.id, c.efectivo.id, clock.now())
    error = _error(_crear, db_session, ana, clock, account_id=c.efectivo)
    assert _campo(error) == (422, "validation_failed", "account_id", service.ARCHIVED_MESSAGE)
    error = _error(
        _crear,
        db_session,
        ana,
        clock,
        type="transfer",
        account_id=c.nomina,
        destination_account_id=c.efectivo,
    )
    assert _campo(error)[2:] == ("destination_account_id", service.ARCHIVED_MESSAGE)


def test_transferencia_a_la_misma_cuenta(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """VAL-TRX-05, CA-TRX-09."""
    error = _error(
        _crear,
        db_session,
        ana,
        clock,
        type="transfer",
        account_id=c.nomina,
        destination_account_id=c.nomina,
    )
    assert _campo(error)[2:] == ("destination_account_id", service.DESTINATION_MESSAGE)


# --- Ajustes (RF-TRX-03, RN-TRX-04, VAL-TRX-09) -------------------------------------------


def test_ajuste_de_saldo(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    """CA-TRX-06."""
    mov = _crear(
        db_session, ana, clock, type="adjustment", account_id=c.efectivo, target_balance="75000"
    )
    assert mov.amount == Decimal(-15_000)
    assert _saldo(db_session, ana, c.efectivo) == _cop(75_000)


def test_ajuste_cuenta_los_movimientos_previos(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    _crear(db_session, ana, clock, account_id=c.orbita, amount="300000")  # deuda 1.120.000
    mov = _crear(
        db_session, ana, clock, type="adjustment", account_id=c.orbita, target_balance="1000000"
    )
    assert mov.amount == Decimal(-120_000)
    assert _saldo(db_session, ana, c.orbita) == _cop(1_000_000)


def test_ajuste_igual_al_saldo(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    error = _error(
        _crear,
        db_session,
        ana,
        clock,
        type="adjustment",
        account_id=c.efectivo,
        target_balance="90000.00",
    )
    assert _campo(error)[2:] == ("target_balance", service.SAME_BALANCE_MESSAGE)


def test_editar_un_ajuste_no_se_cuenta_a_si_mismo(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    mov = _crear(
        db_session, ana, clock, type="adjustment", account_id=c.efectivo, target_balance="75000"
    )
    mov = _reemplazar(
        db_session,
        ana,
        clock,
        mov,
        type="adjustment",
        account_id=c.efectivo,
        target_balance="80000",
    )
    assert mov.amount == Decimal(-10_000)
    assert _saldo(db_session, ana, c.efectivo) == _cop(80_000)


def test_ajuste_fuera_de_rango(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """La diferencia no cabe en NUMERIC(19,4): error de campo, no un 500."""
    _crear(db_session, ana, clock, type="income", account_id=c.nomina, amount="999999999999999")
    error = _error(
        _crear,
        db_session,
        ana,
        clock,
        type="adjustment",
        account_id=c.nomina,
        target_balance="-999999999999999",
    )
    assert _campo(error)[2] == "target_balance"


# --- Editar y eliminar (RF-TRX-07 y 08, CA-TRX-07) ----------------------------------------


def test_editar_y_eliminar(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    mov = _crear(db_session, ana, clock, account_id=c.nomina)
    clock.advance(timedelta(minutes=5))
    mov = _reemplazar(db_session, ana, clock, mov, account_id=c.nomina, amount="100000")
    assert _saldo(db_session, ana, c.nomina) == _cop(2_700_000)
    assert mov.updated_at == clock.now() != mov.created_at

    service.delete_transaction(db_session, ana.id, mov.id)
    assert _saldo(db_session, ana, c.nomina) == _cop(2_800_000)
    assert _campo_404(db_session, ana, mov.id)


def _campo_404(db: Session, user: User, transaction_id: Any) -> bool:
    error = _error(service.get_transaction, db, user.id, transaction_id)
    return (error.status, error.code, error.title) == (
        404,
        "transaction_not_found",
        "No encontramos ese movimiento.",
    )


def test_cambiar_el_tipo(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> None:
    """Un gasto pasa a transferencia: pierde la categoría y la descripción es opcional."""
    mov = _crear(db_session, ana, clock, account_id=c.nomina)
    mov = _reemplazar(
        db_session,
        ana,
        clock,
        mov,
        type="transfer",
        account_id=c.nomina,
        destination_account_id=c.cdt,
        amount="500000",
    )
    assert (mov.type, mov.category, mov.description) == ("transfer", None, None)
    assert _saldo(db_session, ana, c.cdt) == _cop(12_500_000)


def test_editar_en_una_cuenta_archivada(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """RN-TRX-08: se edita sin cambiar la cuenta, pero no se mueve a otra archivada."""
    mov = _crear(db_session, ana, clock, account_id=c.efectivo)
    accounts.archive_account(db_session, ana.id, c.efectivo.id, clock.now())
    mov = _reemplazar(db_session, ana, clock, mov, account_id=c.efectivo, amount="1000")
    assert mov.amount == Decimal(1000)

    accounts.archive_account(db_session, ana.id, c.cdt.id, clock.now())
    error = _error(_reemplazar, db_session, ana, clock, mov, account_id=c.cdt)
    assert _campo(error)[3] == service.ARCHIVED_MESSAGE
    service.delete_transaction(db_session, ana.id, mov.id)


def test_movimientos_de_otro_usuario(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """CA-TRX-11: A no ve, edita ni elimina un movimiento de B."""
    mov = _crear(db_session, ana, clock, account_id=c.nomina)
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    assert _campo_404(db_session, luis, mov.id)
    assert _error(_reemplazar, db_session, luis, clock, mov, account_id=c.nomina).status == 404
    assert _error(service.delete_transaction, db_session, luis.id, mov.id).status == 404
    assert service.list_transactions(db_session, luis.id, Filters()).total == 0


# --- Saldos en SQL = regla de `effects` ---------------------------------------------------


def test_la_consulta_sql_coincide_con_effects(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """Todas las combinaciones de tipo y cuenta: SQL y Python dan el mismo saldo."""
    todas = [c.nomina, c.efectivo, c.cdt, c.orbita]
    esperado = {cuenta.id: _cop(0) for cuenta in todas}
    tipos = {cuenta.id: AccountType(cuenta.type) for cuenta in todas}
    for n, cuenta in enumerate(todas, start=1):
        for tipo in ("expense", "income"):
            _crear(db_session, ana, clock, type=tipo, account_id=cuenta, amount=f"{n}000.25")
            esperado[cuenta.id] += effect(
                TransactionType(tipo), _cop(f"{n}000.25"), Role.ACCOUNT, tipos[cuenta.id]
            )
    for origen, destino in itertools.permutations(todas, 2):
        _crear(
            db_session,
            ana,
            clock,
            type="transfer",
            account_id=origen,
            destination_account_id=destino,
            amount="777.5",
        )
        esperado[origen.id] += effect(
            TransactionType.TRANSFER, _cop("777.5"), Role.ACCOUNT, tipos[origen.id]
        )
        esperado[destino.id] += effect(
            TransactionType.TRANSFER, _cop("777.5"), Role.DESTINATION, tipos[destino.id]
        )
    _crear(db_session, ana, clock, type="adjustment", account_id=c.orbita, target_balance="5")
    esperado[c.orbita.id] = _cop(5) - Money(c.orbita.opening_balance, "COP")

    assert effects_by_account(db_session, ana.id) == esperado


# --- Listado, filtros y resumen (RF-TRX-04 a 06, RN-TRX-05) -------------------------------


def _ids(pagina: service.Page) -> list[Any]:
    return [mov.id for mov in pagina.items]


def _resumen(pagina: service.Page) -> tuple[object, ...]:
    r = pagina.summary
    return (r.count, r.income.amount, r.expense.amount, r.savings.amount, r.transfers.amount)


@pytest.fixture
def mes(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> dict[str, Transaction]:
    """Un movimiento de cada clase, en fechas distintas."""
    datos: dict[str, dict[str, Any]] = {
        "salario": {
            "type": "income",
            "account_id": c.nomina,
            "amount": "3200000",
            "date": "2026-10-01",
        },
        "mercado": {"account_id": c.nomina, "description": "Mercado Éxito", "date": "2026-10-05"},
        "cena": {
            "account_id": c.orbita,
            "amount": "300000",
            "category": "restaurants",
            "description": "Cena",
            "date": "2026-10-10",
        },
        "retiro": {
            "type": "transfer",
            "account_id": c.nomina,
            "destination_account_id": c.efectivo,
            "date": "2026-10-12",
        },
        "ahorro": {
            "type": "transfer",
            "account_id": c.nomina,
            "destination_account_id": c.cdt,
            "amount": "500000",
            "date": "2026-10-15",
        },
        "pago": {
            "type": "transfer",
            "account_id": c.nomina,
            "destination_account_id": c.orbita,
            "amount": "820000",
            "date": "2026-10-20",
            "note": "Pago 50% del mes",
        },
        "uso_cdt": {
            "type": "transfer",
            "account_id": c.cdt,
            "destination_account_id": c.nomina,
            "amount": "100000",
            "date": "2026-10-22",
        },
        "ajuste": {
            "type": "adjustment",
            "account_id": c.efectivo,
            "target_balance": "275000",
            "date": "2026-10-25",
        },
        "septiembre": {
            "account_id": c.efectivo,
            "amount": "5000",
            "description": "Café",
            "category": "restaurants",
            "date": "2026-09-30",
        },
    }
    return {nombre: _crear(db_session, ana, clock, **d) for nombre, d in datos.items()}


def _listar(db: Session, user: User, **kwargs: Any) -> service.Page:
    filtros = {k: kwargs.pop(k) for k in list(kwargs) if k in Filters.__dataclass_fields__}
    return service.list_transactions(db, user.id, Filters(**filtros), **kwargs)


def test_listado_y_resumen(db_session: Session, ana: User, mes: dict[str, Transaction]) -> None:
    """Más reciente primero; transferencias, ahorro y ajustes separados (CA-TRX-02 a 06)."""
    pagina = _listar(db_session, ana, from_date=date(2026, 10, 1), to_date=date(2026, 10, 31))
    assert _ids(pagina) == [
        mes[n].id
        for n in ("ajuste", "uso_cdt", "pago", "ahorro", "retiro", "cena", "mercado", "salario")
    ]
    assert pagina.total == 8
    assert pagina.next_cursor is None
    # Ingresos 3.200.000; gastos 120.000 + 300.000; ahorro neto 500.000 - 100.000;
    # transferencias 200.000 + 820.000; el ajuste solo suma en la cantidad.
    assert _resumen(pagina) == (8, 3_200_000, 420_000, 400_000, 1_020_000)


@pytest.mark.parametrize(
    ("filtros", "esperados"),
    [
        ({"type": TransactionType.TRANSFER}, {"retiro", "ahorro", "pago", "uso_cdt"}),
        ({"category": Category.RESTAURANTS}, {"cena", "septiembre"}),
        ({"from_date": date(2026, 10, 20)}, {"pago", "uso_cdt", "ajuste"}),
        ({"to_date": date(2026, 9, 30)}, {"septiembre"}),
        ({"q": "exito"}, {"mercado"}),  # sin tildes
        ({"q": "MERCADO"}, {"mercado"}),  # nombre de la categoría y descripción
        ({"q": "café"}, {"septiembre"}),
        ({"q": "restaurant"}, {"cena", "septiembre"}),  # categoría
        ({"q": "orbita"}, {"cena", "pago"}),  # cuenta como origen o destino
        ({"q": "50%"}, {"pago"}),  # % literal en la nota
        ({"q": "%"}, {"pago"}),
        ({"q": "_"}, set()),
        ({"q": "   "}, None),  # sin texto: sin filtro
        ({"q": "no existe"}, set()),
    ],
)
def test_filtros(
    db_session: Session,
    ana: User,
    mes: dict[str, Transaction],
    filtros: dict[str, Any],
    esperados: set[str] | None,
) -> None:
    pagina = _listar(db_session, ana, **filtros)
    nombres = {n for n, mov in mes.items() if mov.id in set(_ids(pagina))}
    assert nombres == (set(mes) if esperados is None else esperados)
    assert pagina.total == len(nombres)


def test_filtro_por_cuenta_incluye_destino(
    db_session: Session, ana: User, c: Cuentas, mes: dict[str, Transaction]
) -> None:
    pagina = _listar(db_session, ana, account_id=c.efectivo.id)
    assert set(_ids(pagina)) == {mes["retiro"].id, mes["ajuste"].id, mes["septiembre"].id}
    # El retiro a efectivo es una transferencia; el café de septiembre, un gasto.
    assert _resumen(pagina) == (3, 0, 5_000, 0, 200_000)


def test_filtro_combinado_y_resumen_de_ahorro(
    db_session: Session, ana: User, c: Cuentas, mes: dict[str, Transaction]
) -> None:
    pagina = _listar(db_session, ana, account_id=c.cdt.id, type=TransactionType.TRANSFER)
    assert set(_ids(pagina)) == {mes["ahorro"].id, mes["uso_cdt"].id}
    assert _resumen(pagina) == (2, 0, 0, 400_000, 0)


def test_cuenta_ajena_en_el_filtro(
    db_session: Session, ana: User, clock: FrozenClock, mes: dict[str, Transaction]
) -> None:
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    de_luis = _cuenta(db_session, luis, clock, name="Nómina", type="bank", opening_balance="1")
    bind_user(db_session, ana.id)
    pagina = _listar(db_session, ana, account_id=de_luis.id)
    assert (pagina.items, pagina.total) == ([], 0)
    assert _resumen(pagina) == (0, 0, 0, 0, 0)


def test_orden_por_monto_absoluto(
    db_session: Session, ana: User, mes: dict[str, Transaction]
) -> None:
    pagina = _listar(db_session, ana, sort=Sort.AMOUNT_DESC, limit=3)
    assert _ids(pagina) == [mes["salario"].id, mes["pago"].id, mes["ahorro"].id]
    ascendente = _listar(db_session, ana, sort=Sort.AMOUNT_ASC, limit=2)
    # El ajuste es de -15.000: por valor absoluto va justo después del café de 5.000.
    assert _ids(ascendente) == [mes["septiembre"].id, mes["ajuste"].id]


def test_precision_del_resumen(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock
) -> None:
    """CA-TRX-12."""
    for monto in ("0.10", "0.20"):
        _crear(db_session, ana, clock, type="income", account_id=c.nomina, amount=monto)
    pagina = _listar(db_session, ana)
    assert pagina.summary.income.amount == Decimal("0.30")
    assert _saldo(db_session, ana, c.nomina).amount == Decimal("2800000.30")


# --- Paginación por cursor (DP-API-06, CA-TRX-10) -----------------------------------------


@pytest.fixture
def sesenta(db_session: Session, ana: User, c: Cuentas, clock: FrozenClock) -> list[Transaction]:
    """60 gastos en "Nómina" (varios por día y con la misma hora) y 5 en "Efectivo"."""
    movs = []
    for n in range(60):
        movs.append(
            _crear(
                db_session,
                ana,
                clock,
                account_id=c.nomina,
                amount=str(1000 + n % 7),
                date=f"2026-10-{1 + n % 20:02d}",
            )
        )
    for _ in range(5):
        _crear(db_session, ana, clock, account_id=c.efectivo, amount="1")
    return movs


@pytest.mark.parametrize("orden", list(Sort))
def test_recorre_todas_las_paginas_sin_repetir(
    db_session: Session, ana: User, c: Cuentas, sesenta: list[Transaction], orden: Sort
) -> None:
    filtros = Filters(account_id=c.nomina.id)
    vistos: list[Any] = []
    cursor = None
    paginas = 0
    while True:
        pagina = service.list_transactions(
            db_session, ana.id, filtros, orden, cursor=cursor, limit=25
        )
        assert pagina.total == 60
        assert pagina.summary.expense.amount == sum(m.amount for m in sesenta)
        vistos += _ids(pagina)
        paginas += 1
        cursor = pagina.next_cursor
        if cursor is None:
            break
    assert paginas == 3
    assert len(vistos) == len(set(vistos)) == 60
    assert set(vistos) == {m.id for m in sesenta}


def test_primera_pagina_de_50(
    db_session: Session, ana: User, c: Cuentas, sesenta: list[Transaction]
) -> None:
    """CA-TRX-10: 50 y luego los otros 10."""
    filtros = Filters(account_id=c.nomina.id)
    primera = service.list_transactions(db_session, ana.id, filtros)
    segunda = service.list_transactions(db_session, ana.id, filtros, cursor=primera.next_cursor)
    assert (len(primera.items), len(segunda.items), segunda.next_cursor) == (50, 10, None)


def test_un_movimiento_nuevo_no_desordena_la_paginacion(
    db_session: Session, ana: User, c: Cuentas, clock: FrozenClock, sesenta: list[Transaction]
) -> None:
    filtros = Filters(account_id=c.nomina.id)
    primera = service.list_transactions(db_session, ana.id, filtros, limit=30)
    _crear(db_session, ana, clock, account_id=c.nomina, date=HOY)  # queda al principio
    segunda = service.list_transactions(
        db_session, ana.id, filtros, cursor=primera.next_cursor, limit=30
    )
    assert set(_ids(primera)) | set(_ids(segunda)) == {m.id for m in sesenta}


@pytest.mark.parametrize(
    "cursor",
    [
        "basura",
        "",
        "eyJzIjoiZGF0ZV9kZXNjIn0",
        "e30",
        "!!!",
        "eyJzIjoiZGF0ZV9kZXNjIiwiZiI6IngiLCJrIjpbXX0",
    ],
)
def test_cursor_invalido(
    db_session: Session, ana: User, sesenta: list[Transaction], cursor: str
) -> None:
    error = _error(service.list_transactions, db_session, ana.id, Filters(), cursor=cursor)
    assert _campo(error) == (422, "validation_failed", "cursor", service.CURSOR_MESSAGE)


def test_cursor_de_otro_orden_o_filtro(
    db_session: Session, ana: User, c: Cuentas, sesenta: list[Transaction]
) -> None:
    cursor = service.list_transactions(db_session, ana.id, Filters(), limit=10).next_cursor
    assert cursor is not None
    for filtros, orden in (
        (Filters(), Sort.DATE_ASC),
        (Filters(account_id=c.nomina.id), Sort.DATE_DESC),
        (Filters(q="cafe"), Sort.DATE_DESC),
    ):
        error = _error(service.list_transactions, db_session, ana.id, filtros, orden, cursor=cursor)
        assert _campo(error)[2] == "cursor"


def test_rango_de_fechas_invertido(db_session: Session, ana: User) -> None:
    error = _error(
        _listar, db_session, ana, from_date=date(2026, 10, 31), to_date=date(2026, 10, 1)
    )
    assert _campo(error) == (422, "validation_failed", "from", service.RANGE_MESSAGE)
