"""Saldos reales en /api/v1/accounts (T-TRX-BE-03): CA-TRX-01 a 08 vía HTTP.

Los movimientos se crean con el servicio (los endpoints llegan en BE-04); saldos, totales,
tarjetas y `has_movements` se comprueban en la respuesta de /accounts.
"""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from finora.accounts import service as accounts
from finora.accounts.schemas import CreateAccountRequest
from finora.auth.models import User
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock
from finora.db.rls import bind_user
from finora.transactions import service
from finora.transactions.models import Transaction
from finora.transactions.schemas import TransactionRequest

URL = "/api/v1/accounts"
HOY = "2026-10-29"


def _usuario(db: Session, clock: FrozenClock, email: str) -> User:
    user = User(
        email=email, name=email.split("@")[0], email_verified_at=clock.now(), created_at=clock.now()
    )
    db.add(user)
    db.flush()
    return user


def _entrar(client: TestClient, db: Session, user: User, clock: FrozenClock) -> dict[str, str]:
    raw, sesion = create_session(db, user.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    return _usuario(db_session, clock, "ana@correo.com")


@pytest.fixture
def csrf(client: TestClient, db_session: Session, ana: User, clock: FrozenClock) -> dict[str, str]:
    return _entrar(client, db_session, ana, clock)


@pytest.fixture
def ids(client: TestClient, csrf: dict[str, str]) -> dict[str, str]:
    """CA-ACC-01: Nómina, Efectivo, CDT y Tarjeta Órbita."""
    cuentas: list[dict[str, Any]] = [
        {"name": "Nómina", "type": "bank", "opening_balance": "2800000"},
        {"name": "Efectivo", "type": "cash", "opening_balance": "90000"},
        {"name": "CDT", "type": "investment", "opening_balance": "12000000"},
        {
            "name": "Tarjeta Órbita",
            "type": "credit_card",
            "opening_balance": "820000",
            "credit_limit": "6000000",
            "statement_day": 28,
            "payment_due_day": 18,
        },
    ]
    creadas: dict[str, str] = {}
    for datos in cuentas:
        response = client.post(URL, json=datos, headers=csrf)
        assert response.status_code == 201, response.text
        creadas[datos["name"]] = response.json()["id"]
    return creadas


def _mov(db: Session, user: User, clock: FrozenClock, **datos: Any) -> Transaction:
    bind_user(db, user.id)
    peticion = TransactionRequest.model_validate({"date": HOY, **datos})
    return service.create_transaction(db, user.id, peticion, clock.now())


def _gasto(cuenta: str, monto: str, categoria: str = "groceries") -> dict[str, Any]:
    return {
        "type": "expense",
        "account_id": cuenta,
        "amount": monto,
        "category": categoria,
        "description": "Compra",
    }


def _transferencia(origen: str, destino: str, monto: str) -> dict[str, Any]:
    return {
        "type": "transfer",
        "account_id": origen,
        "destination_account_id": destino,
        "amount": monto,
    }


def _estado(client: TestClient) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    response = client.get(URL)
    assert response.status_code == 200
    body = response.json()
    return {a["name"]: a for a in body["accounts"]}, body["totals"]


def _totales(disponible: str, patrimonio: str, deuda: str) -> dict[str, str]:
    return {"available_balance": disponible, "net_worth": patrimonio, "credit_card_debt": deuda}


def test_sin_movimientos(client: TestClient, ids: dict[str, str]) -> None:
    cuentas, totales = _estado(client)
    assert totales == _totales("2890000.00", "14070000.00", "820000.00")
    assert not any(a["has_movements"] for a in cuentas.values())


def test_ca_trx_01_gasto(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(db_session, ana, clock, **_gasto(ids["Nómina"], "120000"))
    cuentas, totales = _estado(client)
    assert cuentas["Nómina"]["balance"] == "2680000.00"
    assert cuentas["Nómina"]["opening_balance"] == "2800000.00"
    assert cuentas["Nómina"]["has_movements"] is True
    assert cuentas["Efectivo"]["has_movements"] is False
    assert totales == _totales("2770000.00", "13950000.00", "820000.00")


def test_ca_trx_02_transferencia_entre_cuentas_liquidas(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], ids["Efectivo"], "200000"))
    cuentas, totales = _estado(client)
    assert (cuentas["Nómina"]["balance"], cuentas["Efectivo"]["balance"]) == (
        "2600000.00",
        "290000.00",
    )
    assert cuentas["Efectivo"]["has_movements"] is True  # también como destino
    assert totales == _totales("2890000.00", "14070000.00", "820000.00")


def test_ca_trx_03_ahorro(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], ids["CDT"], "500000"))
    cuentas, totales = _estado(client)
    assert cuentas["CDT"]["balance"] == "12500000.00"
    assert totales == _totales("2390000.00", "14070000.00", "820000.00")


def test_ca_trx_04_compra_con_tarjeta(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(db_session, ana, clock, **_gasto(ids["Tarjeta Órbita"], "300000", "restaurants"))
    cuentas, totales = _estado(client)
    tarjeta = cuentas["Tarjeta Órbita"]
    assert tarjeta["balance"] == "1120000.00"
    assert tarjeta["credit_card"]["available_credit"] == "4880000.00"
    assert tarjeta["credit_card"]["usage_percent"] == 19
    assert totales == _totales("2890000.00", "13770000.00", "1120000.00")


def test_ca_trx_05_pago_de_tarjeta(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], ids["Tarjeta Órbita"], "820000"))
    cuentas, totales = _estado(client)
    assert cuentas["Tarjeta Órbita"]["balance"] == "0.00"
    assert cuentas["Tarjeta Órbita"]["credit_card"]["available_credit"] == "6000000.00"
    assert totales == _totales("2070000.00", "14070000.00", "0.00")


def test_pago_mayor_que_la_deuda_y_cupo_superado(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    tarjeta = ids["Tarjeta Órbita"]
    _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], tarjeta, "1000000"))
    cuentas, totales = _estado(client)
    assert cuentas["Tarjeta Órbita"]["balance"] == "-180000.00"  # saldo a favor
    assert totales["credit_card_debt"] == "0.00"

    _mov(db_session, ana, clock, **_gasto(tarjeta, "6500000"))
    cuentas, _ = _estado(client)
    assert cuentas["Tarjeta Órbita"]["credit_card"]["over_limit"] is True


def test_ca_trx_06_ajuste(
    client: TestClient, db_session: Session, ana: User, clock: FrozenClock, ids: dict[str, str]
) -> None:
    _mov(
        db_session,
        ana,
        clock,
        type="adjustment",
        account_id=ids["Efectivo"],
        target_balance="75000",
    )
    cuentas, totales = _estado(client)
    assert cuentas["Efectivo"]["balance"] == "75000.00"
    assert totales["net_worth"] == "14055000.00"


def test_ca_trx_07_editar_y_eliminar(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    ids: dict[str, str],
    csrf: dict[str, str],
) -> None:
    nomina = ids["Nómina"]
    mov = _mov(db_session, ana, clock, **_gasto(nomina, "120000"))
    peticion = TransactionRequest.model_validate({"date": HOY, **_gasto(nomina, "100000")})
    bind_user(db_session, ana.id)  # cada petición HTTP fija y suelta su propio usuario
    service.replace_transaction(db_session, ana.id, mov.id, peticion, clock.now())
    assert client.get(f"{URL}/{nomina}").json()["balance"] == "2700000.00"

    bind_user(db_session, ana.id)
    service.delete_transaction(db_session, ana.id, mov.id)
    cuenta = client.get(f"{URL}/{nomina}").json()
    assert (cuenta["balance"], cuenta["has_movements"]) == ("2800000.00", False)
    # Sin movimientos, el saldo inicial vuelve a ser editable.
    response = client.patch(f"{URL}/{nomina}", json={"opening_balance": "2900000"}, headers=csrf)
    assert response.status_code == 200
    assert response.json()["balance"] == "2900000.00"


@pytest.mark.parametrize("papel", ["origen", "destino"])
def test_ca_trx_08_cuenta_con_movimientos(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    ids: dict[str, str],
    csrf: dict[str, str],
    papel: str,
) -> None:
    """VAL-ACC-07 y 08 con movimientos reales; archivarla sí se puede."""
    efectivo = ids["Efectivo"]
    if papel == "origen":
        _mov(db_session, ana, clock, **_transferencia(efectivo, ids["Nómina"], "1000"))
    else:
        _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], efectivo, "1000"))

    editar = client.patch(f"{URL}/{efectivo}", json={"opening_balance": "1"}, headers=csrf)
    assert (editar.status_code, editar.json()["code"]) == (409, "account_has_movements")
    # Mismo saldo inicial: no es un cambio, no hay conflicto.
    igual = client.patch(f"{URL}/{efectivo}", json={"opening_balance": "90000"}, headers=csrf)
    assert igual.status_code == 200

    borrar = client.request("DELETE", f"{URL}/{efectivo}", json={}, headers=csrf)
    assert (borrar.status_code, borrar.json()["code"]) == (409, "account_has_movements")

    archivar = client.post(f"{URL}/{efectivo}/archive", json={}, headers=csrf)
    assert (archivar.status_code, archivar.json()["has_movements"]) == (200, True)


def test_cuenta_archivada_conserva_su_saldo_pero_no_suma(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    ids: dict[str, str],
    csrf: dict[str, str],
) -> None:
    _mov(db_session, ana, clock, **_transferencia(ids["Nómina"], ids["Efectivo"], "200000"))
    client.post(f"{URL}/{ids['Efectivo']}/archive", json={}, headers=csrf)
    cuentas, totales = _estado(client)
    assert cuentas["Efectivo"]["balance"] == "290000.00"
    assert totales["available_balance"] == "2600000.00"  # solo Nómina


def test_los_movimientos_de_otro_usuario_no_cuentan(
    client: TestClient,
    db_session: Session,
    ana: User,
    clock: FrozenClock,
    ids: dict[str, str],
) -> None:
    """CA-TRX-11 en los saldos."""
    luis = _usuario(db_session, clock, "luis@correo.com")
    bind_user(db_session, luis.id)
    cuenta = accounts.create_account(
        db_session,
        luis.id,
        CreateAccountRequest.model_validate(
            {"name": "Nómina", "type": "bank", "opening_balance": "100"}
        ),
        clock.now(),
    )
    _mov(db_session, luis, clock, **_gasto(str(cuenta.id), "50"))

    cuentas, totales = _estado(client)  # la sesión del cliente es de Ana
    assert cuentas["Nómina"]["id"] == ids["Nómina"]
    assert cuentas["Nómina"]["balance"] == "2800000.00"
    assert totales["available_balance"] == "2890000.00"
    assert uuid.UUID(ids["Nómina"]) != cuenta.id
