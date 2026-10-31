"""Endpoints /api/v1/transactions (T-TRX-BE-04): CA-TRX-01 a 12 vía HTTP, api-contracts.md §6.

El reloj de las pruebas marca el jueves 29/10/2026, 10:00 en Bogotá.
"""

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from finora.auth.models import User
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock

URL = "/api/v1/transactions"
ACCOUNTS = "/api/v1/accounts"
HOY = "2026-10-29"
NO_EXISTE = "0193a1b2-0000-7000-8000-000000000000"


def _usuario(db: Session, clock: FrozenClock, email: str) -> User:
    user = User(
        email=email, name=email.split("@")[0], email_verified_at=clock.now(), created_at=clock.now()
    )
    db.add(user)
    db.flush()
    return user


def _entrar(client: TestClient, db: Session, user: User, clock: FrozenClock) -> dict[str, str]:
    """Deja la cookie de sesión de `user` en el cliente y devuelve la cabecera CSRF."""
    raw, sesion = create_session(db, user.id, SessionStage.ACTIVE, clock.now())
    client.cookies.set(COOKIE_NAME, raw)
    return {"X-CSRF-Token": sesion.csrf_token}


@pytest.fixture
def ana(db_session: Session, clock: FrozenClock) -> User:
    return _usuario(db_session, clock, "ana@correo.com")


@pytest.fixture
def csrf(client: TestClient, db_session: Session, ana: User, clock: FrozenClock) -> dict[str, str]:
    return _entrar(client, db_session, ana, clock)


def _crear_cuentas(client: TestClient, csrf: dict[str, str]) -> dict[str, str]:
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
    ids: dict[str, str] = {}
    for datos in cuentas:
        response = client.post(ACCOUNTS, json=datos, headers=csrf)
        assert response.status_code == 201, response.text
        ids[datos["name"]] = response.json()["id"]
    return ids


@pytest.fixture
def ids(client: TestClient, csrf: dict[str, str]) -> dict[str, str]:
    return _crear_cuentas(client, csrf)


def _gasto(cuenta: str, monto: str = "120000", **otros: Any) -> dict[str, Any]:
    return {
        "type": "expense",
        "amount": monto,
        "date": HOY,
        "account_id": cuenta,
        "category": "groceries",
        "description": "Mercado",
        **otros,
    }


def _transferencia(origen: str, destino: str, monto: str) -> dict[str, Any]:
    return {
        "type": "transfer",
        "amount": monto,
        "date": HOY,
        "account_id": origen,
        "destination_account_id": destino,
    }


def _crear(client: TestClient, csrf: dict[str, str], datos: dict[str, Any]) -> dict[str, Any]:
    response = client.post(URL, json=datos, headers=csrf)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _listar(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get(URL, params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _error_de_campo(response: Any) -> tuple[int, list[str], str | None]:
    body = response.json()
    [detalle] = body["errors"]
    return response.status_code, detalle["loc"], detalle.get("message")


def _cuentas(client: TestClient) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    body = client.get(ACCOUNTS).json()
    return {a["name"]: a for a in body["accounts"]}, body["totals"]


# --- Sesión, CSRF y caché -----------------------------------------------------------------


def test_sin_sesion(client: TestClient) -> None:
    for metodo, url in (
        ("GET", URL),
        ("POST", URL),
        ("GET", f"{URL}/{NO_EXISTE}"),
        ("PUT", f"{URL}/{NO_EXISTE}"),
        ("DELETE", f"{URL}/{NO_EXISTE}"),
    ):
        response = client.request(metodo, url, json={} if metodo != "GET" else None)
        assert response.status_code == 401, (metodo, url)


def test_escrituras_sin_csrf(client: TestClient, csrf: dict[str, str], ids: dict[str, str]) -> None:
    mov = _crear(client, csrf, _gasto(ids["Nómina"]))
    url = f"{URL}/{mov['id']}"
    assert client.post(URL, json=_gasto(ids["Nómina"])).status_code == 403
    assert client.put(url, json=_gasto(ids["Nómina"])).status_code == 403
    assert client.request("DELETE", url, json={}).status_code == 403
    assert _listar(client)["total"] == 1


def test_no_store(client: TestClient, csrf: dict[str, str], ids: dict[str, str]) -> None:
    assert client.get(URL).headers["Cache-Control"] == "no-store"
    mov = _crear(client, csrf, _gasto(ids["Nómina"]))
    assert client.get(f"{URL}/{mov['id']}").headers["Cache-Control"] == "no-store"


# --- Crear y el modelo `Transaction` (§6.2) -----------------------------------------------


def test_ca_trx_01_gasto(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str], clock: FrozenClock
) -> None:
    mov = _crear(client, csrf, _gasto(ids["Nómina"], note="Semana 1"))
    assert mov == {
        "id": mov["id"],
        "type": "expense",
        "amount": "120000.00",
        "date": HOY,
        "account_id": ids["Nómina"],
        "destination_account_id": None,
        "category": "groceries",
        "description": "Mercado",
        "note": "Semana 1",
        "created_at": "2026-10-29T15:00:00Z",
        "updated_at": "2026-10-29T15:00:00Z",
    }
    cuentas, totales = _cuentas(client)
    assert cuentas["Nómina"]["balance"] == "2680000.00"
    assert (totales["available_balance"], totales["net_worth"]) == ("2770000.00", "13950000.00")
    assert _listar(client, **{"from": "2026-10-01", "to": "2026-10-31"})["summary"] == {
        "count": 1,
        "income": "0.00",
        "expense": "120000.00",
        "savings": "0.00",
        "transfers": "0.00",
    }


def test_ca_trx_02_a_05_transferencias(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str]
) -> None:
    _crear(client, csrf, _transferencia(ids["Nómina"], ids["Efectivo"], "200000"))  # 02
    _crear(client, csrf, _transferencia(ids["Nómina"], ids["CDT"], "500000"))  # 03
    _crear(client, csrf, _gasto(ids["Tarjeta Órbita"], "300000", category="restaurants"))  # 04
    pago = _crear(client, csrf, _transferencia(ids["Nómina"], ids["Tarjeta Órbita"], "1120000"))
    assert (pago["category"], pago["description"]) == (None, None)

    cuentas, totales = _cuentas(client)
    assert cuentas["Tarjeta Órbita"]["balance"] == "0.00"  # 05
    assert cuentas["Nómina"]["balance"] == "980000.00"
    assert totales == {
        "available_balance": "1270000.00",
        "net_worth": "13770000.00",  # solo baja por la compra con tarjeta
        "credit_card_debt": "0.00",
    }
    assert _listar(client)["summary"] == {
        "count": 4,
        "income": "0.00",
        "expense": "300000.00",
        "savings": "500000.00",
        "transfers": "1320000.00",
    }


def test_ca_trx_06_ajuste(client: TestClient, csrf: dict[str, str], ids: dict[str, str]) -> None:
    datos = {
        "type": "adjustment",
        "target_balance": "75000",
        "date": HOY,
        "account_id": ids["Efectivo"],
    }
    mov = _crear(client, csrf, datos)
    assert (mov["amount"], mov["category"]) == ("-15000.00", None)
    cuentas, totales = _cuentas(client)
    assert cuentas["Efectivo"]["balance"] == "75000.00"
    assert totales["net_worth"] == "14055000.00"
    resumen = _listar(client)["summary"]
    assert (resumen["count"], resumen["income"], resumen["expense"]) == (1, "0.00", "0.00")

    igual = client.post(URL, json=datos, headers=csrf)
    assert _error_de_campo(igual) == (
        422,
        ["body", "target_balance"],
        "Ese ya es el saldo de la cuenta.",
    )


# --- Validaciones (CA-TRX-09, VAL-TRX-01 a 11) --------------------------------------------


@pytest.mark.parametrize(
    ("cambios", "campo", "mensaje"),
    [
        ({"date": "2026-10-30"}, "date", "Elige una fecha entre el 01/01/2000 y hoy."),
        ({"category": None}, "category", "Elige una categoría."),
        ({"category": "salary"}, "category", "Elige una categoría."),
        ({"account_id": NO_EXISTE}, "account_id", "Elige una de tus cuentas."),
        ({"destination_account_id": "ids:Efectivo"}, "destination_account_id", None),
        ({"amount": 120000}, "amount", None),  # número JSON
        ({"amount": "0"}, "amount", None),
        ({"date": "29/10/2026"}, "date", None),
        ({"description": "x" * 81}, "description", None),
        ({"moneda": "COP"}, "moneda", None),
    ],
)
def test_validaciones(
    client: TestClient,
    csrf: dict[str, str],
    ids: dict[str, str],
    cambios: dict[str, Any],
    campo: str,
    mensaje: str | None,
) -> None:
    datos = _gasto(ids["Nómina"])
    for clave, valor in cambios.items():
        datos[clave] = (
            ids[valor[4:]] if isinstance(valor, str) and valor.startswith("ids:") else valor
        )
    estado, loc, texto = _error_de_campo(client.post(URL, json=datos, headers=csrf))
    assert (estado, loc) == (422, ["body", campo])
    if mensaje is not None:
        assert texto == mensaje
    assert _listar(client)["total"] == 0


def test_transferencia_a_la_misma_cuenta_y_cuenta_archivada(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str]
) -> None:
    misma = client.post(URL, json=_transferencia(ids["Nómina"], ids["Nómina"], "1"), headers=csrf)
    assert _error_de_campo(misma) == (
        422,
        ["body", "destination_account_id"],
        "Elige una cuenta de destino distinta a la de origen.",
    )
    client.post(f"{ACCOUNTS}/{ids['Efectivo']}/archive", json={}, headers=csrf)
    archivada = client.post(URL, json=_gasto(ids["Efectivo"]), headers=csrf)
    assert _error_de_campo(archivada) == (
        422,
        ["body", "account_id"],
        "Esta cuenta está archivada. Reactívala para registrar movimientos.",
    )


# --- Consultar, reemplazar y eliminar (RF-TRX-07 y 08, CA-TRX-07) -------------------------


def test_ca_trx_07_consultar_reemplazar_y_eliminar(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str], clock: FrozenClock
) -> None:
    mov = _crear(client, csrf, _gasto(ids["Nómina"]))
    url = f"{URL}/{mov['id']}"
    assert client.get(url).json() == mov

    clock.advance(timedelta(minutes=5))  # dentro de la sesión (expira por inactividad)
    response = client.put(url, json=_gasto(ids["Nómina"], "100000"), headers=csrf)
    assert response.status_code == 200
    editado = response.json()
    assert (editado["amount"], editado["created_at"], editado["updated_at"]) == (
        "100000.00",
        "2026-10-29T15:00:00Z",
        "2026-10-29T15:05:00Z",
    )
    assert _cuentas(client)[0]["Nómina"]["balance"] == "2700000.00"

    # Cambiar el tipo: pasa a transferencia hacia el CDT.
    transferencia = client.put(
        url, json=_transferencia(ids["Nómina"], ids["CDT"], "100000"), headers=csrf
    ).json()
    assert (transferencia["type"], transferencia["category"]) == ("transfer", None)

    borrado = client.request("DELETE", url, json={}, headers=csrf)
    assert (borrado.status_code, borrado.content) == (204, b"")
    no_esta = client.get(url)
    assert (no_esta.status_code, no_esta.json()["code"], no_esta.json()["title"]) == (
        404,
        "transaction_not_found",
        "No encontramos ese movimiento.",
    )
    cuenta = _cuentas(client)[0]["Nómina"]
    assert (cuenta["balance"], cuenta["has_movements"]) == ("2800000.00", False)


@pytest.mark.parametrize("metodo", ["GET", "PUT", "DELETE"])
def test_id_inexistente_o_invalido(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str], metodo: str
) -> None:
    cuerpo = _gasto(ids["Nómina"]) if metodo == "PUT" else ({} if metodo == "DELETE" else None)
    inexistente = client.request(metodo, f"{URL}/{NO_EXISTE}", json=cuerpo, headers=csrf)
    assert (inexistente.status_code, inexistente.json()["code"]) == (404, "transaction_not_found")
    invalido = client.request(metodo, f"{URL}/no-es-uuid", json=cuerpo, headers=csrf)
    assert invalido.status_code == 422


# --- Aislamiento (CA-TRX-11) --------------------------------------------------------------


def test_ca_trx_11_aislamiento(
    client: TestClient,
    db_session: Session,
    clock: FrozenClock,
    csrf: dict[str, str],
    ids: dict[str, str],
) -> None:
    mov_ana = _crear(client, csrf, _gasto(ids["Nómina"]))
    url_ana = f"{URL}/{mov_ana['id']}"

    luis = _usuario(db_session, clock, "luis@correo.com")
    csrf_luis = _entrar(client, db_session, luis, clock)
    nomina_luis = client.post(
        ACCOUNTS, json={"name": "Nómina", "type": "bank", "opening_balance": "1"}, headers=csrf_luis
    ).json()["id"]

    assert client.get(url_ana).status_code == 404
    assert client.put(url_ana, json=_gasto(nomina_luis), headers=csrf_luis).status_code == 404
    assert client.request("DELETE", url_ana, json={}, headers=csrf_luis).status_code == 404
    ajena = client.post(URL, json=_gasto(ids["Nómina"]), headers=csrf_luis)
    assert _error_de_campo(ajena)[:2] == (422, ["body", "account_id"])
    hacia_ajena = client.post(
        URL, json=_transferencia(nomina_luis, ids["Efectivo"], "1"), headers=csrf_luis
    )
    assert _error_de_campo(hacia_ajena)[:2] == (422, ["body", "destination_account_id"])
    assert _listar(client)["total"] == 0
    assert _listar(client, account_id=ids["Nómina"])["total"] == 0


# --- Listado: filtros, orden y cursor (RF-TRX-04 a 06, CA-TRX-10 y 12) --------------------


def test_filtros_por_query(client: TestClient, csrf: dict[str, str], ids: dict[str, str]) -> None:
    mercado = _crear(
        client, csrf, _gasto(ids["Nómina"], description="Mercado Éxito", date="2026-10-05")
    )
    cena = _crear(
        client,
        csrf,
        _gasto(ids["Tarjeta Órbita"], "300000", category="restaurants", description="Cena"),
    )
    retiro = _crear(client, csrf, _transferencia(ids["Nómina"], ids["Efectivo"], "200000"))

    def ids_de(**params: Any) -> list[str]:
        return [m["id"] for m in _listar(client, **params)["items"]]

    assert ids_de() == [retiro["id"], cena["id"], mercado["id"]]
    assert ids_de(q="exito") == [mercado["id"]]
    assert ids_de(q="órbita") == [cena["id"]]
    assert ids_de(type="transfer") == [retiro["id"]]
    assert ids_de(category="restaurants") == [cena["id"]]
    assert ids_de(account_id=ids["Efectivo"]) == [retiro["id"]]
    assert ids_de(**{"from": "2026-10-06"}) == [retiro["id"], cena["id"]]
    assert ids_de(**{"to": "2026-10-05"}) == [mercado["id"]]
    assert ids_de(sort="amount_desc") == [cena["id"], retiro["id"], mercado["id"]]
    assert ids_de(sort="date_asc", limit=1) == [mercado["id"]]


@pytest.mark.parametrize(
    ("params", "loc"),
    [
        ({"from": "2026-10-31", "to": "2026-10-01"}, ["query", "from"]),
        ({"from": "31/10/2026"}, ["query", "from"]),
        ({"to": "1700000000"}, ["query", "to"]),
        ({"limit": 0}, ["query", "limit"]),
        ({"limit": 101}, ["query", "limit"]),
        ({"q": "x" * 101}, ["query", "q"]),
        ({"type": "gasto"}, ["query", "type"]),
        ({"category": "otra"}, ["query", "category"]),
        ({"sort": "name"}, ["query", "sort"]),
        ({"account_id": "123"}, ["query", "account_id"]),
        ({"cursor": "basura"}, ["query", "cursor"]),
        ({"cursor": "x" * 513}, ["query", "cursor"]),
    ],
)
def test_parametros_invalidos(
    client: TestClient, csrf: dict[str, str], params: dict[str, Any], loc: list[str]
) -> None:
    response = client.get(URL, params=params)
    assert response.status_code == 422
    assert [e["loc"] for e in response.json()["errors"]] == [loc]


def test_ca_trx_10_paginacion(
    client: TestClient, csrf: dict[str, str], ids: dict[str, str]
) -> None:
    for n in range(60):
        _crear(client, csrf, _gasto(ids["Nómina"], str(1000 + n), date=f"2026-10-{1 + n % 28:02d}"))
    _crear(client, csrf, _gasto(ids["Efectivo"], "1"))

    # Sin `limit`: 50 por página.
    primera = _listar(client, account_id=ids["Nómina"], **{"from": "2026-10-01"})
    assert (len(primera["items"]), primera["total"]) == (50, 60)
    assert primera["next_cursor"] is not None
    segunda = _listar(
        client, account_id=ids["Nómina"], cursor=primera["next_cursor"], **{"from": "2026-10-01"}
    )
    assert (len(segunda["items"]), segunda["total"], segunda["next_cursor"]) == (10, 60, None)
    vistos = {m["id"] for m in primera["items"] + segunda["items"]}
    assert len(vistos) == 60
    esperado = sum(1000 + n for n in range(60))
    assert primera["summary"] == segunda["summary"]
    assert primera["summary"]["expense"] == f"{esperado}.00"

    # El cursor no sirve con otros filtros.
    otro = client.get(URL, params={"cursor": primera["next_cursor"]})
    assert otro.status_code == 422


def test_ca_trx_12_precision(client: TestClient, csrf: dict[str, str], ids: dict[str, str]) -> None:
    for monto in ("0.10", "0.20"):
        _crear(
            client,
            csrf,
            {
                "type": "income",
                "amount": monto,
                "date": HOY,
                "account_id": ids["Nómina"],
                "category": "other_income",
                "description": "Intereses",
            },
        )
    assert _listar(client)["summary"]["income"] == "0.30"
    assert _cuentas(client)[0]["Nómina"]["balance"] == "2800000.30"
