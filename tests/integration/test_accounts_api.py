"""Endpoints /api/v1/accounts (T-ACC-BE-03): CA-ACC-01 a 08 vía HTTP, api-contracts.md §5."""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from finora.auth.models import User
from finora.auth.sessions import COOKIE_NAME, SessionStage, create_session
from finora.clock import FrozenClock

URL = "/api/v1/accounts"
TARJETA = {
    "name": "Tarjeta Órbita",
    "type": "credit_card",
    "institution": "Banco Andino",
    "opening_balance": "820000",
    "credit_limit": "6000000",
    "statement_day": 28,
    "payment_due_day": 18,
}


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


def _crear(client: TestClient, csrf: dict[str, str], **datos: Any) -> dict[str, Any]:
    response = client.post(URL, json=datos, headers=csrf)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _listado(client: TestClient) -> dict[str, Any]:
    response = client.get(URL)
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


# --- CA-ACC-01 a 03 -----------------------------------------------------------------------


def test_ca_acc_01_y_02_crear_cuentas_y_ver_totales(
    client: TestClient, csrf: dict[str, str]
) -> None:
    _crear(client, csrf, name="Nómina", type="bank", opening_balance="2800000")
    _crear(client, csrf, name="Efectivo", type="cash", opening_balance="90000")
    _crear(client, csrf, name="CDT", type="investment", opening_balance="12000000")
    tarjeta = _crear(client, csrf, **TARJETA)

    assert tarjeta == {
        "id": tarjeta["id"],
        "name": "Tarjeta Órbita",
        "type": "credit_card",
        "institution": "Banco Andino",
        "opening_balance": "820000.00",
        "balance": "820000.00",
        "has_movements": False,
        "archived": False,
        "credit_card": {
            "credit_limit": "6000000.00",
            "available_credit": "5180000.00",
            "usage_percent": 14,
            "over_limit": False,
            "statement_day": 28,
            "payment_due_day": 18,
        },
        "created_at": "2026-10-29T15:00:00Z",
    }

    listado = _listado(client)
    assert listado["totals"] == {
        "available_balance": "2890000.00",
        "net_worth": "14070000.00",
        "credit_card_debt": "820000.00",
    }
    assert [(c["name"], c["type"]) for c in listado["accounts"]] == [
        ("Nómina", "bank"),
        ("Efectivo", "cash"),
        ("CDT", "investment"),
        ("Tarjeta Órbita", "credit_card"),
    ]
    assert listado["accounts"][0]["credit_card"] is None
    assert listado["accounts"][0]["institution"] is None


def test_ca_acc_03_el_cupo_no_es_saldo_disponible(client: TestClient, csrf: dict[str, str]) -> None:
    _crear(client, csrf, **{**TARJETA, "opening_balance": "0"})
    assert _listado(client)["totals"] == {
        "available_balance": "0.00",
        "net_worth": "0.00",
        "credit_card_debt": "0.00",
    }


def test_sin_cuentas(client: TestClient, csrf: dict[str, str]) -> None:
    assert _listado(client) == {
        "accounts": [],
        "totals": {"available_balance": "0.00", "net_worth": "0.00", "credit_card_debt": "0.00"},
    }


def test_ca_acc_07_precision(client: TestClient, csrf: dict[str, str]) -> None:
    _crear(client, csrf, name="A", type="bank", opening_balance="0.10")
    _crear(client, csrf, name="B", type="wallet", opening_balance="0.20")
    assert _listado(client)["totals"]["available_balance"] == "0.30"


def test_val_acc_10_cupo_superado(client: TestClient, csrf: dict[str, str]) -> None:
    tarjeta = _crear(client, csrf, **{**TARJETA, "opening_balance": "7000000"})
    assert tarjeta["credit_card"] | {"statement_day": 0, "payment_due_day": 0} == {
        "credit_limit": "6000000.00",
        "available_credit": "0.00",
        "usage_percent": 117,
        "over_limit": True,
        "statement_day": 0,
        "payment_due_day": 0,
    }


# --- Consultar, editar, archivar, eliminar ------------------------------------------------


def test_consultar_y_editar(client: TestClient, csrf: dict[str, str]) -> None:
    cuenta = _crear(client, csrf, name="Nómina", type="bank", opening_balance="2800000")
    url = f"{URL}/{cuenta['id']}"
    assert client.get(url).json() == cuenta

    response = client.patch(
        url,
        json={"name": "Nómina principal", "institution": "Banco Andino", "opening_balance": "1.5"},
        headers=csrf,
    )
    assert response.status_code == 200
    editada = response.json()
    assert (editada["name"], editada["institution"], editada["balance"]) == (
        "Nómina principal",
        "Banco Andino",
        "1.50",
    )
    borrada = client.patch(url, json={"institution": None}, headers=csrf).json()
    assert borrada["institution"] is None


def test_ca_acc_04_archivar_y_reactivar(client: TestClient, csrf: dict[str, str]) -> None:
    _crear(client, csrf, name="Nómina", type="bank", opening_balance="1000")
    billetera = _crear(client, csrf, name="Billetera", type="wallet", opening_balance="250000")
    url = f"{URL}/{billetera['id']}"

    archivada = client.post(f"{url}/archive", json={}, headers=csrf)
    assert archivada.status_code == 200
    assert archivada.json()["archived"] is True
    assert client.post(f"{url}/archive", json={}, headers=csrf).status_code == 200  # idempotente
    listado = _listado(client)
    assert [c["archived"] for c in listado["accounts"]] == [False, True]
    assert listado["totals"]["available_balance"] == "1000.00"

    reactivada = client.post(f"{url}/restore", json={}, headers=csrf)
    assert reactivada.json()["archived"] is False
    assert _listado(client)["totals"]["available_balance"] == "251000.00"


def test_ca_acc_05_eliminar(client: TestClient, csrf: dict[str, str]) -> None:
    cuenta = _crear(client, csrf, name="Nómina", type="bank", opening_balance="0")
    url = f"{URL}/{cuenta['id']}"
    response = client.request("DELETE", url, json={}, headers=csrf)
    assert response.status_code == 204
    assert response.content == b""
    assert client.get(url).status_code == 404
    assert _listado(client)["accounts"] == []


# --- CA-ACC-06: aislamiento ---------------------------------------------------------------


def test_ca_acc_06_otro_usuario_no_ve_ni_toca_la_cuenta(
    client: TestClient, db_session: Session, clock: FrozenClock, ana: User, csrf: dict[str, str]
) -> None:
    cuenta = _crear(client, csrf, name="Nómina", type="bank", opening_balance="2800000")
    url = f"{URL}/{cuenta['id']}"

    luis = _usuario(db_session, clock, "luis@correo.com")
    csrf_luis = _entrar(client, db_session, luis, clock)
    respuestas = [
        client.get(url),
        client.patch(url, json={"name": "Mía"}, headers=csrf_luis),
        client.post(f"{url}/archive", json={}, headers=csrf_luis),
        client.post(f"{url}/restore", json={}, headers=csrf_luis),
        client.request("DELETE", url, json={}, headers=csrf_luis),
    ]
    for response in respuestas:
        assert response.status_code == 404
        assert response.json()["code"] == "account_not_found"
        assert response.json()["title"] == "No encontramos esa cuenta."
    assert _listado(client) == {
        "accounts": [],
        "totals": {"available_balance": "0.00", "net_worth": "0.00", "credit_card_debt": "0.00"},
    }

    _entrar(client, db_session, ana, clock)  # la dueña la sigue viendo igual
    assert client.get(url).json() == cuenta


def test_inexistente_y_identificador_invalido(client: TestClient, csrf: dict[str, str]) -> None:
    assert client.get(f"{URL}/0193f2a4-0000-7000-8000-000000000000").status_code == 404
    assert client.get(f"{URL}/no-es-un-id").status_code == 422


# --- CA-ACC-08: validaciones --------------------------------------------------------------


def test_ca_acc_08_nombre_repetido(client: TestClient, csrf: dict[str, str]) -> None:
    _crear(client, csrf, name="Nómina", type="bank", opening_balance="0")
    response = client.post(
        URL, json={"name": "NÓMINA", "type": "cash", "opening_balance": "0"}, headers=csrf
    )
    assert response.status_code == 409
    body = response.json()
    assert (body["code"], body["title"]) == (
        "account_name_taken",
        "Ya tienes una cuenta con ese nombre.",
    )
    assert body["errors"] == [
        {
            "loc": ["body", "name"],
            "type": "name_taken",
            "message": "Ya tienes una cuenta con ese nombre.",
        }
    ]


def test_ca_acc_08_tarjeta_sin_cupo(client: TestClient, csrf: dict[str, str]) -> None:
    datos = {k: v for k, v in TARJETA.items() if k != "credit_limit"}
    response = client.post(URL, json=datos, headers=csrf)
    assert response.status_code == 422
    assert response.json()["code"] == "validation_failed"
    assert response.json()["errors"] == [
        {
            "loc": ["body", "credit_limit"],
            "type": "missing",
            "message": "Indica el cupo de la tarjeta.",
        }
    ]


@pytest.mark.parametrize("monto", ["1250000.123", 1250000, "1.250.000"])
def test_ca_acc_08_monto_invalido(client: TestClient, csrf: dict[str, str], monto: Any) -> None:
    response = client.post(
        URL, json={"name": "Nómina", "type": "bank", "opening_balance": monto}, headers=csrf
    )
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "opening_balance"]


def test_el_tipo_no_se_puede_editar(client: TestClient, csrf: dict[str, str]) -> None:
    cuenta = _crear(client, csrf, name="Nómina", type="bank", opening_balance="0")
    response = client.patch(f"{URL}/{cuenta['id']}", json={"type": "cash"}, headers=csrf)
    assert response.status_code == 422
    assert response.json()["errors"][0]["loc"] == ["body", "type"]


# --- Sesión, CSRF y caché -----------------------------------------------------------------


def test_sin_sesion(client: TestClient) -> None:
    response = client.get(URL)
    assert (response.status_code, response.json()["code"]) == (401, "session_expired")


def test_escritura_sin_csrf(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post(URL, json={"name": "Nómina", "type": "bank", "opening_balance": "0"})
    assert (response.status_code, response.json()["code"]) == (403, "csrf_failed")
    assert _listado(client)["accounts"] == []


def test_escritura_desde_otro_origen(client: TestClient, csrf: dict[str, str]) -> None:
    response = client.post(
        URL,
        json={"name": "Nómina", "type": "bank", "opening_balance": "0"},
        headers={**csrf, "Origin": "https://sitio.malo"},
    )
    assert response.status_code == 403


def test_respuestas_sin_cache(client: TestClient, csrf: dict[str, str]) -> None:
    assert client.get(URL).headers["cache-control"] == "no-store"


def test_openapi_declara_los_montos_como_cadena(client: TestClient) -> None:
    schemas = client.get("/api/v1/openapi.json").json()["components"]["schemas"]
    assert schemas["AccountResponse"]["properties"]["balance"]["type"] == "string"
    assert schemas["TotalsResponse"]["properties"]["net_worth"]["type"] == "string"
    entrada = schemas["CreateAccountRequest"]["properties"]["opening_balance"]
    assert entrada["type"] == "string"
