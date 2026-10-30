"""Pruebas del endpoint de salud y del formato de errores (CA-SETUP-05, VAL-SETUP-03)."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from finora.main import create_app


def test_health_responde_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ruta_inexistente_responde_problem_json() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/no-existe")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": "No encontramos el recurso solicitado.",
        "status": 404,
        "instance": "/api/v1/no-existe",
    }


def test_metodo_no_permitido_responde_problem_json() -> None:
    client = TestClient(create_app())
    response = client.post("/api/v1/health")
    assert response.status_code == 405
    assert response.headers["content-type"] == "application/problem+json"


def test_validacion_responde_422_sin_eco_de_datos() -> None:
    app = create_app()

    @app.get("/api/v1/_eco")
    async def eco(n: int) -> int:
        return n

    response = TestClient(app).get("/api/v1/_eco", params={"n": "secreto"})
    assert response.status_code == 422
    body = response.json()
    assert body["title"] == "Algunos datos no son válidos."
    assert body["errors"] == [{"loc": ["query", "n"], "type": "int_parsing"}]
    assert "secreto" not in response.text


def test_error_inesperado_no_expone_detalles() -> None:
    app: FastAPI = create_app()

    @app.get("/api/v1/_falla")
    async def falla() -> None:
        raise RuntimeError("detalle interno")

    response = TestClient(app, raise_server_exceptions=False).get("/api/v1/_falla")
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/problem+json"
    assert "detalle interno" not in response.text
