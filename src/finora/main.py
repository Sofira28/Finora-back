"""Punto de entrada de la API de FINORA."""

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, FastAPI, Request, Response

from finora.api.v1 import accounts, auth, health, me, transactions
from finora.auth.maintenance import PeriodicPurge
from finora.errors import register_error_handlers

NO_STORE_PREFIXES = (
    "/api/v1/auth",
    "/api/v1/me",
    "/api/v1/accounts",
    "/api/v1/transactions",
)


def create_app() -> FastAPI:
    app = FastAPI(title="FINORA API", version="1.0.0", openapi_url="/api/v1/openapi.json")
    register_error_handlers(app)
    app.state.auth_purge = PeriodicPurge()

    @app.middleware("http")
    async def no_store(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Autenticación, perfil y datos financieros nunca se guardan en caché (plan.md §8).
        response = await call_next(request)
        if request.url.path.startswith(NO_STORE_PREFIXES):
            response.headers["Cache-Control"] = "no-store"
        return response

    api_v1 = APIRouter(prefix="/api/v1")
    api_v1.include_router(health.router)
    api_v1.include_router(auth.router)
    api_v1.include_router(me.router)
    api_v1.include_router(accounts.router)
    api_v1.include_router(transactions.router)
    app.include_router(api_v1)
    return app


app = create_app()
