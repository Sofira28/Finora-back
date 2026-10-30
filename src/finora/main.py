"""Punto de entrada de la API de FINORA."""

from collections.abc import Awaitable, Callable

from fastapi import APIRouter, FastAPI, Request, Response

from finora.api.v1 import auth, health, me
from finora.auth.maintenance import PeriodicPurge
from finora.errors import register_error_handlers

NO_STORE_PREFIXES = ("/api/v1/auth", "/api/v1/me")


def create_app() -> FastAPI:
    app = FastAPI(title="FINORA API", version="1.0.0", openapi_url="/api/v1/openapi.json")
    register_error_handlers(app)
    app.state.auth_purge = PeriodicPurge()

    @app.middleware("http")
    async def no_store(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Respuestas de autenticación y perfil nunca se guardan en caché (plan.md §8).
        response = await call_next(request)
        if request.url.path.startswith(NO_STORE_PREFIXES):
            response.headers["Cache-Control"] = "no-store"
        return response

    api_v1 = APIRouter(prefix="/api/v1")
    api_v1.include_router(health.router)
    api_v1.include_router(auth.router)
    api_v1.include_router(me.router)
    app.include_router(api_v1)
    return app


app = create_app()
