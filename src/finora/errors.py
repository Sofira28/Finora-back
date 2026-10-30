"""Manejadores de error en formato RFC 9457 (application/problem+json)."""

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"

# Títulos en es-CO; nunca se exponen detalles internos.
_TITLES: dict[int, str] = {
    400: "La solicitud no es válida.",
    401: "Necesitas iniciar sesión.",
    403: "No tienes permiso para realizar esta acción.",
    404: "No encontramos el recurso solicitado.",
    405: "Método no permitido para este recurso.",
    409: "La solicitud entra en conflicto con el estado actual.",
    422: "Algunos datos no son válidos.",
    429: "Demasiados intentos. Intenta de nuevo en unos minutos.",
    500: "Ocurrió un error inesperado. Intenta de nuevo más tarde.",
}


class ApiProblemError(Exception):
    """Error de negocio con un `code` estable para el frontend (specs/api-contracts.md §4.1)."""

    def __init__(
        self,
        status: int,
        code: str,
        title: str | None = None,
        headers: dict[str, str] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.title = title
        self.headers = headers
        self.extra = extra


def problem(
    status: int,
    request: Request,
    title: str | None = None,
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title or _TITLES.get(status, HTTPStatus(status).phrase),
        "status": status,
        "instance": request.url.path,
        **extra,
    }
    return JSONResponse(body, status_code=status, media_type=PROBLEM_JSON, headers=headers)


async def _api_problem(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, ApiProblemError):  # solo se registra para este tipo
        raise exc
    return problem(
        exc.status, request, title=exc.title, headers=exc.headers, code=exc.code, **exc.extra
    )


async def _http_exception(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # solo se registra para este tipo
        raise exc
    return problem(exc.status_code, request)


async def _validation_exception(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # solo se registra para este tipo
        raise exc
    errors = [
        {"loc": list(err.get("loc", ())), "type": err.get("type", "")} for err in exc.errors()
    ]
    return problem(422, request, errors=errors)


async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Error no controlado en %s", request.url.path)
    return problem(500, request)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiProblemError, _api_problem)
    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_exception)
    app.add_exception_handler(Exception, _unhandled_exception)
