"""Protección CSRF (plan.md §8, specs/api-contracts.md §4.1).

- Toda petición POST, PATCH o DELETE exige `Content-Type: application/json` (fuerza el
  preflight de CORS entre orígenes) y un `Origin` igual a FINORA_WEB_URL.
- Las que además llevan sesión exigen `X-CSRF-Token` con el token de esa sesión.
"""

import secrets

from fastapi import Request

from finora.auth.models import AuthSession
from finora.errors import ApiProblemError

CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_TITLE = "No pudimos completar la acción. Recarga la página e intenta de nuevo."


def _csrf_failed() -> ApiProblemError:
    return ApiProblemError(403, "csrf_failed", _CSRF_TITLE)


def check_origin_and_content_type(request: Request, web_url: str) -> None:
    if request.method not in UNSAFE_METHODS:
        return
    content_type = request.headers.get("content-type", "")
    if content_type.split(";")[0].strip().lower() != "application/json":
        raise _csrf_failed()
    if request.headers.get("origin") != web_url:
        raise _csrf_failed()


def check_csrf_token(request: Request, session: AuthSession) -> None:
    if request.method not in UNSAFE_METHODS:
        return
    sent = request.headers.get(CSRF_HEADER, "")
    if not secrets.compare_digest(sent.encode(), session.csrf_token.encode()):
        raise _csrf_failed()
