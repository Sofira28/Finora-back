"""GET /api/v1/health: comprobación de vida (FEAT-SETUP, RF-SETUP-05)."""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok"]


@router.get("/health")
async def health() -> HealthResponse:
    # No expone versión, dependencias ni datos internos.
    return HealthResponse(status="ok")
