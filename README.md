# finora-back

Aplicación backend de FINORA.

## Responsabilidad

- Lógica de negocio y cálculos financieros con precisión monetaria segura.
- Clasificación correcta de ingresos, gastos, ahorro y transferencias (las transferencias entre cuentas propias no son ingreso ni gasto).
- Persistencia, autenticación y autorización.
- Validación obligatoria de toda entrada y aislamiento de datos por usuario.
- Implementación de los contratos definidos en `../specs/api-contracts.md`.

## Estado

**Stack:** Python + FastAPI + PostgreSQL ([ADR-0001](../docs/decisions/ADR-0001-stack-tecnologico.md)). Estructura base creada en `project-setup`; aún sin modelo de negocio. Esta aplicación es independiente de `finora-web`.

## Requisitos

- Python 3.14 y [uv](https://docs.astral.sh/uv/)
- Docker con el plugin `compose`, accesible por el usuario (para la base de datos y las pruebas de integración)

## Comandos

```bash
uv sync                                  # instalar dependencias
cp .env.example .env
docker compose up -d db                  # PostgreSQL local en 127.0.0.1:5432
uv run alembic upgrade head              # aplicar migraciones
uv run uvicorn finora.main:app --reload  # API en http://localhost:8000/api/v1
uv run ruff check . && uv run ruff format --check .
uv run mypy .
uv run pytest                            # todas las pruebas (requiere Docker)
uv run pytest -m "not db"                # sin pruebas de base de datos
```

## Estructura

- `src/finora/domain/money.py`: tipo `Money` (`Decimal`, `ROUND_HALF_EVEN`, sin `float`).
- `src/finora/errors.py`: errores RFC 9457 con mensajes es-CO.
- `src/finora/db/`: motor y sesiones de SQLAlchemy 2; migraciones en `migrations/`.
