# finora-back

Aplicación backend de FINORA.

## Responsabilidad

- Lógica de negocio y cálculos financieros con precisión monetaria segura.
- Clasificación correcta de ingresos, gastos, ahorro y transferencias (las transferencias entre cuentas propias no son ingreso ni gasto).
- Persistencia, autenticación y autorización.
- Validación obligatoria de toda entrada y aislamiento de datos por usuario.
- Implementación de los contratos definidos en `../specs/api-contracts.md`.

## Estado

**Stack:** Python + FastAPI + PostgreSQL ([ADR-0001](../docs/decisions/ADR-0001-stack-tecnologico.md)). Esta aplicación es independiente de `finora-web`.

Implementado: autenticación y perfil (`authentication`): registro con verificación de correo, inicio de sesión con sesiones de servidor, recuperación de contraseña, verificación en dos pasos (TOTP y códigos de recuperación), inicio de sesión con Google, reautenticación y eliminación de la cuenta. Aún sin módulos financieros.

## Requisitos

- Python 3.14 y [uv](https://docs.astral.sh/uv/)
- Docker con el plugin `compose`, accesible por el usuario (base de datos, Mailpit y pruebas de integración)

## Desarrollo local

```bash
uv sync                                  # instalar dependencias
cp .env.example .env                     # valores de desarrollo; sin secretos
docker compose up -d db mailpit          # PostgreSQL (127.0.0.1:5432) y Mailpit
uv run alembic upgrade head              # aplicar migraciones
uv run uvicorn finora.main:app --reload  # API en http://localhost:8000/api/v1
```

- **Correos:** en desarrollo se envían por SMTP a [Mailpit](https://mailpit.axllent.org/), que no los entrega a nadie. Se leen en http://localhost:8025.
- **Documentación de la API:** http://localhost:8000/docs (OpenAPI en `/api/v1/openapi.json`, que `finora-web` usa con `pnpm api:types`).
- Los enlaces de los correos apuntan a `FINORA_WEB_URL` (por defecto `finora-web` en http://localhost:5173), que reenvía `/api` a este backend.

## Variables de entorno

Todas llevan el prefijo `FINORA_`; `.env.example` trae los valores de desarrollo.

| Variable | Uso |
|---|---|
| `ENVIRONMENT` | `development`, `test` o `production`. Fuera de `development` la clave de MFA es obligatoria. |
| `DATABASE_URL` | Conexión a PostgreSQL (`postgresql+psycopg://…`). |
| `WEB_URL` | Origen de `finora-web`: enlaces de los correos, redirecciones de Google y verificación de `Origin` (CSRF). |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM` | Envío de correos. En desarrollo, Mailpit sin credenciales. El proveedor de producción está pendiente (PA-AUTH-10). |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Cliente OAuth de Google; van juntas. Vacías, el inicio con Google queda apagado (PA-AUTH-11). |
| `MFA_ENCRYPTION_KEY` | 32 bytes en base64 URL-safe para cifrar los secretos TOTP. Vacía en `development` se usa una clave temporal: **la verificación en dos pasos configurada deja de funcionar al reiniciar el servidor**. |
| `PRIVACY_POLICY_VERSION` | Versión de la política de datos que se debe aceptar al registrarse. |
| `TRUSTED_PROXY` | `true` solo detrás de un proxy de confianza que agregue `X-Forwarded-For`. |
| `RATE_LIMIT_LOGIN_PER_IP`, `RATE_LIMIT_EMAIL_PER_IP` | Límites por IP (inicio de sesión cada 15 min; registro, recuperación y reenvío cada hora). |

Para una clave de MFA estable en desarrollo:

```bash
uv run python -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Nunca se versiona `.env` ni una clave real.

## Calidad y pruebas

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy .
uv run pytest                              # todas (Docker: Testcontainers levanta PostgreSQL y Mailpit)
uv run pytest -m "not db and not mailpit"  # solo las que no necesitan Docker
```

Las pruebas de integración usan contenedores propios; no tocan la base de datos de desarrollo.

## Estructura

- `src/finora/main.py`: aplicación FastAPI, middlewares (CSRF, `Cache-Control: no-store` en `/auth` y `/me`) y limpieza periódica.
- `src/finora/api/v1/`: endpoints (`health`, `auth`, `me`); traducen HTTP y delegan en los servicios.
- `src/finora/auth/`: casos de uso (`service.py`), sesiones, CSRF, tokens de un solo uso, contraseñas (Argon2id), MFA, Google (OIDC con PKCE), límites de intentos y eventos de seguridad.
- `src/finora/email/`: plantillas y envío SMTP (o en memoria para pruebas).
- `src/finora/domain/money.py`: tipo `Money` (`Decimal`, `ROUND_HALF_EVEN`, sin `float`).
- `src/finora/errors.py`: errores RFC 9457 con `code` y mensajes es-CO.
- `src/finora/db/`: motor y sesiones de SQLAlchemy 2; migraciones en `migrations/`.
