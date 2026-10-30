"""Esquema de autenticación y fixtures compartidas (T-AUTH-DB-01, plan.md §5, RN-AUTH-07)."""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from finora.auth.models import (
    AuthSession,
    AuthToken,
    DataConsent,
    ExternalIdentity,
    LoginAttempt,
    MfaCredential,
    MfaRecoveryCode,
    OAuthFlow,
    SecurityEvent,
    User,
)
from finora.clock import FrozenClock
from finora.db import Base
from finora.db.models import load_all_models

# Mismo instante que el reloj de prueba de conftest.py.
TEST_NOW = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)

TABLAS = {
    "users",
    "external_identities",
    "auth_sessions",
    "auth_tokens",
    "mfa_credentials",
    "mfa_recovery_codes",
    "oauth_flows",
    "login_attempts",
    "data_consents",
    "security_events",
}


def _hash() -> bytes:
    return hashlib.sha256(secrets.token_bytes(32)).digest()


def _usuario(email: str = "ana@correo.com", name: str = "Ana") -> User:
    return User(email=email, name=name, created_at=TEST_NOW)


def _sesion(user: User, **cambios: Any) -> AuthSession:
    datos: dict[str, Any] = {
        "token_hash": _hash(),
        "user_id": user.id,
        "stage": "active",
        "csrf_token": secrets.token_urlsafe(32),
        "created_at": TEST_NOW,
        "last_activity_at": TEST_NOW,
        "expires_at": TEST_NOW + timedelta(days=7),
    }
    datos.update(cambios)
    return AuthSession(**datos)


def _falla_al_guardar(db_session: Session, *objetos: Base) -> None:
    db_session.add_all(objetos)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


# --- Migración ----------------------------------------------------------------------------


def test_migracion_crea_las_10_tablas(engine: Engine) -> None:
    assert set(inspect(engine).get_table_names()) >= TABLAS


def test_modelos_coinciden_con_la_migracion(engine: Engine) -> None:
    load_all_models()
    with engine.connect() as conn:
        diferencias = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diferencias == []


def test_migracion_baja_y_vuelve_a_subir(engine: Engine, alembic_cfg: Config) -> None:
    command.downgrade(alembic_cfg, "base")
    assert TABLAS.isdisjoint(inspect(engine).get_table_names())
    command.upgrade(alembic_cfg, "head")
    assert set(inspect(engine).get_table_names()) >= TABLAS


# --- Usuarios -----------------------------------------------------------------------------


def test_correo_unico(db_session: Session) -> None:
    db_session.add(_usuario())
    db_session.flush()
    _falla_al_guardar(db_session, _usuario(name="Otra Ana"))


@pytest.mark.parametrize("email", ["Ana@correo.com", " ana@correo.com", "ana@correo.com "])
def test_correo_debe_estar_normalizado(db_session: Session, email: str) -> None:
    # RN-AUTH-01: la normalización la hace la aplicación; la BD la exige.
    _falla_al_guardar(db_session, _usuario(email=email))


@pytest.mark.parametrize("name", ["", " ", " Ana", "Ana ", "a" * 101])
def test_nombre_invalido(db_session: Session, name: str) -> None:
    _falla_al_guardar(db_session, _usuario(name=name))


@pytest.mark.parametrize("name", ["A", "a" * 100, "María José Pérez Ñáñez", "Ana 🌱"])
def test_nombre_valido(db_session: Session, name: str) -> None:
    # RN-AUTH-03: la longitud se cuenta en caracteres, no en bytes.
    db_session.add(_usuario(name=name))
    db_session.flush()


def test_ids_son_uuid_v7(db_session: Session) -> None:
    usuario = _usuario()
    db_session.add(usuario)
    db_session.flush()
    assert isinstance(usuario.id, uuid.UUID)
    assert usuario.id.version == 7


# --- Sesiones, tokens e identidades -------------------------------------------------------


@pytest.mark.parametrize(
    "cambios",
    [
        {"stage": "otra"},
        {"stage": "link_pending"},  # sin identidad de Google pendiente
        {"stage": "active", "pending_google_subject": "123"},
    ],
)
def test_etapas_de_sesion_invalidas(db_session: Session, cambios: dict[str, Any]) -> None:
    usuario = _usuario()
    db_session.add(usuario)
    db_session.flush()
    _falla_al_guardar(db_session, _sesion(usuario, **cambios))


def test_sesion_link_pending_con_identidad(db_session: Session) -> None:
    usuario = _usuario()
    db_session.add(usuario)
    db_session.flush()
    db_session.add(_sesion(usuario, stage="link_pending", pending_google_subject="123"))
    db_session.flush()


def test_hash_de_token_unico(db_session: Session) -> None:
    usuario = _usuario()
    db_session.add(usuario)
    db_session.flush()
    repetido = _hash()

    def token() -> AuthToken:
        return AuthToken(
            user_id=usuario.id,
            purpose="verify_email",
            token_hash=repetido,
            created_at=TEST_NOW,
            expires_at=TEST_NOW + timedelta(hours=24),
        )

    db_session.add(token())
    db_session.flush()
    _falla_al_guardar(db_session, token())


def test_identidad_externa_unica_y_solo_google(db_session: Session) -> None:
    ana, luis = _usuario(), _usuario("luis@correo.com", "Luis")
    db_session.add_all([ana, luis])
    db_session.flush()
    db_session.add(
        ExternalIdentity(user_id=ana.id, provider="google", subject="s1", created_at=TEST_NOW)
    )
    db_session.flush()
    _falla_al_guardar(
        db_session,
        ExternalIdentity(user_id=luis.id, provider="google", subject="s1", created_at=TEST_NOW),
    )
    _falla_al_guardar(
        db_session,
        ExternalIdentity(user_id=luis.id, provider="facebook", subject="s2", created_at=TEST_NOW),
    )


# --- Eliminación en cascada (RN-AUTH-07) --------------------------------------------------


def test_eliminar_usuario_borra_todo_y_conserva_eventos_anonimos(db_session: Session) -> None:
    ana, luis = _usuario(), _usuario("luis@correo.com", "Luis")
    db_session.add_all([ana, luis])
    db_session.flush()

    def datos_de(user: User) -> list[Base]:
        sesion = _sesion(user, id=uuid.uuid7())
        return [
            sesion,
            ExternalIdentity(
                user_id=user.id, provider="google", subject=str(user.id), created_at=TEST_NOW
            ),
            AuthToken(
                user_id=user.id,
                purpose="reset_password",
                token_hash=_hash(),
                created_at=TEST_NOW,
                expires_at=TEST_NOW + timedelta(hours=1),
            ),
            MfaCredential(user_id=user.id, secret_encrypted=b"cifrado", created_at=TEST_NOW),
            MfaRecoveryCode(user_id=user.id, code_hash="hash"),
            OAuthFlow(
                state_hash=_hash(),
                nonce="n",
                code_verifier="v",
                intent="reauth",
                session_id=sesion.id,
                created_at=TEST_NOW,
                expires_at=TEST_NOW + timedelta(minutes=10),
            ),
            DataConsent(user_id=user.id, policy_version="0", accepted_at=TEST_NOW),
            SecurityEvent(
                user_id=user.id, type="login_succeeded", ip="203.0.113.7", created_at=TEST_NOW
            ),
        ]

    for user in (ana, luis):
        db_session.add_all(datos_de(user))
    db_session.flush()

    db_session.delete(ana)
    db_session.flush()
    db_session.expunge_all()

    def cuantos(modelo: type[Base], **filtro: Any) -> int:
        consulta = select(func.count()).select_from(modelo).filter_by(**filtro)
        return db_session.execute(consulta).scalar_one()

    for modelo in (
        AuthSession,
        ExternalIdentity,
        AuthToken,
        MfaCredential,
        MfaRecoveryCode,
        DataConsent,
    ):
        assert cuantos(modelo, user_id=ana.id) == 0, modelo.__tablename__
        assert cuantos(modelo, user_id=luis.id) == 1, modelo.__tablename__
    assert cuantos(OAuthFlow) == 1  # el de Ana cayó con su sesión
    # SUP-AUTH-04: el evento se conserva sin vínculo con el usuario.
    assert cuantos(SecurityEvent) == 2
    assert cuantos(SecurityEvent, user_id=None) == 1


def test_intentos_no_dependen_de_usuarios(db_session: Session) -> None:
    db_session.add(LoginAttempt(key="ip:203.0.113.7", kind="login", created_at=TEST_NOW))
    db_session.flush()


# --- Fixtures compartidas -----------------------------------------------------------------


def test_cliente_de_prueba_responde(client: TestClient) -> None:
    assert client.get("/api/v1/health").json() == {"status": "ok"}


def test_reloj_de_prueba_controla_el_tiempo(clock: FrozenClock) -> None:
    assert clock.now() == TEST_NOW
    clock.advance(timedelta(minutes=31))
    assert clock.now() - TEST_NOW == timedelta(minutes=31)


def test_cada_prueba_empieza_con_la_bd_vacia(db_session: Session) -> None:
    # Las pruebas anteriores agregaron usuarios; la reversión por prueba los descarta.
    assert db_session.execute(select(func.count()).select_from(User)).scalar_one() == 0


def test_los_commit_de_la_aplicacion_no_escapan_de_la_prueba(
    db_session: Session, engine: Engine
) -> None:
    db_session.add(_usuario("commit@correo.com"))
    db_session.commit()
    with engine.connect() as otra_conexion:
        visibles = otra_conexion.execute(
            select(func.count()).select_from(User).where(User.email == "commit@correo.com")
        ).scalar_one()
    assert visibles == 0
