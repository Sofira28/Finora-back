"""Tokens de un solo uso (T-AUTH-BE-04, RN-AUTH-04/05, RNF-AUTH-05, VAL-AUTH-09)."""

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session

from finora.auth.models import AuthToken, User
from finora.auth.tokens import TokenPurpose, consume_token, hash_token, issue_token

AHORA = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)
VERIFICAR = TokenPurpose.VERIFY_EMAIL
RESTABLECER = TokenPurpose.RESET_PASSWORD


@pytest.fixture
def usuario(db_session: Session) -> User:
    user = User(email="ana@correo.com", name="Ana", created_at=AHORA)
    db_session.add(user)
    db_session.flush()
    return user


def test_emite_token_aleatorio_y_guarda_solo_el_hash(db_session: Session, usuario: User) -> None:
    raw = issue_token(db_session, usuario.id, VERIFICAR, AHORA)
    otro = issue_token(db_session, usuario.id, RESTABLECER, AHORA)
    assert raw != otro
    assert len(raw) >= 43  # 32 bytes en base64 URL-safe
    guardados = db_session.scalars(select(AuthToken)).all()
    assert {t.token_hash for t in guardados} == {hash_token(raw), hash_token(otro)}
    assert all(raw.encode() not in t.token_hash for t in guardados)


def test_consumir_devuelve_el_usuario_una_sola_vez(db_session: Session, usuario: User) -> None:
    raw = issue_token(db_session, usuario.id, VERIFICAR, AHORA)
    assert consume_token(db_session, raw, VERIFICAR, AHORA) == usuario.id
    assert consume_token(db_session, raw, VERIFICAR, AHORA) is None


@pytest.mark.parametrize(
    ("proposito", "vigencia"),
    [(VERIFICAR, timedelta(hours=24)), (RESTABLECER, timedelta(hours=1))],
)
def test_vence_en_el_plazo(
    db_session: Session, usuario: User, proposito: TokenPurpose, vigencia: timedelta
) -> None:
    raw = issue_token(db_session, usuario.id, proposito, AHORA)
    casi = AHORA + vigencia - timedelta(seconds=1)
    assert consume_token(db_session, raw, proposito, AHORA + vigencia) is None
    assert consume_token(db_session, raw, proposito, casi) == usuario.id


def test_no_sirve_para_otro_proposito(db_session: Session, usuario: User) -> None:
    raw = issue_token(db_session, usuario.id, VERIFICAR, AHORA)
    assert consume_token(db_session, raw, RESTABLECER, AHORA) is None
    assert consume_token(db_session, raw, VERIFICAR, AHORA) == usuario.id


@pytest.mark.parametrize("raw", ["", "inventado", "x" * 10_000, "ñ\x00"])
def test_token_inexistente(db_session: Session, usuario: User, raw: str) -> None:
    issue_token(db_session, usuario.id, VERIFICAR, AHORA)
    assert consume_token(db_session, raw, VERIFICAR, AHORA) is None


def test_uno_nuevo_invalida_el_anterior(db_session: Session, usuario: User) -> None:
    viejo = issue_token(db_session, usuario.id, RESTABLECER, AHORA)
    nuevo = issue_token(db_session, usuario.id, RESTABLECER, AHORA + timedelta(minutes=5))
    assert consume_token(db_session, viejo, RESTABLECER, AHORA) is None
    assert consume_token(db_session, nuevo, RESTABLECER, AHORA) == usuario.id


def test_uno_nuevo_no_toca_otros_propositos_ni_otros_usuarios(
    db_session: Session, usuario: User
) -> None:
    luis = User(email="luis@correo.com", name="Luis", created_at=AHORA)
    db_session.add(luis)
    db_session.flush()
    verificacion = issue_token(db_session, usuario.id, VERIFICAR, AHORA)
    de_luis = issue_token(db_session, luis.id, RESTABLECER, AHORA)
    issue_token(db_session, usuario.id, RESTABLECER, AHORA)
    assert consume_token(db_session, verificacion, VERIFICAR, AHORA) == usuario.id
    assert consume_token(db_session, de_luis, RESTABLECER, AHORA) == luis.id


# --- Concurrencia: transacciones reales, no la transacción revertida de db_session ---------


@pytest.fixture
def token_confirmado(engine: Engine) -> Iterator[str]:
    with Session(engine) as db:
        user = User(email=f"{uuid.uuid4().hex}@correo.com", name="Concurrente", created_at=AHORA)
        db.add(user)
        db.flush()
        raw = issue_token(db, user.id, RESTABLECER, AHORA)
        db.commit()
        user_id = user.id
    yield raw
    with Session(engine) as db:
        db.execute(delete(User).where(User.id == user_id))
        db.commit()


def test_dos_usos_simultaneos_solo_uno_tiene_exito(engine: Engine, token_confirmado: str) -> None:
    intentos = 8
    barrera = threading.Barrier(intentos)
    resultados: list[uuid.UUID | None] = []
    candado = threading.Lock()

    def consumir() -> None:
        with Session(engine) as db:
            barrera.wait()
            user_id = consume_token(db, token_confirmado, RESTABLECER, AHORA)
            db.commit()
        with candado:
            resultados.append(user_id)

    hilos = [threading.Thread(target=consumir) for _ in range(intentos)]
    for hilo in hilos:
        hilo.start()
    for hilo in hilos:
        hilo.join(timeout=30)
    assert len(resultados) == intentos
    assert sum(r is not None for r in resultados) == 1
