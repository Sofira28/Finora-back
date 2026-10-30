"""Eventos de seguridad (T-AUTH-BE-06, RNF-AUTH-06)."""

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from finora.auth.events import SecurityEventType, record_event
from finora.auth.models import SecurityEvent, User
from finora.clock import FrozenClock


def test_registra_evento_con_usuario_e_ip(db_session: Session, clock: FrozenClock) -> None:
    user = User(email="ana@correo.com", name="Ana", created_at=clock.now())
    db_session.add(user)
    db_session.flush()
    record_event(
        db_session,
        SecurityEventType.LOGIN_SUCCEEDED,
        clock.now(),
        user_id=user.id,
        ip="203.0.113.7",
    )
    evento = db_session.scalars(select(SecurityEvent)).one()
    assert (evento.type, evento.user_id, str(evento.ip), evento.created_at) == (
        "login_succeeded",
        user.id,
        "203.0.113.7",
        clock.now(),
    )


def test_registra_evento_sin_usuario_ni_ip(db_session: Session, clock: FrozenClock) -> None:
    # Fallo de inicio de sesión con un correo sin cuenta.
    record_event(db_session, SecurityEventType.LOGIN_FAILED, clock.now())
    evento = db_session.scalars(select(SecurityEvent)).one()
    assert (evento.user_id, evento.ip) == (None, None)


def test_la_tabla_no_tiene_donde_guardar_datos_sensibles(db_session: Session) -> None:
    columnas = {c["name"] for c in inspect(db_session.connection()).get_columns("security_events")}
    assert columnas == {"id", "user_id", "type", "ip", "created_at"}


def test_tipos_de_evento_cubren_rnf_auth_06() -> None:
    requeridos = {
        "registered",
        "login_succeeded",
        "login_failed",
        "password_changed",
        "mfa_enabled",
        "mfa_disabled",
        "account_deleted",
    }
    assert requeridos <= {tipo.value for tipo in SecurityEventType}
