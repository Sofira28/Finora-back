"""Casos de uso de autenticación (FEAT-AUTH).

Los endpoints traducen HTTP; aquí vive la lógica. Los correos no se envían aquí: se
devuelven para que el endpoint los programe en segundo plano (RNF-AUTH-03).
"""

import hmac
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidTag
from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from finora.auth import mfa, rate_limit
from finora.auth.dependencies import session_expired
from finora.auth.events import SecurityEventType, record_event
from finora.auth.google import GoogleAuthError, GoogleIdentity, GoogleOidcClient
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
from finora.auth.passwords import (
    PasswordPolicyError,
    hash_password,
    needs_rehash,
    normalize_email,
    validate_password,
    verify_password,
)
from finora.auth.sessions import (
    REAUTH_WINDOW,
    SessionStage,
    create_session,
    revoke_all_sessions,
    revoke_session,
    rotate_session,
)
from finora.auth.tokens import TokenPurpose, consume_token, hash_token, issue_token, peek_token
from finora.config import Settings
from finora.email import OutgoingEmail, templates
from finora.errors import ApiProblemError

logger = logging.getLogger(__name__)

EMAIL_SENT_MESSAGE = "Te enviamos un correo para confirmar tu cuenta."
RESEND_MESSAGE = "Si tu cuenta está pendiente de confirmar, te enviamos un nuevo enlace."
FORGOT_MESSAGE = (
    "Si existe una cuenta con ese correo, te enviamos un enlace para restablecer la contraseña."
)
SETUP_MESSAGE = "Te enviamos un enlace a tu correo para crear tu contraseña."


@dataclass
class RequestContext:
    """Lo que todo caso de uso necesita de la petición."""

    db: Session
    now: datetime
    settings: Settings
    ip: str | None
    emails: list[OutgoingEmail] = field(default_factory=list)


def invalid_field(field_name: str, error_type: str, message: str) -> ApiProblemError:
    return ApiProblemError(
        422,
        "validation_failed",
        errors=[{"loc": ["body", field_name], "type": error_type, "message": message}],
    )


def invalid_token() -> ApiProblemError:
    return ApiProblemError(400, "invalid_token", "Este enlace ya no es válido. Solicita uno nuevo.")


def invalid_credentials() -> ApiProblemError:
    return ApiProblemError(
        401, "invalid_credentials", "El correo o la contraseña no son correctos."
    )


def _user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == normalize_email(email)))


def _limit_by_ip(ctx: RequestContext, limit: rate_limit.Limit) -> None:
    key = rate_limit.ip_key(ctx.ip)
    rate_limit.check(ctx.db, key, limit, ctx.now)
    rate_limit.record(ctx.db, key, limit, ctx.now)
    ctx.db.commit()  # el intento cuenta aunque luego falle la validación


def _verification_email(ctx: RequestContext, user: User) -> OutgoingEmail:
    raw = issue_token(ctx.db, user.id, TokenPurpose.VERIFY_EMAIL, ctx.now)
    link = f"{ctx.settings.web_url}/verificar-correo?token={raw}"
    return templates.verify_email(user.email, user.name, link)


# --- Registro y verificación --------------------------------------------------------------


def register(
    ctx: RequestContext, email: str, name: str, password: str, policy_version: str
) -> None:
    """RF-AUTH-01/02, VAL-AUTH-04: misma respuesta y mismo trabajo exista o no la cuenta."""
    _limit_by_ip(ctx, rate_limit.email_ip_limit(ctx.settings))
    address = normalize_email(email)
    if policy_version != ctx.settings.privacy_policy_version:
        raise invalid_field(
            "privacy_policy_version",
            "policy_not_accepted",
            "Debes aceptar la política de tratamiento de datos personales.",
        )
    try:
        validate_password(password, email=address)
    except PasswordPolicyError as exc:
        raise invalid_field("password", exc.rule, exc.message) from exc

    # El hash se calcula siempre para que el tiempo no revele si el correo existe.
    password_hash = hash_password(password)
    existing = _user_by_email(ctx.db, address)
    if existing is None:
        user = User(email=address, name=name, password_hash=password_hash, created_at=ctx.now)
        ctx.db.add(user)
        ctx.db.flush()
        ctx.db.add(DataConsent(user_id=user.id, policy_version=policy_version, accepted_at=ctx.now))
        record_event(ctx.db, SecurityEventType.REGISTERED, ctx.now, user_id=user.id, ip=ctx.ip)
        ctx.emails.append(_verification_email(ctx, user))
    elif existing.email_verified_at is not None:
        web = ctx.settings.web_url
        ctx.emails.append(
            templates.duplicate_registration(
                existing.email,
                existing.name,
                f"{web}/iniciar-sesion",
                f"{web}/recuperar-contrasena",
            )
        )
    else:
        # Cuenta sin verificar: se reenvía la verificación; nombre y contraseña no cambian.
        ctx.emails.append(_verification_email(ctx, existing))
    ctx.db.commit()


def verify_email(ctx: RequestContext, raw_token: str) -> None:
    user_id = consume_token(ctx.db, raw_token, TokenPurpose.VERIFY_EMAIL, ctx.now)
    if user_id is None:
        ctx.db.rollback()
        raise invalid_token()
    user = ctx.db.get_one(User, user_id)
    if user.email_verified_at is None:
        user.email_verified_at = ctx.now
        record_event(ctx.db, SecurityEventType.EMAIL_VERIFIED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()


def resend_verification(ctx: RequestContext, email: str) -> None:
    _limit_by_ip(ctx, rate_limit.email_ip_limit(ctx.settings))
    user = _user_by_email(ctx.db, email)
    if user is not None and user.email_verified_at is None:
        ctx.emails.append(_verification_email(ctx, user))
    ctx.db.commit()


# --- Inicio y cierre de sesión ------------------------------------------------------------


@dataclass(frozen=True)
class LoginResult:
    raw_session: str
    next: SessionStage


def login(
    ctx: RequestContext, email: str, password: str, previous: AuthSession | None
) -> LoginResult:
    """RF-AUTH-04, RF-AUTH-12, RNF-AUTH-04, VAL-AUTH-05/06/07."""
    _limit_by_ip(ctx, rate_limit.login_ip_limit(ctx.settings))
    account = rate_limit.account_key(email)
    rate_limit.check(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)

    user = _user_by_email(ctx.db, email)
    password_hash = user.password_hash if user else None
    # Siempre se verifica (contra el hash de relleno si no hay cuenta): tiempo constante.
    valid = verify_password(password_hash, password)
    if not valid or user is None or password_hash is None:
        rate_limit.record(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
        record_event(
            ctx.db,
            SecurityEventType.LOGIN_FAILED,
            ctx.now,
            user_id=user.id if user else None,
            ip=ctx.ip,
        )
        ctx.db.commit()
        raise invalid_credentials()

    if user.email_verified_at is None:
        ctx.db.commit()
        raise ApiProblemError(
            403,
            "email_not_verified",
            "Confirma tu correo para continuar. ¿Te enviamos el enlace de nuevo?",
        )
    if needs_rehash(password_hash):
        user.password_hash = hash_password(password)

    result = _start_session(ctx, user, previous)
    ctx.db.commit()
    return result


def _start_session(ctx: RequestContext, user: User, previous: AuthSession | None) -> LoginResult:
    """Primer factor superado: sesión activa, o pendiente del código si hay MFA (RF-AUTH-19)."""
    if previous is not None:
        revoke_session(ctx.db, previous)  # identificador nuevo en cada inicio de sesión
    stage = (
        SessionStage.MFA_PENDING
        if _confirmed_mfa(ctx.db, user.id) is not None
        else SessionStage.ACTIVE
    )
    raw, _ = create_session(ctx.db, user.id, stage, ctx.now)
    if stage == SessionStage.ACTIVE:
        record_event(ctx.db, SecurityEventType.LOGIN_SUCCEEDED, ctx.now, user_id=user.id, ip=ctx.ip)
    return LoginResult(raw, stage)


def logout(ctx: RequestContext, session: AuthSession | None) -> None:
    if session is not None:
        record_event(ctx.db, SecurityEventType.LOGOUT, ctx.now, user_id=session.user_id, ip=ctx.ip)
        revoke_session(ctx.db, session)
    ctx.db.commit()


# --- Recuperación y cambio de contraseña --------------------------------------------------


def _reset_email(ctx: RequestContext, user: User) -> OutgoingEmail:
    raw = issue_token(ctx.db, user.id, TokenPurpose.RESET_PASSWORD, ctx.now)
    link = f"{ctx.settings.web_url}/restablecer-contrasena?token={raw}"
    # Sin contraseña (solo Google), el mismo enlace crea la primera (RF-AUTH-18).
    return templates.password_reset(
        user.email, user.name, link, first_password=user.password_hash is None
    )


def _changed_email(ctx: RequestContext, user: User) -> OutgoingEmail:
    link = f"{ctx.settings.web_url}/recuperar-contrasena"
    return templates.password_changed(user.email, user.name, link)


def _validated_password(password: str, email: str, field_name: str) -> None:
    try:
        validate_password(password, email=email)
    except PasswordPolicyError as exc:
        raise invalid_field(field_name, exc.rule, exc.message) from exc


def forgot_password(ctx: RequestContext, email: str) -> None:
    """RF-AUTH-08: misma respuesta exista o no la cuenta."""
    _limit_by_ip(ctx, rate_limit.email_ip_limit(ctx.settings))
    user = _user_by_email(ctx.db, email)
    if user is not None:
        ctx.emails.append(_reset_email(ctx, user))
    ctx.db.commit()


def reset_password(ctx: RequestContext, raw_token: str, new_password: str) -> None:
    """RF-AUTH-08/09/18: valida antes de gastar el enlace; cierra todas las sesiones."""
    user_id = peek_token(ctx.db, raw_token, TokenPurpose.RESET_PASSWORD, ctx.now)
    if user_id is None:
        raise invalid_token()
    user = ctx.db.get_one(User, user_id)
    _validated_password(new_password, user.email, "new_password")
    password_hash = hash_password(new_password)
    # Consumo atómico: si otra petición lo usó entre tanto, esta falla.
    if consume_token(ctx.db, raw_token, TokenPurpose.RESET_PASSWORD, ctx.now) is None:
        ctx.db.rollback()
        raise invalid_token()
    user.password_hash = password_hash
    revoke_all_sessions(ctx.db, user.id)
    record_event(ctx.db, SecurityEventType.PASSWORD_RESET, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.emails.append(_changed_email(ctx, user))
    ctx.db.commit()


def change_password(
    ctx: RequestContext,
    user: User,
    session: AuthSession,
    current_password: str,
    new_password: str,
) -> None:
    """RF-AUTH-15 y RF-AUTH-09: exige la actual; cierra las demás sesiones."""
    account = rate_limit.account_key(user.email)
    rate_limit.check(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
    if not verify_password(user.password_hash, current_password):
        rate_limit.record(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
        ctx.db.commit()
        raise ApiProblemError(401, "invalid_credentials", "La contraseña actual no es correcta.")
    _validated_password(new_password, user.email, "new_password")
    user.password_hash = hash_password(new_password)
    revoke_all_sessions(ctx.db, user.id, except_id=session.id)
    record_event(ctx.db, SecurityEventType.PASSWORD_CHANGED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.emails.append(_changed_email(ctx, user))
    ctx.db.commit()


def request_password_setup(ctx: RequestContext, user: User) -> None:
    """RF-AUTH-18: cuentas solo con Google piden por correo el enlace para crear contraseña."""
    if user.password_hash is not None:
        raise ApiProblemError(409, "password_already_set", "Tu cuenta ya tiene una contraseña.")
    _limit_by_ip(ctx, rate_limit.email_ip_limit(ctx.settings))
    ctx.emails.append(_reset_email(ctx, user))
    ctx.db.commit()


# --- Perfil -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Profile:
    name: str
    email: str
    has_password: bool
    google_linked: bool
    mfa_enabled: bool


def profile(db: Session, user: User) -> Profile:
    """RF-AUTH-14: siempre del usuario de la sesión (RN-AUTH-08)."""
    google = db.scalar(select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id))
    mfa = db.get(MfaCredential, user.id)
    return Profile(
        name=user.name,
        email=user.email,
        has_password=user.password_hash is not None,
        google_linked=google is not None,
        mfa_enabled=mfa is not None and mfa.confirmed_at is not None,
    )


def rename(db: Session, user: User, name: str) -> Profile:
    user.name = name
    db.commit()
    return profile(db, user)


# --- Segundo factor (MFA) -----------------------------------------------------------------

INVALID_CODE = "El código no es correcto."


def _confirmed_mfa(db: Session, user_id: object) -> MfaCredential | None:
    credential = db.get(MfaCredential, user_id)
    return credential if credential is not None and credential.confirmed_at is not None else None


def _use_totp(ctx: RequestContext, credential: MfaCredential, code: str) -> bool:
    try:
        secret = mfa.decrypt_secret(
            ctx.settings.mfa_key, credential.user_id, credential.secret_encrypted
        )
    except InvalidTag:
        # Clave de cifrado distinta a la usada al configurar (p. ej. clave temporal de
        # development tras reiniciar): el usuario no puede pasar el segundo factor con TOTP.
        logger.error("No se pudo descifrar un secreto TOTP; revisar FINORA_MFA_ENCRYPTION_KEY")
        return False
    step = mfa.match_totp(secret, code, ctx.now, credential.last_used_step)
    if step is None:
        return False
    # Atómico: si dos peticiones usan el mismo código a la vez, solo una lo consume.
    used = ctx.db.execute(
        update(MfaCredential)
        .where(
            MfaCredential.user_id == credential.user_id,
            or_(MfaCredential.last_used_step.is_(None), MfaCredential.last_used_step < step),
        )
        .values(last_used_step=step)
        .returning(MfaCredential.user_id)
    ).scalar_one_or_none()
    return used is not None


def _use_recovery_code(ctx: RequestContext, user_id: object, code: str) -> bool:
    if not mfa.is_recovery_code_format(code):
        return False
    used = ctx.db.execute(
        update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.code_hash == mfa.hash_recovery_code(ctx.settings.mfa_key, code),
            MfaRecoveryCode.used_at.is_(None),
        )
        .values(used_at=ctx.now)
        .returning(MfaRecoveryCode.id)
    ).scalar_one_or_none()
    return used is not None


def _second_factor(ctx: RequestContext, credential: MfaCredential, code: str) -> bool:
    """TOTP o, si no lo es, código de recuperación (RF-AUTH-12)."""
    if _use_totp(ctx, credential, code):
        return True
    if _use_recovery_code(ctx, credential.user_id, code):
        record_event(
            ctx.db,
            SecurityEventType.MFA_RECOVERY_CODE_USED,
            ctx.now,
            user_id=credential.user_id,
            ip=ctx.ip,
        )
        return True
    return False


def login_mfa(ctx: RequestContext, session: AuthSession, code: str) -> str:
    """RF-AUTH-12: completa el inicio de sesión; devuelve la cookie de la sesión activa."""
    user = ctx.db.get_one(User, session.user_id)
    account = rate_limit.account_key(user.email)
    rate_limit.check(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
    credential = _confirmed_mfa(ctx.db, user.id)
    if credential is None or not _second_factor(ctx, credential, code):
        rate_limit.record(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
        record_event(ctx.db, SecurityEventType.MFA_FAILED, ctx.now, user_id=user.id, ip=ctx.ip)
        ctx.db.commit()
        raise ApiProblemError(401, "invalid_credentials", INVALID_CODE)
    raw, _ = rotate_session(ctx.db, session, SessionStage.ACTIVE, ctx.now)
    record_event(ctx.db, SecurityEventType.LOGIN_SUCCEEDED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()
    return raw


def reauthenticate(
    ctx: RequestContext,
    user: User,
    session: AuthSession,
    password: str | None,
    code: str | None,
) -> None:
    """RF-AUTH-21: contraseña (+ código), o código tras volver de Google con MFA activa."""
    account = rate_limit.account_key(user.email)
    rate_limit.check(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
    credential = _confirmed_mfa(ctx.db, user.id)
    if password is None:
        # Segundo paso de la reautenticación con Google (callback con reauth=codigo).
        valid = (
            session.google_reauth_at is not None
            and ctx.now - session.google_reauth_at < REAUTH_WINDOW
            and credential is not None
            and code is not None
            and _second_factor(ctx, credential, code)
        )
    else:
        valid = verify_password(user.password_hash, password)
        if valid and credential is not None:
            valid = code is not None and _second_factor(ctx, credential, code)
    if not valid:
        rate_limit.record(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
        ctx.db.commit()
        raise ApiProblemError(
            401, "invalid_credentials", "La contraseña o el código no son correctos."
        )
    session.reauthenticated_at = ctx.now
    session.google_reauth_at = None
    record_event(ctx.db, SecurityEventType.REAUTHENTICATED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()


@dataclass(frozen=True)
class MfaSetup:
    secret: str
    otpauth_uri: str


def setup_mfa(ctx: RequestContext, user: User) -> MfaSetup:
    """RF-AUTH-10: secreto nuevo pendiente de confirmar; reemplaza uno pendiente anterior."""
    credential = ctx.db.get(MfaCredential, user.id)
    if credential is not None and credential.confirmed_at is not None:
        raise ApiProblemError(
            409, "mfa_already_enabled", "La verificación en dos pasos ya está activa."
        )
    secret = mfa.generate_secret()
    encrypted = mfa.encrypt_secret(ctx.settings.mfa_key, user.id, secret)
    if credential is None:
        ctx.db.add(MfaCredential(user_id=user.id, secret_encrypted=encrypted, created_at=ctx.now))
    else:
        credential.secret_encrypted = encrypted
        credential.last_used_step = None
        credential.created_at = ctx.now
    ctx.db.commit()
    return MfaSetup(secret=secret, otpauth_uri=mfa.provisioning_uri(secret, user.email))


def confirm_mfa(ctx: RequestContext, user: User, code: str) -> list[str]:
    """RF-AUTH-10/11: activa la MFA y entrega los 10 códigos de recuperación una sola vez."""
    credential = ctx.db.get(MfaCredential, user.id)
    if credential is None or credential.confirmed_at is not None:
        raise invalid_field(
            "code",
            "mfa_not_pending",
            "No hay una configuración pendiente. Vuelve a empezar la activación.",
        )
    if not _use_totp(ctx, credential, code):
        raise invalid_field("code", "invalid_code", INVALID_CODE)
    credential.confirmed_at = ctx.now
    ctx.db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes = mfa.generate_recovery_codes()
    ctx.db.add_all(
        MfaRecoveryCode(user_id=user.id, code_hash=mfa.hash_recovery_code(ctx.settings.mfa_key, c))
        for c in codes
    )
    record_event(ctx.db, SecurityEventType.MFA_ENABLED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()
    return codes


def disable_mfa(ctx: RequestContext, user: User, code: str) -> None:
    """RF-AUTH-13: con reautenticación reciente (en el endpoint) y un código TOTP vigente."""
    credential = _confirmed_mfa(ctx.db, user.id)
    if credential is None:
        raise invalid_field(
            "code", "mfa_not_enabled", "La verificación en dos pasos no está activa."
        )
    if not _use_totp(ctx, credential, code):
        raise invalid_field("code", "invalid_code", INVALID_CODE)
    ctx.db.delete(credential)
    ctx.db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    record_event(ctx.db, SecurityEventType.MFA_DISABLED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()


# --- Google (RF-AUTH-05, 17, 19 y 21) -----------------------------------------------------

GOOGLE_FLOW_TTL = timedelta(minutes=10)
LOGIN_ERROR = "/iniciar-sesion?error=google"  # VAL-AUTH-13
LOGIN_UNVERIFIED = "/iniciar-sesion?error=google_unverified"  # VAL-AUTH-12
REAUTH_ERROR = "/perfil?reauth=error"


def google_redirect_uri(settings: Settings) -> str:
    # Mismo origen que finora-web (proxy de /api): la cookie de sesión llega al callback.
    return f"{settings.web_url}/api/v1/auth/google/callback"


@dataclass(frozen=True)
class GoogleStart:
    url: str
    # Valor del `state` para la cookie que ata el flujo a este navegador; None si no hay flujo.
    raw_state: str | None


def google_start(
    ctx: RequestContext,
    google: GoogleOidcClient,
    intent: str,
    session: AuthSession | None,
    privacy_policy_version: str | None,
) -> GoogleStart:
    reauth = intent == "reauth"
    if reauth and (session is None or session.stage != SessionStage.ACTIVE):
        return GoogleStart(f"{ctx.settings.web_url}/iniciar-sesion", None)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)  # 86 caracteres (RFC 7636: de 43 a 128)
    accepted = privacy_policy_version == ctx.settings.privacy_policy_version
    ctx.db.add(
        OAuthFlow(
            state_hash=hash_token(state),
            nonce=nonce,
            code_verifier=code_verifier,
            intent=intent,
            session_id=session.id if reauth and session is not None else None,
            privacy_policy_version=privacy_policy_version if accepted and not reauth else None,
            created_at=ctx.now,
            expires_at=ctx.now + GOOGLE_FLOW_TTL,
        )
    )
    ctx.db.commit()
    url = google.authorization_url(
        redirect_uri=google_redirect_uri(ctx.settings),
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
        reauth=reauth,
    )
    return GoogleStart(url, state)


@dataclass(frozen=True)
class GoogleOutcome:
    path: str  # ruta de finora-web a la que se redirige
    raw_session: str | None = None


def google_callback(
    ctx: RequestContext,
    google: GoogleOidcClient,
    *,
    state: str | None,
    code: str | None,
    error: str | None,
    browser_state: str | None,
    previous: AuthSession | None,
) -> GoogleOutcome:
    """Termina el flujo de Google. Todo resultado es una redirección; nunca un error JSON."""
    flow = None
    # El `state` debe coincidir con la cookie de este navegador: impide que alguien haga
    # entrar a otra persona con su propia cuenta de Google (CSRF de inicio de sesión).
    if state and browser_state and hmac.compare_digest(state, browser_state):
        flow = ctx.db.scalars(
            delete(OAuthFlow)
            .where(OAuthFlow.state_hash == hash_token(state), OAuthFlow.expires_at > ctx.now)
            .returning(OAuthFlow)
        ).one_or_none()
    if flow is None:
        ctx.db.commit()
        return GoogleOutcome(LOGIN_ERROR)
    outcome = _finish_google_flow(ctx, google, flow, code, error, previous)
    ctx.db.commit()
    return outcome


def _finish_google_flow(
    ctx: RequestContext,
    google: GoogleOidcClient,
    flow: OAuthFlow,
    code: str | None,
    error: str | None,
    previous: AuthSession | None,
) -> GoogleOutcome:
    reauth = flow.intent == "reauth"
    failure = GoogleOutcome(REAUTH_ERROR if reauth else LOGIN_ERROR)
    if error is not None or not code:
        return failure  # cancelación o error de Google (VAL-AUTH-13)
    try:
        identity = google.exchange_code(
            redirect_uri=google_redirect_uri(ctx.settings),
            code=code,
            code_verifier=flow.code_verifier,
            nonce=flow.nonce,
        )
    except GoogleAuthError:
        logger.warning("Falló el intercambio con Google", exc_info=True)
        return failure
    if not identity.email_verified:
        return GoogleOutcome(REAUTH_ERROR if reauth else LOGIN_UNVERIFIED)
    if reauth:
        return _google_reauth(ctx, flow, identity, previous)
    return _google_login(ctx, flow, identity, previous)


def _google_user_id(db: Session, subject: str) -> uuid.UUID | None:
    return db.scalar(
        select(ExternalIdentity.user_id).where(
            ExternalIdentity.provider == "google", ExternalIdentity.subject == subject
        )
    )


def _link_google(ctx: RequestContext, user: User, subject: str) -> None:
    ctx.db.add(
        ExternalIdentity(user_id=user.id, provider="google", subject=subject, created_at=ctx.now)
    )
    record_event(ctx.db, SecurityEventType.GOOGLE_LINKED, ctx.now, user_id=user.id, ip=ctx.ip)


def _google_name(identity: GoogleIdentity) -> str:
    """RF-AUTH-05: nombre de Google ajustado a RN-AUTH-03; sin nombre, el usuario del correo."""
    name = identity.name.strip()[:100].strip()
    return name or identity.email.split("@")[0][:100]


def _session_outcome(result: LoginResult) -> GoogleOutcome:
    path = "/" if result.next == SessionStage.ACTIVE else "/iniciar-sesion/codigo"
    return GoogleOutcome(path, result.raw_session)


def _google_login(
    ctx: RequestContext, flow: OAuthFlow, identity: GoogleIdentity, previous: AuthSession | None
) -> GoogleOutcome:
    linked = _google_user_id(ctx.db, identity.subject)
    if linked is not None:
        known = ctx.db.get_one(User, linked)
        return _session_outcome(_start_session(ctx, known, previous))

    consented = flow.privacy_policy_version == ctx.settings.privacy_policy_version
    user = _user_by_email(ctx.db, identity.email)
    if user is None:
        # CA-AUTH-04: cuenta nueva, verificada, con el nombre de Google.
        if not consented:
            return GoogleOutcome(LOGIN_ERROR)
        user = User(
            email=normalize_email(identity.email),
            name=_google_name(identity),
            password_hash=None,
            email_verified_at=ctx.now,
            created_at=ctx.now,
        )
        ctx.db.add(user)
        ctx.db.flush()
        record_event(ctx.db, SecurityEventType.REGISTERED, ctx.now, user_id=user.id, ip=ctx.ip)
    elif user.email_verified_at is None:
        # RF-AUTH-17, excepción: Google demuestra que el correo es de quien entra. La
        # contraseña nunca se verificó (pudo ponerla un tercero): se descarta.
        if not consented:
            return GoogleOutcome(LOGIN_ERROR)
        user.password_hash = None
        user.name = _google_name(identity)
        user.email_verified_at = ctx.now
        ctx.db.execute(delete(AuthToken).where(AuthToken.user_id == user.id))
        ctx.db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
        ctx.db.execute(delete(MfaCredential).where(MfaCredential.user_id == user.id))
        revoke_all_sessions(ctx.db, user.id)
        record_event(ctx.db, SecurityEventType.EMAIL_VERIFIED, ctx.now, user_id=user.id, ip=ctx.ip)
    elif user.password_hash is not None:
        # RF-AUTH-17 / CA-AUTH-13: nada de sesión hasta confirmar la contraseña de FINORA.
        if previous is not None:
            revoke_session(ctx.db, previous)
        raw, _ = create_session(
            ctx.db,
            user.id,
            SessionStage.LINK_PENDING,
            ctx.now,
            pending_google_subject=identity.subject,
        )
        return GoogleOutcome("/iniciar-sesion/vincular-google", raw)
    else:
        # Cuenta solo con Google vinculada a otra identidad de Google con el mismo correo.
        return GoogleOutcome(LOGIN_ERROR)

    if consented and flow.privacy_policy_version is not None:
        ctx.db.add(
            DataConsent(
                user_id=user.id, policy_version=flow.privacy_policy_version, accepted_at=ctx.now
            )
        )
    _link_google(ctx, user, identity.subject)
    return _session_outcome(_start_session(ctx, user, previous))


def _google_reauth(
    ctx: RequestContext, flow: OAuthFlow, identity: GoogleIdentity, previous: AuthSession | None
) -> GoogleOutcome:
    """RF-AUTH-21: misma sesión que pidió el flujo y la cuenta de Google vinculada al usuario."""
    if (
        previous is None
        or previous.id != flow.session_id
        or previous.stage != SessionStage.ACTIVE
        or _google_user_id(ctx.db, identity.subject) != previous.user_id
    ):
        return GoogleOutcome(REAUTH_ERROR)
    # Se pidió max_age=0: si Google informa auth_time, la autenticación debe ser reciente.
    stale = ctx.now.timestamp() - (identity.auth_time or 0) > REAUTH_WINDOW.total_seconds()
    if identity.auth_time is not None and stale:
        return GoogleOutcome(REAUTH_ERROR)
    if _confirmed_mfa(ctx.db, previous.user_id) is not None:
        previous.google_reauth_at = ctx.now
        return GoogleOutcome("/perfil?reauth=codigo")
    previous.reauthenticated_at = ctx.now
    record_event(
        ctx.db, SecurityEventType.REAUTHENTICATED, ctx.now, user_id=previous.user_id, ip=ctx.ip
    )
    return GoogleOutcome("/perfil?reauth=ok")


def google_link(ctx: RequestContext, session: AuthSession, password: str) -> LoginResult:
    """RF-AUTH-17 / CA-AUTH-13: la contraseña de FINORA autoriza vincular Google."""
    user = ctx.db.get_one(User, session.user_id)
    account = rate_limit.account_key(user.email)
    rate_limit.check(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
    if not verify_password(user.password_hash, password):
        rate_limit.record(ctx.db, account, rate_limit.ACCOUNT_FAILURES, ctx.now)
        record_event(ctx.db, SecurityEventType.LOGIN_FAILED, ctx.now, user_id=user.id, ip=ctx.ip)
        ctx.db.commit()
        raise ApiProblemError(401, "invalid_credentials", "La contraseña no es correcta.")
    subject = session.pending_google_subject
    if subject is None:  # no ocurre: la restricción de la tabla lo exige en link_pending
        raise session_expired()
    linked = _google_user_id(ctx.db, subject)
    if linked is None:
        _link_google(ctx, user, subject)
    elif linked != user.id:  # otra cuenta se quedó con esa identidad mientras tanto
        raise session_expired()
    # Si hay MFA, el código se pide a continuación (RF-AUTH-17 y RF-AUTH-19).
    stage = (
        SessionStage.MFA_PENDING
        if _confirmed_mfa(ctx.db, user.id) is not None
        else SessionStage.ACTIVE
    )
    raw, _ = rotate_session(ctx.db, session, stage, ctx.now)
    if stage == SessionStage.ACTIVE:
        record_event(ctx.db, SecurityEventType.LOGIN_SUCCEEDED, ctx.now, user_id=user.id, ip=ctx.ip)
    ctx.db.commit()
    return LoginResult(raw, stage)


# --- Eliminación de la cuenta (RF-AUTH-16, RN-AUTH-07) ------------------------------------

DELETE_CONFIRMATION = "ELIMINAR"


def delete_account(ctx: RequestContext, user: User, confirmation: str) -> None:
    """Borrado inmediato y definitivo; la reautenticación reciente la exige el endpoint.

    Las tablas que referencian a `users` borran en cascada (sesiones, tokens, MFA, Google,
    consentimientos y, en adelante, los datos financieros). Los eventos de seguridad se
    conservan sin nada que identifique al usuario (SUP-AUTH-04): `user_id` queda nulo por la
    clave foránea y aquí se borra la IP. También se borran los intentos ligados a su correo.
    """
    if confirmation != DELETE_CONFIRMATION:
        raise invalid_field(
            "confirmation", "confirmation_mismatch", "Escribe ELIMINAR para confirmar."
        )
    ctx.db.execute(update(SecurityEvent).where(SecurityEvent.user_id == user.id).values(ip=None))
    ctx.db.execute(
        delete(LoginAttempt).where(LoginAttempt.key == rate_limit.account_key(user.email))
    )
    ctx.db.delete(user)
    ctx.db.flush()
    record_event(ctx.db, SecurityEventType.ACCOUNT_DELETED, ctx.now)
    ctx.db.commit()
