"""Endpoints /api/v1/auth (specs/api-contracts.md §4.2 y §4.3)."""

import logging
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from finora.auth import service
from finora.auth.dependencies import (
    ClockDep,
    CurrentSession,
    CurrentUser,
    DbSession,
    LinkPendingSession,
    OptionalSession,
    PendingMfaSession,
    PreviousSession,
    SettingsDep,
    purge_periodically,
    verify_request_origin,
)
from finora.auth.google import GoogleOidcClient, get_google_client
from finora.auth.models import User
from finora.auth.rate_limit import client_ip
from finora.auth.schemas import (
    AcceptedResponse,
    CodeRequest,
    EmailRequest,
    GoogleLinkRequest,
    LoginRequest,
    LoginResponse,
    ReauthenticateRequest,
    RegisterRequest,
    ResetPasswordRequest,
    SessionResponse,
    SessionUser,
    VerifyEmailRequest,
)
from finora.auth.sessions import SessionStage, clear_session_cookie, set_session_cookie
from finora.email import EmailDeliveryError, EmailSender, OutgoingEmail, get_email_sender
from finora.errors import ApiProblemError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(verify_request_origin), Depends(purge_periodically)],
)


def request_context(
    request: Request, db: DbSession, clock: ClockDep, settings: SettingsDep
) -> service.RequestContext:
    return service.RequestContext(
        db=db, now=clock.now(), settings=settings, ip=client_ip(request, settings)
    )


Context = Annotated[service.RequestContext, Depends(request_context)]
Sender = Annotated[EmailSender, Depends(get_email_sender)]


def _send_quietly(sender: EmailSender, email: OutgoingEmail) -> None:
    try:
        sender.send(email)
    except EmailDeliveryError:
        # Sin la dirección en el registro (dato personal); el usuario puede pedir reenvío.
        logger.exception("No se pudo enviar un correo transaccional")


def schedule_emails(
    tasks: BackgroundTasks, sender: EmailSender, ctx: service.RequestContext
) -> None:
    for email in ctx.emails:
        tasks.add_task(_send_quietly, sender, email)


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(
    body: RegisterRequest, ctx: Context, tasks: BackgroundTasks, sender: Sender
) -> AcceptedResponse:
    service.register(ctx, body.email, body.name, body.password, body.privacy_policy_version)
    schedule_emails(tasks, sender, ctx)
    return AcceptedResponse(message=service.EMAIL_SENT_MESSAGE)


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
def verify_email(body: VerifyEmailRequest, ctx: Context) -> None:
    service.verify_email(ctx, body.token)


@router.post("/verify-email/resend", status_code=status.HTTP_202_ACCEPTED)
def resend_verification(
    body: EmailRequest, ctx: Context, tasks: BackgroundTasks, sender: Sender
) -> AcceptedResponse:
    service.resend_verification(ctx, body.email)
    schedule_emails(tasks, sender, ctx)
    return AcceptedResponse(message=service.RESEND_MESSAGE)


@router.post("/password/forgot", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    body: EmailRequest, ctx: Context, tasks: BackgroundTasks, sender: Sender
) -> AcceptedResponse:
    service.forgot_password(ctx, body.email)
    schedule_emails(tasks, sender, ctx)
    return AcceptedResponse(message=service.FORGOT_MESSAGE)


@router.post("/password/reset", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(
    body: ResetPasswordRequest, ctx: Context, tasks: BackgroundTasks, sender: Sender
) -> None:
    service.reset_password(ctx, body.token, body.new_password)
    schedule_emails(tasks, sender, ctx)


@router.post("/login")
def login(
    body: LoginRequest, ctx: Context, previous: PreviousSession, response: Response
) -> LoginResponse:
    result = service.login(ctx, body.email, body.password, previous)
    set_session_cookie(response, result.raw_session)
    return LoginResponse(next="app" if result.next == SessionStage.ACTIVE else "mfa")


@router.post("/login/mfa")
def login_mfa(
    body: CodeRequest, ctx: Context, session: PendingMfaSession, response: Response
) -> LoginResponse:
    raw = service.login_mfa(ctx, session, body.code)
    set_session_cookie(response, raw)
    return LoginResponse(next="app")


@router.post("/reauthenticate", status_code=status.HTTP_204_NO_CONTENT)
def reauthenticate(
    body: ReauthenticateRequest, ctx: Context, user: CurrentUser, session: CurrentSession
) -> None:
    service.reauthenticate(ctx, user, session, body.password, body.code)


# --- Google (§4.4) ------------------------------------------------------------------------

Google = Annotated[GoogleOidcClient | None, Depends(get_google_client)]
# Ata el flujo al navegador que lo empezó; solo viaja a las rutas de Google.
OAUTH_COOKIE = "finora_oauth_state"
_OAUTH_COOKIE_PATH = "/api/v1/auth/google"
_QUERY_MAX = 2048


@router.get("/google/start")
def google_start(
    ctx: Context,
    google: Google,
    session: OptionalSession,
    intent: Literal["login", "reauth"] = "login",
    privacy_policy_version: Annotated[str | None, Query(max_length=32)] = None,
) -> RedirectResponse:
    if google is None:
        raise ApiProblemError(404, "not_found")
    start = service.google_start(ctx, google, intent, session, privacy_policy_version)
    response = RedirectResponse(start.url, status_code=status.HTTP_302_FOUND)
    if start.raw_state is not None:
        response.set_cookie(
            OAUTH_COOKIE,
            start.raw_state,
            max_age=int(service.GOOGLE_FLOW_TTL.total_seconds()),
            path=_OAUTH_COOKIE_PATH,
            secure=True,
            httponly=True,
            samesite="lax",
        )
    return response


@router.get("/google/callback")
def google_callback(
    ctx: Context,
    google: Google,
    session: OptionalSession,
    state: Annotated[str | None, Query(max_length=_QUERY_MAX)] = None,
    code: Annotated[str | None, Query(max_length=_QUERY_MAX)] = None,
    error: Annotated[str | None, Query(max_length=_QUERY_MAX)] = None,
    browser_state: Annotated[str | None, Cookie(alias=OAUTH_COOKIE)] = None,
) -> RedirectResponse:
    if google is None:
        outcome = service.GoogleOutcome(service.LOGIN_ERROR)
    else:
        outcome = service.google_callback(
            ctx,
            google,
            state=state,
            code=code,
            error=error,
            browser_state=browser_state,
            previous=session,
        )
    response = RedirectResponse(
        f"{ctx.settings.web_url}{outcome.path}", status_code=status.HTTP_302_FOUND
    )
    response.delete_cookie(OAUTH_COOKIE, path=_OAUTH_COOKIE_PATH, secure=True, httponly=True)
    if outcome.raw_session is not None:
        set_session_cookie(response, outcome.raw_session)
    return response


@router.post("/google/link")
def google_link(
    body: GoogleLinkRequest, ctx: Context, session: LinkPendingSession, response: Response
) -> LoginResponse:
    result = service.google_link(ctx, session, body.password)
    set_session_cookie(response, result.raw_session)
    return LoginResponse(next="app" if result.next == SessionStage.ACTIVE else "mfa")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(ctx: Context, session: OptionalSession, response: Response) -> None:
    service.logout(ctx, session)
    clear_session_cookie(response)


@router.get("/session")
def get_session(session: OptionalSession, db: DbSession, settings: SettingsDep) -> SessionResponse:
    if session is None:
        return SessionResponse(
            stage=None, csrf_token=None, google_enabled=settings.google_enabled, user=None
        )
    user = None
    if session.stage == SessionStage.ACTIVE:
        account = db.get_one(User, session.user_id)
        user = SessionUser(name=account.name, email=account.email)
    return SessionResponse(
        stage=session.stage,  # type: ignore[arg-type]
        csrf_token=session.csrf_token,
        google_enabled=settings.google_enabled,
        user=user,
    )
