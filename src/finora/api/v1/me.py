"""Endpoints /api/v1/me: perfil del usuario de la sesión (specs/api-contracts.md §4.6).

Ningún endpoint recibe un identificador de usuario: siempre es el de la sesión (RN-AUTH-08).
"""

from dataclasses import asdict

from fastapi import APIRouter, BackgroundTasks, Depends, Response, status

from finora.api.v1.auth import Context, Sender, schedule_emails
from finora.auth import service
from finora.auth.dependencies import (
    CurrentSession,
    CurrentUser,
    DbSession,
    RecentlyReauthenticated,
    purge_periodically,
    verify_request_origin,
)
from finora.auth.schemas import (
    AcceptedResponse,
    ChangePasswordRequest,
    CodeRequest,
    DeleteAccountRequest,
    MfaSetupResponse,
    ProfileResponse,
    RecoveryCodesResponse,
    RenameRequest,
)
from finora.auth.sessions import clear_session_cookie

router = APIRouter(
    prefix="/me",
    tags=["me"],
    dependencies=[Depends(verify_request_origin), Depends(purge_periodically)],
)


@router.get("")
def get_profile(user: CurrentUser, db: DbSession) -> ProfileResponse:
    return ProfileResponse(**asdict(service.profile(db, user)))


@router.patch("")
def rename(body: RenameRequest, user: CurrentUser, db: DbSession) -> ProfileResponse:
    return ProfileResponse(**asdict(service.rename(db, user, body.name)))


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: ChangePasswordRequest,
    user: CurrentUser,
    session: CurrentSession,
    ctx: Context,
    tasks: BackgroundTasks,
    sender: Sender,
) -> None:
    service.change_password(ctx, user, session, body.current_password, body.new_password)
    schedule_emails(tasks, sender, ctx)


@router.post("/password/setup", status_code=status.HTTP_202_ACCEPTED)
def request_password_setup(
    user: CurrentUser, ctx: Context, tasks: BackgroundTasks, sender: Sender
) -> AcceptedResponse:
    service.request_password_setup(ctx, user)
    schedule_emails(tasks, sender, ctx)
    return AcceptedResponse(message=service.SETUP_MESSAGE)


# --- Verificación en dos pasos (RF-AUTH-10 a 13) ------------------------------------------


@router.post("/mfa/setup")
def setup_mfa(user: CurrentUser, _: RecentlyReauthenticated, ctx: Context) -> MfaSetupResponse:
    setup = service.setup_mfa(ctx, user)
    return MfaSetupResponse(secret=setup.secret, otpauth_uri=setup.otpauth_uri)


@router.post("/mfa/confirm")
def confirm_mfa(body: CodeRequest, user: CurrentUser, ctx: Context) -> RecoveryCodesResponse:
    return RecoveryCodesResponse(recovery_codes=service.confirm_mfa(ctx, user, body.code))


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_mfa(
    body: CodeRequest, user: CurrentUser, _: RecentlyReauthenticated, ctx: Context
) -> None:
    service.disable_mfa(ctx, user, body.code)


# --- Eliminación de la cuenta (RF-AUTH-16) ------------------------------------------------


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(
    body: DeleteAccountRequest,
    user: CurrentUser,
    _: RecentlyReauthenticated,
    ctx: Context,
    response: Response,
) -> None:
    service.delete_account(ctx, user, body.confirmation)
    clear_session_cookie(response)
