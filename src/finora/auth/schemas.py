"""Modelos de request/response de /auth y /me (specs/api-contracts.md §4)."""

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from finora.validation import reject_control_characters

# Tope de entrada antes de normalizar y calcular el hash: la política (RN-AUTH-02) la aplica
# el servicio con sus mensajes; esto solo evita cuerpos desmedidos.
RawPassword = Annotated[str, Field(min_length=1, max_length=1024)]


# RN-AUTH-03: sin espacios en los extremos, de 1 a 100 caracteres, sin caracteres de control.
Name = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=100),
    AfterValidator(reject_control_characters),
]
Token = Annotated[str, Field(min_length=1, max_length=256)]
# En el inicio de sesión cualquier texto vale: un correo mal escrito recibe el mismo 401.
LoginEmail = Annotated[str, Field(min_length=1, max_length=320)]
# TOTP (6 dígitos) o código de recuperación (ABCDE-FGHIJ); el formato lo revisa el servicio.
Code = Annotated[str, Field(min_length=1, max_length=32)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Request):
    email: EmailStr
    name: Name
    password: RawPassword
    privacy_policy_version: Annotated[str, Field(min_length=1, max_length=32)]


class VerifyEmailRequest(_Request):
    token: Token


class EmailRequest(_Request):
    email: EmailStr


class LoginRequest(_Request):
    email: LoginEmail
    password: RawPassword


class AcceptedResponse(BaseModel):
    message: str


class LoginResponse(BaseModel):
    next: Literal["app", "mfa"]


class SessionUser(BaseModel):
    name: str
    email: str


class SessionResponse(BaseModel):
    # Sin sesión: stage, csrf_token y user en null (la página de inicio de sesión
    # necesita google_enabled antes de tener sesión).
    stage: Literal["active", "mfa_pending", "link_pending"] | None
    csrf_token: str | None
    google_enabled: bool
    user: SessionUser | None


class ResetPasswordRequest(_Request):
    token: Token
    new_password: RawPassword


class ChangePasswordRequest(_Request):
    current_password: RawPassword
    new_password: RawPassword


class RenameRequest(_Request):
    name: Name


class ProfileResponse(BaseModel):
    name: str
    email: str
    has_password: bool
    google_linked: bool
    mfa_enabled: bool


class CodeRequest(_Request):
    code: Code


class ReauthenticateRequest(_Request):
    # Sin contraseña solo tras volver de Google con MFA activa (RF-AUTH-21).
    password: RawPassword | None = None
    code: Code | None = None


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class GoogleLinkRequest(_Request):
    password: RawPassword


class DeleteAccountRequest(_Request):
    confirmation: Annotated[str, Field(max_length=32)]
