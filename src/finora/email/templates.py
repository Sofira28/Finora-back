"""Plantillas de correo en español colombiano (RNF-AUTH-08).

Cada plantilla devuelve texto plano y HTML. Los enlaces los construye quien llama,
con FINORA_WEB_URL; aquí solo se escapan para el HTML.
"""

from html import escape

from finora.email.sender import OutgoingEmail

_FIRMA = "El equipo de FINORA\nTu dinero, más claro."


def _html(name: str, paragraphs: list[str], link: tuple[str, str] | None = None) -> str:
    # paragraphs es HTML de confianza (texto fijo de las plantillas); name y link se escapan.
    body = "".join(f"<p>{p}</p>" for p in paragraphs)
    button = ""
    if link is not None:
        label, url = link
        button = f'<p><a href="{escape(url)}">{escape(label)}</a></p>'
    return (
        '<!doctype html><html lang="es-CO"><body style="font-family: Inter, Arial, sans-serif">'
        f"<p>Hola, {escape(name)}:</p>{body}{button}"
        "<p>El equipo de FINORA<br>Tu dinero, más claro.</p></body></html>"
    )


def verify_email(to: str, name: str, link: str) -> OutgoingEmail:
    return OutgoingEmail(
        to=to,
        subject="Confirma tu correo en FINORA",
        text=(
            f"Hola, {name}:\n\n"
            "Gracias por registrarte en FINORA. Para activar tu cuenta, confirma tu correo "
            f"abriendo este enlace:\n\n{link}\n\n"
            "El enlace vence en 24 horas y solo se puede usar una vez.\n"
            "Si no creaste esta cuenta, ignora este mensaje.\n\n" + _FIRMA
        ),
        html=_html(
            name,
            [
                "Gracias por registrarte en FINORA. Para activar tu cuenta, confirma tu correo.",
                "El enlace vence en 24 horas y solo se puede usar una vez. "
                "Si no creaste esta cuenta, ignora este mensaje.",
            ],
            ("Confirmar mi correo", link),
        ),
    )


def password_reset(to: str, name: str, link: str, *, first_password: bool) -> OutgoingEmail:
    # first_password: cuentas que solo usan Google y crean su primera contraseña (RF-AUTH-18).
    if first_password:
        subject = "Crea tu contraseña de FINORA"
        intro = "Recibimos una solicitud para crear una contraseña para tu cuenta de FINORA."
        label = "Crear mi contraseña"
    else:
        subject = "Restablece tu contraseña de FINORA"
        intro = "Recibimos una solicitud para restablecer la contraseña de tu cuenta de FINORA."
        label = "Restablecer mi contraseña"
    warning = (
        "El enlace vence en 1 hora y solo se puede usar una vez. "
        "Si no hiciste esta solicitud, ignora este mensaje: tu contraseña no cambiará."
    )
    return OutgoingEmail(
        to=to,
        subject=subject,
        text=f"Hola, {name}:\n\n{intro}\n\n{link}\n\n{warning}\n\n" + _FIRMA,
        html=_html(name, [intro, warning], (label, link)),
    )


def duplicate_registration(to: str, name: str, login_link: str, reset_link: str) -> OutgoingEmail:
    # Aviso al dueño del correo; la respuesta HTTP no revela que la cuenta existe (VAL-AUTH-04).
    intro = "Alguien intentó crear una cuenta en FINORA con tu correo, pero ya tienes una."
    advice = (
        "Si fuiste tú, inicia sesión con tu cuenta. Si olvidaste tu contraseña, "
        "puedes restablecerla. Si no fuiste tú, no tienes que hacer nada."
    )
    return OutgoingEmail(
        to=to,
        subject="Ya tienes una cuenta en FINORA",
        text=(
            f"Hola, {name}:\n\n{intro}\n\n{advice}\n\n"
            f"Iniciar sesión: {login_link}\nRestablecer contraseña: {reset_link}\n\n" + _FIRMA
        ),
        html=_html(
            name,
            [
                escape(intro),
                escape(advice),
                f'<a href="{escape(reset_link)}">Restablecer mi contraseña</a>',
            ],
            ("Iniciar sesión", login_link),
        ),
    )


def password_changed(to: str, name: str, reset_link: str) -> OutgoingEmail:
    intro = "La contraseña de tu cuenta de FINORA cambió y cerramos las demás sesiones abiertas."
    advice = "Si no fuiste tú, restablece tu contraseña de inmediato."
    return OutgoingEmail(
        to=to,
        subject="Tu contraseña de FINORA cambió",
        text=f"Hola, {name}:\n\n{intro}\n\n{advice}\n\n{reset_link}\n\n" + _FIRMA,
        html=_html(name, [intro, advice], ("Restablecer mi contraseña", reset_link)),
    )
