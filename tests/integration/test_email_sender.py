"""Pruebas del envío de correos y sus plantillas (T-AUTH-BE-02, RF-AUTH-02/08, RNF-AUTH-08)."""

import ssl
from collections.abc import Callable, Iterator
from os import PathLike
from typing import Any, Self

import httpx
import pytest
from testcontainers.community.mailpit import MailpitContainer, MailpitUser

from finora.config import Settings
from finora.email import (
    EmailDeliveryError,
    InMemoryEmailSender,
    OutgoingEmail,
    SmtpEmailSender,
    get_email_sender,
    templates,
)

REMITENTE = "FINORA <no-responder@finora.local>"
ENLACE = "http://localhost:5173/verificar-correo?token=abc123"
CLAVE_MAILPIT = "clave-de-prueba"

CORREO = OutgoingEmail(
    to="ana@correo.com", subject="Asunto de prueba", text="Texto plano", html="<p>HTML</p>"
)

PLANTILLAS: dict[str, Callable[[], OutgoingEmail]] = {
    "verificacion": lambda: templates.verify_email("ana@correo.com", ENLACE),
    "restablecer": lambda: templates.password_reset(
        "ana@correo.com", "Ana", ENLACE, first_password=False
    ),
    "primera_contrasena": lambda: templates.password_reset(
        "ana@correo.com", "Ana", ENLACE, first_password=True
    ),
    "registro_duplicado": lambda: templates.duplicate_registration(
        "ana@correo.com", "Ana", "http://x/iniciar-sesion", ENLACE
    ),
    "contrasena_cambiada": lambda: templates.password_changed("ana@correo.com", "Ana", ENLACE),
}


# --- Plantillas -------------------------------------------------------------------------


@pytest.mark.parametrize("nombre", PLANTILLAS)
def test_plantillas_tienen_texto_html_y_enlace(nombre: str) -> None:
    correo = PLANTILLAS[nombre]()
    assert correo.to == "ana@correo.com"
    assert correo.subject
    # La verificación va a una dirección sin confirmar: no lleva el nombre (QA-03).
    assert ("Hola:" if nombre == "verificacion" else "Hola, Ana:") in correo.text
    assert ENLACE in correo.text
    assert ENLACE in correo.html
    assert 'lang="es-CO"' in correo.html


def test_plantillas_indican_vencimiento_de_los_enlaces() -> None:
    assert "24 horas" in PLANTILLAS["verificacion"]().text  # RN-AUTH-04
    assert "1 hora" in PLANTILLAS["restablecer"]().text  # RN-AUTH-05
    assert "1 hora" in PLANTILLAS["primera_contrasena"]().text


def test_primera_contrasena_usa_otro_asunto() -> None:
    assert PLANTILLAS["primera_contrasena"]().subject == "Crea tu contraseña de FINORA"
    assert PLANTILLAS["restablecer"]().subject == "Restablece tu contraseña de FINORA"


def test_html_escapa_el_nombre_y_los_enlaces() -> None:
    correo = templates.password_reset(
        "ana@correo.com", '<script>alert("x")</script>', 'http://x/?a=1&b="2"', first_password=False
    )
    assert "<script>" not in correo.html
    assert "&lt;script&gt;" in correo.html
    assert 'href="http://x/?a=1&amp;b=&quot;2&quot;"' in correo.html


# --- Adaptadores sin red ----------------------------------------------------------------


def test_en_memoria_guarda_los_correos() -> None:
    sender = InMemoryEmailSender()
    sender.send(CORREO)
    assert sender.outbox == [CORREO]


def test_rechaza_saltos_de_linea_en_cabeceras() -> None:
    sender = SmtpEmailSender("localhost", 1025, REMITENTE)
    inyeccion = OutgoingEmail(
        to="ana@correo.com", subject="Hola\nBcc: otro@correo.com", text="t", html="h"
    )
    with pytest.raises(ValueError):
        sender.build_message(inyeccion)


def test_mensaje_con_texto_y_html() -> None:
    message = SmtpEmailSender("localhost", 1025, REMITENTE).build_message(CORREO)
    assert message["From"] == REMITENTE
    assert message["Subject"] == "Asunto de prueba"
    tipos = [parte.get_content_type() for parte in message.iter_parts()]
    assert tipos == ["text/plain", "text/html"]


def test_servidor_inalcanzable_lanza_error_de_entrega() -> None:
    sender = SmtpEmailSender("127.0.0.1", 1, REMITENTE, timeout=2)
    with pytest.raises(EmailDeliveryError):
        sender.send(CORREO)


def test_dependencia_usa_la_configuracion() -> None:
    settings = Settings(smtp_host="smtp.ejemplo.co", smtp_port=2525, _env_file=None)  # type: ignore[call-arg]
    sender = get_email_sender(settings)
    assert isinstance(sender, SmtpEmailSender)
    assert sender.build_message(CORREO)["From"] == settings.email_from


# --- Mailpit real -----------------------------------------------------------------------


class _MailpitContainer(MailpitContainer):
    """Monta el certificado de prueba con la opción `z` de Docker.

    Con SELinux activo (p. ej. Fedora), el contenedor no puede leer archivos de /tmp
    montados sin reetiquetar y Mailpit no arranca.
    """

    def with_volume_mapping(
        self, host: str | PathLike[str], container: str, mode: str = "ro"
    ) -> Self:
        return super().with_volume_mapping(host, container, f"{mode},z")


@pytest.fixture(scope="module")
def mailpit() -> Iterator[MailpitContainer]:
    usuarios = [MailpitUser("finora", CLAVE_MAILPIT)]
    with _MailpitContainer("axllent/mailpit:v1.32.0", users=usuarios) as container:
        yield container


@pytest.fixture
def api(mailpit: MailpitContainer) -> Iterator[httpx.Client]:
    base = f"http://{mailpit.get_container_host_ip()}:{mailpit.get_exposed_port(8025)}/api/v1"
    with httpx.Client(base_url=base, timeout=10) as client:
        client.delete("/messages")  # bandeja vacía en cada prueba
        yield client


def _sender(mailpit: MailpitContainer, password: str = CLAVE_MAILPIT) -> SmtpEmailSender:
    # STARTTLS con el certificado autofirmado del contenedor y usuario obligatorio.
    contexto = ssl.create_default_context(cadata=mailpit.tls_cert.decode())
    contexto.check_hostname = False
    return SmtpEmailSender(
        host=mailpit.get_container_host_ip(),
        port=int(mailpit.get_exposed_smtp_port()),
        sender=REMITENTE,
        username="finora",
        password=password,
        ssl_context=contexto,
    )


def _unico_mensaje(api: httpx.Client) -> dict[str, Any]:
    listado = api.get("/messages").json()
    assert listado["total"] == 1
    detalle: dict[str, Any] = api.get(f"/message/{listado['messages'][0]['ID']}").json()
    return detalle


@pytest.mark.mailpit
def test_smtp_entrega_con_starttls_y_credenciales(
    mailpit: MailpitContainer, api: httpx.Client
) -> None:
    _sender(mailpit).send(CORREO)
    mensaje = _unico_mensaje(api)
    assert mensaje["Subject"] == "Asunto de prueba"
    assert mensaje["To"][0]["Address"] == "ana@correo.com"
    assert mensaje["From"] == {"Name": "FINORA", "Address": "no-responder@finora.local"}
    assert mensaje["Text"].strip() == "Texto plano"
    assert "<p>HTML</p>" in mensaje["HTML"]


@pytest.mark.mailpit
@pytest.mark.parametrize("nombre", PLANTILLAS)
def test_smtp_entrega_cada_plantilla_en_utf8(
    nombre: str, mailpit: MailpitContainer, api: httpx.Client
) -> None:
    correo = PLANTILLAS[nombre]()
    _sender(mailpit).send(correo)
    mensaje = _unico_mensaje(api)
    assert mensaje["Subject"] == correo.subject  # tildes y ñ intactas
    assert ENLACE in mensaje["Text"]


@pytest.mark.mailpit
def test_smtp_rechaza_credenciales_incorrectas(mailpit: MailpitContainer) -> None:
    with pytest.raises(EmailDeliveryError):
        _sender(mailpit, password="incorrecta").send(CORREO)  # noqa: S106 - caso a probar


@pytest.mark.mailpit
def test_smtp_no_acepta_certificado_no_confiable(mailpit: MailpitContainer) -> None:
    # Sin el certificado del contenedor, la validación por defecto debe fallar.
    sender = SmtpEmailSender(
        host=mailpit.get_container_host_ip(),
        port=int(mailpit.get_exposed_smtp_port()),
        sender=REMITENTE,
        username="finora",
        password=CLAVE_MAILPIT,
    )
    with pytest.raises(EmailDeliveryError):
        sender.send(CORREO)
