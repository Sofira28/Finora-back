"""Puerto de envío de correos y sus adaptadores (ADR-0002, DP-ARQ-14)."""

import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Annotated, Protocol

from fastapi import Depends

from finora.config import Settings, get_settings


@dataclass(frozen=True)
class OutgoingEmail:
    to: str
    subject: str
    text: str
    html: str


class EmailDeliveryError(Exception):
    """El correo no se pudo entregar al servidor SMTP."""


class EmailSender(Protocol):
    def send(self, email: OutgoingEmail) -> None: ...


class SmtpEmailSender:
    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._username = username
        self._password = password
        self._timeout = timeout
        # Por defecto se validan certificado y nombre del servidor.
        self._ssl_context = ssl_context or ssl.create_default_context()

    def build_message(self, email: OutgoingEmail) -> EmailMessage:
        # EmailMessage rechaza saltos de línea en cabeceras (inyección de cabeceras).
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email.to
        message["Subject"] = email.subject
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(domain="finora")
        message.set_content(email.text)
        message.add_alternative(email.html, subtype="html")
        return message

    def send(self, email: OutgoingEmail) -> None:
        message = self.build_message(email)
        try:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
                if self._username is not None:
                    # Con credenciales, nunca se envían sin cifrar.
                    smtp.starttls(context=self._ssl_context)
                    smtp.login(self._username, self._password or "")
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise EmailDeliveryError(f"No se pudo enviar el correo a {self._host}") from exc


class InMemoryEmailSender:
    """Guarda los correos en una lista en vez de enviarlos (pruebas)."""

    def __init__(self) -> None:
        self.outbox: list[OutgoingEmail] = []

    def send(self, email: OutgoingEmail) -> None:
        self.outbox.append(email)


def get_email_sender(settings: Annotated[Settings, Depends(get_settings)]) -> EmailSender:
    return SmtpEmailSender(
        host=settings.smtp_host,
        port=settings.smtp_port,
        sender=settings.email_from,
        username=settings.smtp_username,
        password=(
            settings.smtp_password.get_secret_value()
            if settings.smtp_password is not None
            else None
        ),
    )
