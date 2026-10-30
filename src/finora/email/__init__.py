"""Correos transaccionales (ADR-0002)."""

from finora.email.sender import (
    EmailDeliveryError,
    EmailSender,
    InMemoryEmailSender,
    OutgoingEmail,
    SmtpEmailSender,
    get_email_sender,
)

__all__ = [
    "EmailDeliveryError",
    "EmailSender",
    "InMemoryEmailSender",
    "OutgoingEmail",
    "SmtpEmailSender",
    "get_email_sender",
]
