"""Outgoing e-mail through an SMTP relay (Google Workspace's smtp-relay.gmail.com,
unauthenticated from a registered IP, STARTTLS). The relay is configured in the
admin console (settings smtp_host, smtp_port, mail_from); the OSC_SMTP_*
environment variables only seed those settings on first start. No host = off.
Addresses are used for the one message and never stored."""

from __future__ import annotations

import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

from .config import env

ENV_DEFAULTS = {
    "smtp_host": env("SMTP_HOST", "").strip(),
    "smtp_port": env("SMTP_PORT", "587").strip() or "587",
    "mail_from": env("MAIL_FROM", "Ocean Software Check <noreply@oceansoftwarecheck.com>").strip(),
}

_ADDRESS_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


@dataclass(frozen=True)
class Relay:
    host: str
    port: int
    sender: str

    @property
    def enabled(self) -> bool:
        return bool(self.host)


def relay_from_settings(get_setting) -> Relay:
    """Builds the relay from the settings store (a callable key -> str)."""
    try:
        port = int(get_setting("smtp_port") or 587)
    except ValueError:
        port = 587
    return Relay(host=(get_setting("smtp_host") or "").strip(), port=port,
                 sender=(get_setting("mail_from") or "").strip() or ENV_DEFAULTS["mail_from"])


def valid_address(value: str) -> bool:
    return bool(_ADDRESS_RE.fullmatch(value.strip())) and len(value) <= 254


def valid_host(value: str) -> bool:
    return value == "" or bool(_HOST_RE.fullmatch(value))


def valid_sender(value: str) -> bool:
    """Either a bare address or `Display Name <address>`."""
    m = re.fullmatch(r"(?:[^<>]+ )?<([^<>]+)>|([^<>\s]+)", value.strip())
    return bool(m) and valid_address(m.group(1) or m.group(2))


def send(relay: Relay, to: str, subject: str, text: str,
         attachments: list[tuple[str, bytes, str]] | None = None) -> None:
    """Sends one message; raises on failure. `attachments`: (filename, bytes, mime type)."""
    if not relay.enabled:
        raise RuntimeError("No SMTP relay configured.")
    msg = EmailMessage()
    msg["From"] = relay.sender
    msg["To"] = to.strip()
    msg["Subject"] = subject
    msg.set_content(text)
    for filename, data, mimetype in attachments or []:
        maintype, subtype = mimetype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    with smtplib.SMTP(relay.host, relay.port, timeout=30) as smtp:
        smtp.ehlo()
        if relay.port != 465:
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
        smtp.send_message(msg)
