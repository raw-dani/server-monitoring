"""SMTP email sender with STARTTLS/SSL, retry backoff, and PDF attachment support."""

from __future__ import annotations

import email.encoders
import os
import smtplib
import socket
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional, Sequence, Tuple

from shsm.core.context import Context
from shsm.utils.redact import redact
from shsm.utils.retry import retry_call

EMAIL_PRESETS: Dict[str, Dict[str, Any]] = {
    "gmail": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "security": "starttls",
    },
    "brevo": {
        "smtp_host": "smtp-relay.brevo.com",
        "smtp_port": 587,
        "security": "starttls",
    },
    "mailtrap": {
        "smtp_host": "live.smtp.mailtrap.io",
        "smtp_port": 587,
        "security": "starttls",
    },
    "mailtrap_sandbox": {
        "smtp_host": "sandbox.smtp.mailtrap.io",
        "smtp_port": 2525,
        "security": "starttls",
    },
    "sendgrid": {
        "smtp_host": "smtp.sendgrid.net",
        "smtp_port": 587,
        "security": "starttls",
        "username": "apikey",
    },
    "mailgun": {
        "smtp_host": "smtp.mailgun.org",
        "smtp_port": 587,
        "security": "starttls",
    },
    "postmark": {
        "smtp_host": "smtp.postmarkapp.com",
        "smtp_port": 587,
        "security": "starttls",
    },
    "ses": {
        "smtp_port": 587,
        "security": "starttls",
    },
    "local": {
        "smtp_host": "127.0.0.1",
        "smtp_port": 25,
        "security": "none",
    },
}


class SMTPTransport:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.config = ctx.config

    def send_email(
        self,
        subject: str,
        html_body: str,
        recipients: Optional[Sequence[str]] = None,
        pdf_attachment_path: Optional[str] = None,
        text_body: Optional[str] = None,
    ) -> Tuple[bool, int, Optional[str]]:
        """Send email with bounded retry. Returns (success, attempts, error_message)."""
        cfg = self.config.section("email")
        if not cfg.get("enabled", True):
            return False, 0, "Email is disabled in configuration"

        provider = str(cfg.get("provider", "custom")).lower()
        preset = EMAIL_PRESETS.get(provider, {})

        host = str(cfg.get("smtp_host") or preset.get("smtp_host") or "localhost")
        port = int(cfg.get("smtp_port") or preset.get("smtp_port") or 587)
        sec = str(cfg.get("security") or preset.get("security") or "starttls").lower()
        user = str(cfg.get("username") or preset.get("username") or "")
        password = self.config.secret("smtp_password")

        configured_from = cfg.get("from_address")
        if configured_from:
            from_addr = str(configured_from)
        elif user and "@" in user:
            from_addr = user
        else:
            from_addr = f"shsm@{socket.getfqdn()}"

        from_name = str(cfg.get("from_name", "GM Teknologi Server Monitor"))
        target_recipients = list(recipients or cfg.get("recipients", ["rohmataliwardani@gmail.com"]))

        if not target_recipients:
            return False, 0, "No recipients specified"

        timeout = float(cfg.get("timeout_seconds", 20))
        retries = int(cfg.get("retries", 3))
        base_delay = float(cfg.get("retry_base_delay_seconds", 2.0))
        max_delay = float(cfg.get("retry_max_delay_seconds", 60.0))

        # Build MIME message
        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
        msg["To"] = ", ".join(target_recipients)

        alt = MIMEMultipart("alternative")
        if text_body:
            alt.attach(MIMEText(text_body, "plain", "utf-8"))
        alt.attach(MIMEText(html_body, "html", "utf-8"))
        msg.attach(alt)

        # Attach PDF if present
        if pdf_attachment_path and os.path.isfile(pdf_attachment_path):
            try:
                with open(pdf_attachment_path, "rb") as fh:
                    part = MIMEBase("application", "pdf")
                    part.set_payload(fh.read())
                email.encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{os.path.basename(pdf_attachment_path)}"',
                )
                msg.attach(part)
            except OSError as exc:
                return False, 0, f"Cannot read attachment {pdf_attachment_path}: {exc}"

        def _do_send():
            server: Any
            if sec == "ssl":
                server = smtplib.SMTP_SSL(host, port, timeout=timeout)
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)

            with server:
                if sec == "starttls":
                    server.starttls()
                if user and password:
                    server.login(user, password)
                server.send_message(msg, from_addr=from_addr, to_addrs=target_recipients)

        try:
            _, attempts = retry_call(
                _do_send,
                retries=retries,
                base_delay=base_delay,
                max_delay=max_delay,
                retry_on=(smtplib.SMTPException, OSError, TimeoutError),
            )
            return True, attempts, None
        except Exception as exc:
            return False, retries + 1, redact(str(exc))
