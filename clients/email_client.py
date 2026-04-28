"""SMTP email client.
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Any

log = logging.getLogger("email_client")

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USER).strip() or SMTP_USER
EMAIL_TO = [a.strip() for a in os.environ.get("EMAIL_TO", "").split(",") if a.strip()]

SMTP_TIMEOUT = 30


def is_configured() -> bool:
    """True when SMTP is configured well enough to actually send."""
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and EMAIL_TO)


def send_email(subject: str, body: str) -> dict[str, Any]:
    """Send a plaintext email. Dry-runs if SMTP isn't fully configured.

    Returns: {ok, sent, dry_run, to, error}.
    """
    if not is_configured():
        return {"ok": True, "sent": 0, "to": EMAIL_TO, "error": None, }

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(EMAIL_TO)
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        log.info("email sent: subject=%r to=%s", subject, EMAIL_TO)
        return {"ok": True, "sent": len(EMAIL_TO), "to": EMAIL_TO, "error": None, }
    except Exception as exc:
        log.error("email send failed: %s", exc)
        return {"ok": False, "sent": 0, "to": EMAIL_TO, "error": str(exc), }
