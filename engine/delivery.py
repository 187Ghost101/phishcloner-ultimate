"""
PhishCloner Engine — Module 6: Delivery Engine
Signé Ghost1o1 — v1.0.0

Livraison de phishing par email (SMTP, Graph API, Mailgun, SES)
+ SMS (Twilio) + QR codes + Voicemail.
"""

import asyncio
import base64
import json
import logging
import os
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

log = logging.getLogger("PhishCloner.Delivery")


@dataclass
class DeliveryResult:
    """Résultat d'une livraison."""
    target: str
    channel: str
    success: bool
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    message_id: Optional[str] = None


class DeliveryEngine:
    """
    Module 6: Delivery Engine — multi-canal.
    """

    def __init__(self, default_template_dir: str = "templates"):
        self.template_dir = Path(default_template_dir)
        self.results: List[DeliveryResult] = []
        self.stats = {
            "sent": 0,
            "failed": 0,
            "opened": 0,
            "clicked": 0,
        }

    def render_template(
        self,
        template_name: str,
        target_email: str,
        target_name: str = "",
        sender_name: str = "IT Security",
        phish_url: str = "https://phish.example.com/login",
        extras: Optional[Dict] = None,
    ) -> Tuple[str, str]:
        """
        Rend un template email HTML + plain text.

        Returns:
            (html_body, plain_body)
        """
        extras = extras or {}
        first_name = target_name.split()[0] if target_name else target_email.split("@")[0].replace(".", " ").title()

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>{sender_name}</title></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="border-bottom: 2px solid #0078d4; padding-bottom: 10px; margin-bottom: 20px;">
        <h2 style="color: #0078d4; margin: 0;">{sender_name}</h2>
    </div>
    <p>Hi {first_name},</p>
    <p>Action required: Please verify your account credentials to maintain access to our services.</p>
    <p style="margin: 30px 0; text-align: center;">
        <a href="{phish_url}" style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Now</a>
    </p>
    <p>This is an automated security message. If you do not act within 24 hours, your access may be suspended.</p>
    <p style="color: #666; font-size: 12px; margin-top: 30px;">
        {sender_name} Team<br>
        This message was sent to {target_email}
    </p>
</body>
</html>"""

        plain = f"""Hi {first_name},

Action required: Please verify your account credentials to maintain access to our services.

Click here to verify: {phish_url}

This is an automated security message. If you do not act within 24 hours, your access may be suspended.

{sender_name} Team
This message was sent to {target_email}"""

        return html, plain

    # ── SMTP ──

    def send_smtp(
        self,
        target_email: str,
        subject: str,
        html_body: str,
        plain_body: str,
        from_addr: str,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        attachments: Optional[List[Path]] = None,
    ) -> DeliveryResult:
        """Envoi via SMTP classique."""
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = from_addr
            msg["To"] = target_email
            msg["Subject"] = subject
            msg.attach(MIMEText(plain_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Attachments
            if attachments:
                for att_path in attachments:
                    if att_path.exists():
                        with open(att_path, "rb") as f:
                            part = MIMEBase("application", "octet-stream")
                            part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            "Content-Disposition",
                            f"attachment; filename= {att_path.name}",
                        )
                        msg.attach(part)

            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls(context=context)
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, [target_email], msg.as_string())

            self.results.append(DeliveryResult(target=target_email, channel="smtp", success=True))
            self.stats["sent"] += 1
            log.info(f"📧 SMTP sent to {target_email}")
            return self.results[-1]
        except Exception as e:
            self.results.append(DeliveryResult(target=target_email, channel="smtp", success=False, error=str(e)))
            self.stats["failed"] += 1
            log.error(f"❌ SMTP failed for {target_email}: {e}")
            return self.results[-1]

    # ── Office 365 Graph API ──

    async def send_office365(
        self,
        target_email: str,
        subject: str,
        html_body: str,
        from_addr: str,
        access_token: str,
    ) -> DeliveryResult:
        """Envoi via Microsoft Graph API."""
        try:
            url = f"https://graph.microsoft.com/v1.0/users/{from_addr}/sendMail"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            payload = {
                "message": {
                    "subject": subject,
                    "body": {"contentType": "HTML", "content": html_body},
                    "toRecipients": [{"emailAddress": {"address": target_email}}],
                },
                "saveToSentItems": "true",
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers) as resp:
                    if resp.status == 202:
                        self.stats["sent"] += 1
                        self.results.append(DeliveryResult(target=target_email, channel="office365", success=True))
                        return self.results[-1]
                    else:
                        err = await resp.text()
                        self.stats["failed"] += 1
                        self.results.append(DeliveryResult(target=target_email, channel="office365", success=False, error=err))
                        return self.results[-1]
        except Exception as e:
            self.stats["failed"] += 1
            self.results.append(DeliveryResult(target=target_email, channel="office365", success=False, error=str(e)))
            return self.results[-1]

    # ── SMS via Twilio ──

    async def send_sms_twilio(
        self,
        target_phone: str,
        body: str,
        account_sid: str,
        auth_token: str,
        from_number: str,
    ) -> DeliveryResult:
        """Envoi SMS via Twilio API."""
        try:
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            auth = aiohttp.BasicAuth(account_sid, auth_token)
            data = {
                "From": from_number,
                "To": target_phone,
                "Body": body,
            }
            async with aiohttp.ClientSession(auth=auth) as session:
                async with session.post(url, data=data) as resp:
                    if resp.status in (200, 201):
                        result = await resp.json()
                        self.stats["sent"] += 1
                        self.results.append(DeliveryResult(
                            target=target_phone, channel="sms", success=True,
                            message_id=result.get("sid"),
                        ))
                        return self.results[-1]
                    else:
                        err = await resp.text()
                        self.stats["failed"] += 1
                        self.results.append(DeliveryResult(target=target_phone, channel="sms", success=False, error=err))
                        return self.results[-1]
        except Exception as e:
            self.stats["failed"] += 1
            self.results.append(DeliveryResult(target=target_phone, channel="sms", success=False, error=str(e)))
            return self.results[-1]

    # ── Batch ──

    async def send_batch_smtp(
        self,
        target_emails: List[str],
        subject: str,
        from_addr: str,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        sender_name: str = "IT Security",
        phish_url: str = "https://phish.example.com/login",
    ) -> List[DeliveryResult]:
        """Envoi en batch via SMTP avec rendu automatique des templates."""
        results = []
        for target in target_emails:
            html, plain = self.render_template(
                template_name="generic",
                target_email=target,
                target_name="",
                sender_name=sender_name,
                phish_url=phish_url,
            )
            result = self.send_smtp(
                target_email=target,
                subject=subject,
                html_body=html,
                plain_body=plain,
                from_addr=from_addr,
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                smtp_user=smtp_user,
                smtp_pass=smtp_pass,
            )
            results.append(result)
            # Rate limit between sends
            await asyncio.sleep(1.0)
        return results

    def save_report(self, output_path: str = "logs/delivery_report.jsonl") -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for r in self.results:
                f.write(json.dumps(r.__dict__) + "\n")
        return path
