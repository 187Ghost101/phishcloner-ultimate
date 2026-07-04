"""
PhishCloner Engine — Module 7: Proxy Pool
Signé Ghost1o1 — v1.0.0

Rotating SOCKS5/HTTP proxy pool + Tor fallback.
"""

import asyncio
import json
import logging
import random
import socket
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

log = logging.getLogger("PhishCloner.ProxyPool")

PROXY_SOURCES = [
    {
        "name": "proxyscrape",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=http&proxy_format=protocolipport&format=json&timeout=20000",
        "parser": "json",
    },
    {
        "name": "geonode",
        "url": "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps",
        "parser": "geonode",
    },
    {
        "name": "proxy-list",
        "url": "https://www.proxy-list.download/api/v1/get?type=http",
        "parser": "text",
    },
]


@dataclass
class Proxy:
    """Représente un proxy individuel."""
    host: str
    port: int
    protocol: str = "http"
    source: str = "unknown"
    country: str = "??"
    latency: float = 999.0
    failures: int = 0
    alive: bool = True

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"


class ProxyPool:
    """Pool de proxies rotatifs avec health checking."""

    def __init__(
        self,
        pool_size: int = 20,
        rotation_strategy: str = "weighted",
        max_failures: int = 3,
        health_check_interval: int = 300,
        use_tor: bool = False,
        tor_socks_port: int = 9050,
        cache_file: str = "data/proxy_cache.json",
    ):
        self.pool_size = pool_size
        self.rotation_strategy = rotation_strategy
        self.max_failures = max_failures
        self.health_check_interval = health_check_interval
        self.use_tor = use_tor
        self.tor_proxy = f"socks5://127.0.0.1:{tor_socks_port}"
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

        self._proxies: Dict[str, Proxy] = {}
        self._round_robin_index = 0
        self._lock = asyncio.Lock()
        self.stats = {
            "total_proxies": 0,
            "alive": 0,
            "requests_sent": 0,
            "requests_failed": 0,
        }

    async def scrape_proxies(self, min_proxies: int = 10) -> int:
        new_proxies = 0
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            for source in PROXY_SOURCES:
                try:
                    async with session.get(source["url"]) as resp:
                        data = await resp.text()
                    if source["parser"] == "json":
                        try:
                            items = json.loads(data)
                            for item in items:
                                host = item.get("ip") or item.get("host")
                                port = item.get("port")
                                if host and port:
                                    self._add_proxy(Proxy(host=host, port=int(port), source=source["name"]))
                                    new_proxies += 1
                        except (json.JSONDecodeError, TypeError):
                            pass
                    elif source["parser"] == "geonode":
                        try:
                            items = json.loads(data).get("data", [])
                            for item in items:
                                self._add_proxy(Proxy(
                                    host=item.get("ip"), port=int(item.get("port", 8080)),
                                    source=source["name"], country=item.get("country", "??"),
                                ))
                                new_proxies += 1
                        except (json.JSONDecodeError, TypeError):
                            pass
                    elif source["parser"] == "text":
                        for line in data.splitlines():
                            line = line.strip()
                            if ":" in line and not line.startswith("#"):
                                parts = line.split(":")
                                if len(parts) >= 2:
                                    try:
                                        self._add_proxy(Proxy(host=parts[0], port=int(parts[1]), source=source["name"]))
                                        new_proxies += 1
                                    except (ValueError, IndexError):
                                        pass
                except Exception as e:
                    log.debug(f"Scrape failed for {source['name']}: {e}")
        log.info(f"Scraped {new_proxies} new proxies — pool: {len(self._proxies)}")
        return new_proxies

    def _add_proxy(self, proxy: Proxy):
        key = f"{proxy.host}:{proxy.port}"
        if key not in self._proxies:
            self._proxies[key] = proxy

    async def health_check(self, test_url: str = "https://httpbin.org/ip") -> int:
        alive = 0

        async def check_single(proxy: Proxy):
            nonlocal alive
            try:
                start = time.monotonic()
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8)) as session:
                    async with session.get(test_url, proxy=proxy.url, ssl=False) as resp:
                        if resp.status == 200:
                            proxy.latency = (time.monotonic() - start) * 1000
                            proxy.alive = True
                            proxy.failures = 0
                            alive += 1
            except Exception:
                proxy.failures += 1
                if proxy.failures >= self.max_failures:
                    proxy.alive = False

        await asyncio.gather(*[check_single(p) for p in self._proxies.values()], return_exceptions=True)
        self._proxies = {k: v for k, v in self._proxies.items() if v.alive}
        self.stats["alive"] = alive
        self.stats["total_proxies"] = len(self._proxies)
        log.info(f"Health check: {alive} alive")
        return alive

    async def get_proxy(self) -> Optional[str]:
        async with self._lock:
            alive_proxies = [p for p in self._proxies.values() if p.alive]
            if not alive_proxies:
                if self.use_tor:
                    return self.tor_proxy
                return None
            if self.rotation_strategy == "round_robin":
                proxy = alive_proxies[self._round_robin_index % len(alive_proxies)]
                self._round_robin_index += 1
            elif self.rotation_strategy == "random":
                proxy = random.choice(alive_proxies)
            else:  # weighted
                weights = [1000.0 / max(p.latency, 1.0) for p in alive_proxies]
                total = sum(weights)
                weights = [w / total for w in weights]
                proxy = random.choices(alive_proxies, weights=weights, k=1)[0]
            return proxy.url

    async def mark_failure(self, proxy_url: str):
        async with self._lock:
            parsed = urlparse(proxy_url)
            key = f"{parsed.hostname}:{parsed.port}"
            if key in self._proxies:
                self._proxies[key].failures += 1
                if self._proxies[key].failures >= self.max_failures:
                    self._proxies[key].alive = False

    @staticmethod
    def check_tor() -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(("127.0.0.1", 9050))
            s.close()
            return True
        except Exception:
            return False

    async def start(self, initial_scrape: bool = True):
        if self.cache_file.exists():
            try:
                cached = json.loads(self.cache_file.read_text())
                for p_data in cached:
                    self._add_proxy(Proxy(**p_data))
            except Exception:
                pass
        if initial_scrape:
            await self.scrape_proxies(min_proxies=self.pool_size)
        await self.health_check()


class ProxiedMITMTransport:
    """Wrapper aiohttp autour du ProxyPool pour le MITM."""

    def __init__(self, proxy_pool: ProxyPool):
        self.pool = proxy_pool

    async def request(self, method: str, url: str, **kwargs):
        proxy_url = await self.pool.get_proxy()
        if proxy_url:
            kwargs["proxy"] = proxy_url
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            async with session.request(method, url, **kwargs) as resp:
                resp._body = await resp.read()
                return resp
