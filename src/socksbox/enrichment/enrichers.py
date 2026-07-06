from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterator
import aiohttp
from aiohttp_socks import SocksConnector

from socksbox.models import ProxyInfo
from socksbox.status import (
    IPINFO_FORBIDDEN_STATUS,
    _mark_proxy_not_working,
    _response_carries_forbidden,
    log_forbidden_detection,
)


class ProxyEnricher(ABC):
    """Decorator pattern: base decorator/interface for proxy enrichment."""

    @abstractmethod
    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str = "127.0.0.1",
        token: str = "",
        timeout: float = 10.0,
        audit_log_path: Path | None = None,
    ) -> ProxyInfo:
        ...


class BaseEnricher(ProxyEnricher):
    """The default leaf/core enricher that just returns the proxy."""

    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str = "127.0.0.1",
        token: str = "",
        timeout: float = 10.0,
        audit_log_path: Path | None = None,
    ) -> ProxyInfo:
        return proxy


class GeoEnricher(ProxyEnricher):
    """Decorator: Adds geo enrichment (ipinfo.io) capability to a proxy."""

    def __init__(self, wrapped: ProxyEnricher) -> None:
        self._wrapped = wrapped

    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str = "127.0.0.1",
        token: str = "",
        timeout: float = 10.0,
        audit_log_path: Path | None = None,
    ) -> ProxyInfo:
        # First enrich with the wrapped enricher
        proxy = await self._wrapped.enrich(proxy, socks_port, listen, token, timeout, audit_log_path)

        url = "https://ipinfo.io/json"
        if token:
            url += f"?token={token}"

        enrich_diag = proxy.diagnostics.setdefault("enrich", {})
        enrich_diag.update({"status": "started", "socks_port": socks_port, "listen": listen, "url": url})

        try:
            connector = SocksConnector.from_url(f"socks5://{listen}:{socks_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    enrich_diag["http_status"] = resp.status
                    body_text = await resp.text()

                    # Forbidden detection
                    if resp.status == IPINFO_FORBIDDEN_STATUS and _response_carries_forbidden(body_text):
                        _mark_proxy_not_working(
                            proxy,
                            reason="ipinfo.io forbidden 403 response",
                            extra={
                                "http_status": resp.status,
                                "socks_port": socks_port,
                                "check_command": f"curl --socks5 {listen}:{socks_port} ipinfo.io/json",
                            },
                        )
                        log_forbidden_detection(
                            proxy,
                            socks_port=socks_port,
                            audit_log_path=audit_log_path,
                            http_status=resp.status,
                        )
                        enrich_diag.update({"status": "failed", "reason": "ipinfo_forbidden_403"})
                        return proxy

                    if resp.status != 200:
                        enrich_diag.update({"status": "failed", "reason": "non_200_response"})
                        return proxy

                    try:
                        data = json.loads(body_text) if body_text else None
                    except json.JSONDecodeError:
                        enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                        return proxy

                    if not isinstance(data, dict):
                        enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                        return proxy

                    # Enrich fields
                    proxy.raw_geo = data
                    proxy.ip = str(data.get("ip", ""))
                    proxy.country_code = str(data.get("country", ""))
                    proxy.city = str(data.get("city", ""))
                    proxy.region = str(data.get("region", ""))
                    proxy.org = str(data.get("org", ""))
                    proxy.timezone = str(data.get("timezone", ""))
                    proxy.country = proxy.country_code

                    enrich_diag.update({
                        "status": "ok",
                        "ip": proxy.ip,
                        "country_code": proxy.country_code,
                        "city": proxy.city,
                        "region": proxy.region,
                        "org": proxy.org,
                        "timezone": proxy.timezone,
                    })

        except Exception as exc:
            enrich_diag.update({
                "status": "failed",
                "reason": "exception",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })

        return proxy


class ProxyBatchIterator:
    """Iterator pattern: iterates over working proxies in batches."""

    def __init__(self, proxies: list[ProxyInfo], batch_size: int = 50) -> None:
        self._proxies = [p for p in proxies if p.working]
        self._batch_size = batch_size
        self._index = 0

    def __iter__(self) -> Iterator[list[ProxyInfo]]:
        return self

    def __next__(self) -> list[ProxyInfo]:
        if self._index >= len(self._proxies):
            raise StopIteration
        batch = self._proxies[self._index : self._index + self._batch_size]
        self._index += self._batch_size
        return batch
