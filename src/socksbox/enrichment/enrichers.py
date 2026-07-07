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
        tokens: dict[str, str] | None = None,
        active_providers: list[str] | None = None,
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
        tokens: dict[str, str] | None = None,
        active_providers: list[str] | None = None,
    ) -> ProxyInfo:
        return proxy


class EnrichmentProvider(ABC):
    """Abstract base class representing an enrichment API provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier of the provider (e.g. 'ipinfo', 'abuseipdb')."""
        ...

    @abstractmethod
    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str,
        token: str,
        timeout: float,
        session: aiohttp.ClientSession,
        audit_log_path: Path | None = None,
    ) -> dict[str, Any] | None:
        """Query the API. Returns the raw response dict, or None if failed."""
        ...

    @abstractmethod
    def populate_proxy(self, proxy: ProxyInfo, response_data: dict[str, Any]) -> None:
        """Extract and update relevant location/geo/info fields on ProxyInfo."""
        ...


async def _resolve_proxy_ip(session: aiohttp.ClientSession, timeout: float) -> str | None:
    """Resolve the external IP address of the proxy."""
    # Try ipify first
    try:
        async with session.get("https://api.ipify.org?format=json", timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, dict) and "ip" in data:
                    return str(data["ip"])
    except Exception:
        pass

    # Try ipinfo.io/json without token as fallback
    try:
        async with session.get("https://ipinfo.io/json", timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status == 200:
                data = await resp.json()
                if isinstance(data, dict) and "ip" in data:
                    return str(data["ip"])
    except Exception:
        pass

    return None


class IpInfoProvider(EnrichmentProvider):
    """Provider for ipinfo.io/json enrichment."""

    @property
    def name(self) -> str:
        return "ipinfo"

    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str,
        token: str,
        timeout: float,
        session: aiohttp.ClientSession,
        audit_log_path: Path | None = None,
    ) -> dict[str, Any] | None:
        url = "https://ipinfo.io/json"
        if token:
            url += f"?token={token}"

        enrich_diag = proxy.diagnostics.setdefault("enrich", {})
        enrich_diag.update({"socks_port": socks_port, "listen": listen, "url": url})

        try:
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
                    return None

                if resp.status != 200:
                    enrich_diag.update({"status": "failed", "reason": "non_200_response"})
                    return None

                try:
                    data = json.loads(body_text) if body_text else None
                except json.JSONDecodeError:
                    enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                    return None

                if not isinstance(data, dict):
                    enrich_diag.update({"status": "failed", "reason": "invalid_json_payload"})
                    return None

                return data
        except Exception as exc:
            enrich_diag.update({
                "status": "failed",
                "reason": "exception",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            return None

    def populate_proxy(self, proxy: ProxyInfo, response_data: dict[str, Any]) -> None:
        proxy.ip = str(response_data.get("ip", ""))
        proxy.country_code = str(response_data.get("country", ""))
        proxy.city = str(response_data.get("city", ""))
        proxy.region = str(response_data.get("region", ""))
        proxy.org = str(response_data.get("org", ""))
        proxy.timezone = str(response_data.get("timezone", ""))
        proxy.country = proxy.country_code


class AbuseIPDBProvider(EnrichmentProvider):
    """Provider for abuseipdb.com check enrichment."""

    @property
    def name(self) -> str:
        return "abuseipdb"

    async def enrich(
        self,
        proxy: ProxyInfo,
        socks_port: int,
        listen: str,
        token: str,
        timeout: float,
        session: aiohttp.ClientSession,
        audit_log_path: Path | None = None,
    ) -> dict[str, Any] | None:
        if not token:
            return None

        # Resolve IP if not set
        ip = proxy.ip
        if not ip:
            ip = await _resolve_proxy_ip(session, timeout)
            if not ip:
                return None
            proxy.ip = ip

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "",
        }
        headers = {
            "Key": token,
            "Accept": "application/json",
        }

        try:
            async with session.get(url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status != 200:
                    return None
                try:
                    data = await resp.json()
                except Exception:
                    return None
                if not isinstance(data, dict):
                    return None
                return data
        except Exception:
            return None

    def populate_proxy(self, proxy: ProxyInfo, response_data: dict[str, Any]) -> None:
        data = response_data.get("data", {})
        if not data:
            return
        if not proxy.ip:
            proxy.ip = str(data.get("ipAddress", ""))
        if not proxy.country_code:
            proxy.country_code = str(data.get("countryCode", ""))
        if not proxy.country:
            proxy.country = proxy.country_code
        if not proxy.org:
            proxy.org = str(data.get("isp", ""))


class EnrichmentProviderRegistry:
    """Registry to manage active enrichment providers."""

    def __init__(self) -> None:
        self._providers: dict[str, EnrichmentProvider] = {}

    def register(self, provider: EnrichmentProvider) -> None:
        self._providers[provider.name] = provider

    def unregister(self, name: str) -> None:
        self._providers.pop(name, None)

    def get_providers(self) -> list[EnrichmentProvider]:
        return list(self._providers.values())

    def get(self, name: str) -> EnrichmentProvider | None:
        return self._providers.get(name)


PROVIDER_REGISTRY = EnrichmentProviderRegistry()
# Register defaults
PROVIDER_REGISTRY.register(IpInfoProvider())
PROVIDER_REGISTRY.register(AbuseIPDBProvider())


class GeoEnricher(ProxyEnricher):
    """Decorator: Adds geo enrichment capability to a proxy using registered providers."""

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
        tokens: dict[str, str] | None = None,
        active_providers: list[str] | None = None,
    ) -> ProxyInfo:
        # First enrich with the wrapped enricher
        proxy = await self._wrapped.enrich(proxy, socks_port, listen, token, timeout, audit_log_path, tokens, active_providers)

        if tokens is None:
            tokens = {}
        if token and "ipinfo" not in tokens:
            tokens["ipinfo"] = token

        if active_providers is None:
            active_providers = [p.name for p in PROVIDER_REGISTRY.get_providers()]

        try:
            connector = SocksConnector.from_url(f"socks5://{listen}:{socks_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                for provider in PROVIDER_REGISTRY.get_providers():
                    if provider.name not in active_providers:
                        continue
                    if not proxy.working:
                        break

                    prov_token = tokens.get(provider.name, "")
                    # Call provider
                    resp_data = await provider.enrich(
                        proxy,
                        socks_port=socks_port,
                        listen=listen,
                        token=prov_token,
                        timeout=timeout,
                        session=session,
                        audit_log_path=audit_log_path,
                    )

                    if resp_data:
                        # Save raw response data
                        if not isinstance(proxy.raw_geo, dict):
                            proxy.raw_geo = {}
                        proxy.raw_geo[provider.name] = resp_data

                        # Populate fields
                        provider.populate_proxy(proxy, resp_data)

                        # Update diagnostics
                        enrich_diag = proxy.diagnostics.setdefault("enrich", {})
                        enrich_diag["status"] = "ok"

        except Exception as exc:
            enrich_diag = proxy.diagnostics.setdefault("enrich", {})
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
